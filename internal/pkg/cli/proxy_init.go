// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	awscloudformation "github.com/aws/copilot-cli/internal/pkg/aws/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/deploy"
	"github.com/aws/copilot-cli/internal/pkg/deploy/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/describe/stack"
	"github.com/aws/copilot-cli/internal/pkg/exec"
	"github.com/aws/copilot-cli/internal/pkg/term/color"
	"github.com/aws/copilot-cli/internal/pkg/term/log"
	"github.com/aws/copilot-cli/internal/pkg/term/prompt"
	"github.com/aws/copilot-cli/internal/pkg/term/selector"
	"github.com/aws/copilot-cli/internal/pkg/workspace"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const ()

const (
	proxyInitAppNameHelpPrompt = "Proxy will be initiated in the selected application."
	proxyInitEnvNameHelpPrompt = "Proxy will be initiated in the selected environment."
	defaultUserName            = "root"
)

var (
	proxyInitAppNamePrompt = fmt.Sprintf("for which %s would you like to initalize the proxy?", color.Emphasize("application"))
	proxyInitEnvNamePrompt = fmt.Sprintf("for which %s would you like to initalize the proxy?", color.Emphasize("environment"))
)

type initProxyVars struct {
	appName string
	envName string
}

type cmdRunner interface {
	Run(name string, args []string, opts ...exec.CmdOption) error
}

type initProxyOpts struct {
	initProxyVars

	// Interfaces to interact with dependencies.
	fs       afero.Fs
	prompt   prompter
	store    store
	provider sessionProvider
	sess     *session.Session
	deployer proxyDeployer
	ws       wsBastionWriter
	//dockerEngine configSelector
	sel       configSelector
	desc      stack.StackDescriber
	cmdRunner cmdRunner

	errChannel chan error

	// Outputs stored on successful actions.
	sshPid          string
	securityGroupId string //
	publicIpAddress string // The task's public IP
	dockerfilePath  string
	idRsaPath       string

	// Init a Dockerfile parser using fs and input path
	dockerfile func(string) dockerfileParser
}

type CreateProxyResourcesInput struct {
	AppName string
	EnvName string
}

func newInitProxyOpts(vars initProxyVars) (*initProxyOpts, error) {
	sessProvider := sessions.ImmutableProvider(sessions.UserAgentExtras("proxy"))
	sess, err := sessProvider.Default()
	if err != nil {
		return nil, err
	}
	store := config.NewSSMStore(identity.New(sess), ssm.New(sess), aws.StringValue(sess.Config.Region))
	prompter := prompt.New()
	ws, err := workspace.New()
	if err != nil {
		return nil, err
	}
	cmd := exec.NewCmd()
	deployer := cloudformation.New(sess)
	opts := &initProxyOpts{
		initProxyVars: vars,
		store:         store,
		fs:            &afero.Afero{Fs: afero.NewOsFs()},
		prompt:        prompter,
		deployer:      deployer,
		ws:            ws,
		sel:           selector.NewConfigSelector(prompter, store),
		cmdRunner:     cmd,
	}
	return opts, nil
}

// Validate returns an error for any invalid optional flags.
func (o *initProxyOpts) Validate() error {
	return nil
}

// Ask prompts for and validates any required flags.
func (o *initProxyOpts) Ask() error {
	if err := o.askAppName(); err != nil {
		return err
	}

	if err := o.askEnvName(); err != nil {
		return err
	}

	return nil
}

func (o *initProxyOpts) askAppName() error {
	if o.appName != "" {
		return nil
	}

	app, err := o.sel.Application(proxyInitAppNamePrompt, proxyInitAppNameHelpPrompt)
	if err != nil {
		return fmt.Errorf("ask for application: %w", err)
	}
	o.appName = app
	return nil
}

func (o *initProxyOpts) askEnvName() error {
	if o.envName != "" {
		return nil
	}
	env, err := o.sel.Environment(proxyInitEnvNamePrompt, proxyInitEnvNameHelpPrompt, o.appName)
	if err != nil {
		return fmt.Errorf("select environment to delete: %w", err)
	}
	o.envName = env
	return nil
}

// Execute writes the service's manifest file and stores the service in SSM.
func (o *initProxyOpts) Execute() error {
	done, errCh := o.waitForCleanup()

	if err := o.configureSessForProxy(); err != nil {
		errCh <- err
	}

	if err := o.deployProxyResources(); err != nil {
		errCh <- err
	}

	o.securityGroupId = cloudformation.SecurityGroupId

	err := o.writeFiles()
	if err != nil {
		o.deleteFiles()
		return err
	}
	defer o.deleteFiles()

	o.publicIpAddress, err = o.startTask(o.securityGroupId)
	if err != nil {
		errCh <- err
	}
	log.Successln("Started bastion host.")
	err = o.startSSHProxy()
	if err != nil {
		errCh <- err
	}
	log.Successln("Started ssh proxy server.")
	log.Infoln("You can now connect to your backend services by routing traffic")
	log.Infof("through the SOCKS5 proxy configured at localhost:9000.\n")
	log.Infoln("Example:")
	log.Infoln(color.HighlightCodeBlock(fmt.Sprintf(`export http_proxy=socks5h://localhost:9000
curl http://${SVC}.%s.%s.local:${PORT}/`, o.envName, o.appName)))
	log.Infoln("This terminal will block until an interrupt, then tear down these resources.")

	for {
		select {
		case <-done:
			select {
			case err = <-errCh:
				return err
			default:
				return nil
			}
		}
	}

	return nil
}

func (o *initProxyOpts) configureSessForProxy() error {
	var sess *session.Session
	var err error
	fmt.Println("inside configureSessForProxy")
	sessProvider := sessions.ImmutableProvider(sessions.UserAgentExtras("proxy init"))
	sess, err = sessProvider.Default()
	fmt.Println("inside configureSessForProxy1")
	if err != nil {
		return fmt.Errorf("get default session: %w", err)
	}
	o.sess = sess
	return nil
}

func (o *initProxyOpts) deployProxyResources() error {
	if err := o.deploy(); err != nil {
		return fmt.Errorf("proxy resource: %w", err)
	}
	return nil
}

func (o *initProxyOpts) deploy() error {
	var deployOpts []awscloudformation.StackOption

	input := &deploy.CreateProxyResourcesInput{
		AppName: o.appName,
		EnvName: o.envName,
	}
	return o.deployer.DeployProxy(os.Stderr, input, deployOpts...)
}

func (o *initProxyOpts) writeFiles() error {
	log.Infoln("Writing temp files to disk...")
	sshDockerfile := []byte(`FROM alpine:latest
RUN apk add openssh
RUN ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa
RUN echo "root:$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 36 ; echo '')" | chpasswd

COPY authorized_keys /root/.ssh/authorized_keys

COPY sshd_config /etc/ssh/sshd_config

RUN chmod 0700 ~/.ssh \
    && chmod 0600 ~/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
`)

	dockerfilePath, err := o.ws.WriteBastionFile("bastion.Dockerfile", o.envName, sshDockerfile)
	if err != nil {
		return err
	}
	o.dockerfilePath = dockerfilePath

	sshdConfig := []byte(`PasswordAuthentication no
PermitEmptyPasswords no

Match User root
  AllowTcpForwarding yes
  X11Forwarding no
  AllowAgentForwarding no
  ForceCommand /bin/false
`)
	_, err = o.ws.WriteBastionFile("sshd_config", o.envName, sshdConfig)
	if err != nil {
		return err
	}
	log.Infoln("Generating a new rsa keypair...")
	pubKey, privKey, err := generateKeyPair()
	if err != nil {
		return err
	}

	idRsaPath, err := o.ws.WriteBastionFile("id_rsa", o.envName, privKey)
	if err != nil {
		return err
	}
	o.idRsaPath = idRsaPath
	if err = o.cmdRunner.Run("chmod", []string{"0600", idRsaPath}); err != nil {
		return err
	}
	_, err = o.ws.WriteBastionFile("authorized_keys", o.envName, pubKey)
	if err != nil {
		return err
	}

	return nil
}

func (o *initProxyOpts) deleteFiles() {
	o.ws.DeleteFolder("environments", o.envName, "bastion")
}

func (o *initProxyOpts) startSSHProxy() error {
	o.cmdRunner.Run("ssh", []string{"-oStrictHostKeyChecking=no", "-D", "9000", "-i", o.idRsaPath, "-CNf", fmt.Sprintf("%s@%s", defaultUserName, o.publicIpAddress)})
	return nil
}

func generateKeyPair() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	var privKeyBuffer bytes.Buffer

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(&privKeyBuffer, privateKeyPEM); err != nil {
		return nil, nil, err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	var pubKeyBuf bytes.Buffer
	pubKeyBuf.Write(ssh.MarshalAuthorizedKey(pub))

	return pubKeyBuf.Bytes(), privKeyBuffer.Bytes(), nil
}

func (o *initProxyOpts) startTask(securityGroupId string) (string, error) {
	// configure runner
	taskRunner, err := newTaskRunOpts(runTaskVars{
		count:                 1,
		cpu:                   256,
		memory:                512,
		dockerfilePath:        o.dockerfilePath,
		dockerfileContextPath: filepath.Dir(o.dockerfilePath),
		securityGroups:        []string{securityGroupId},
		env:                   o.envName,
		appName:               o.appName,
		groupName:             "task-proxy",
	})
	if err != nil {
		return "", err
	}
	err = taskRunner.Execute()
	if err != nil {
		return "", err
	}
	if len(taskRunner.publicIPs) != 1 {
		return "", errors.New("expected exactly 1 public IP")
	}

	var publicIP string
	for _, ip := range taskRunner.publicIPs {
		publicIP = ip
		break
	}
	return publicIP, nil
}

func (o *initProxyOpts) waitForCleanup() (chan bool, chan error) {
	errCh := make(chan error)
	done := make(chan bool)
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Infoln("received sigterm")
		o.bestEffortCleanup()
		close(errCh)
		done <- true
	}()
	go func() {
		err := <-errCh
		log.Errorf("Error setting up proxy: %w", err)
		o.bestEffortCleanup()
		errCh <- err
		done <- true
	}()
	return done, errCh
}

func (o *initProxyOpts) bestEffortCleanup() {
	o.stopSSH()
	o.stopTask()
	o.deleteStack()
}

func (o *initProxyOpts) stopSSH() {
	//TODO; Right now stopSSH is a noop because destroying the task breaks the pipe.
	return
}

func (o *initProxyOpts) stopTask() {
	//TODO
	deleter, _ := newDeleteTaskOpts(deleteTaskVars{
		name:             "task-proxy",
		app:              o.appName,
		env:              o.envName,
		skipConfirmation: true,
		defaultCluster:   false,
	})
	deleter.Execute()
}

func (o *initProxyOpts) deleteStack() {
	o.deployer.DeleteProxy()
}

// BuildProxyInitCmd build the command for creating a new proxy.
func BuildProxyInitCmd() *cobra.Command {
	vars := initProxyVars{}
	cmd := &cobra.Command{
		Use:     "proxy",
		Short:   "Creates a new proxy in an application.",
		Long:    `Creates a new proxy in an application.`,
		Example: `"`,
		RunE: runCmdE(func(cmd *cobra.Command, args []string) error {
			opts, err := newInitProxyOpts(vars)
			if err != nil {
				return err
			}
			if err := opts.Validate(); err != nil { // validate flags
				return err
			}
			if err := opts.Ask(); err != nil {
				return err
			}
			if err := opts.Execute(); err != nil {
				return err
			}
			return nil
		}),
	}
	cmd.Flags().StringVarP(&vars.appName, appFlag, appFlagShort, "", appFlagDescription)
	cmd.Flags().StringVarP(&vars.envName, envFlag, envFlagShort, "", envFlagDescription)

	return cmd
}
