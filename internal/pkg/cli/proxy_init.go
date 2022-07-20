// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/term/color"
	"github.com/aws/copilot-cli/internal/pkg/term/log"
	"github.com/aws/copilot-cli/internal/pkg/term/prompt"
	"github.com/aws/copilot-cli/internal/pkg/term/selector"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const ()

const (
	proxyInitAppNameHelpPrompt = "Proxy will be initiated in the selected application."
	proxyInitEnvNameHelpPrompt = "Proxy will be initiated in the selected environment."
)

var (
	proxyInitAppNamePrompt = fmt.Sprintf("for which %s would you like to initalize the proxy?", color.Emphasize("application"))
	proxyInitEnvNamePrompt = fmt.Sprintf("for which %s would you like to initalize the proxy?", color.Emphasize("environment"))
)

type initProxyVars struct {
	appName string
	envName string
}

type initProxyOpts struct {
	initProxyVars

	// Interfaces to interact with dependencies.
	fs     afero.Fs
	prompt prompter
	store  store

	//dockerEngine configSelector
	sel configSelector

	errChannel chan error

	// Outputs stored on successful actions.
	sshPid          string
	securityGroupId string //
	publicIpAddress string // The task's public IP

	// Init a Dockerfile parser using fs and input path
	dockerfile func(string) dockerfileParser
}

func newInitProxyOpts(vars initProxyVars) (*initProxyOpts, error) {
	sessProvider := sessions.ImmutableProvider(sessions.UserAgentExtras("proxy"))
	sess, err := sessProvider.Default()
	if err != nil {
		return nil, err
	}
	store := config.NewSSMStore(identity.New(sess), ssm.New(sess), aws.StringValue(sess.Config.Region))
	prompter := prompt.New()

	opts := &initProxyOpts{
		initProxyVars: vars,
		store:         store,
		fs:            &afero.Afero{Fs: afero.NewOsFs()},
		prompt:        prompter,
		sel:           selector.NewConfigSelector(prompter, store),
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
	var securityGroupId string
	// TODO: Deploy security group stack
	_, err := o.startTask(securityGroupId)

	// TODO: exec ssh -D 9000 -qCN -f root@${publicIP} and define cleanup
	done, errCh := o.waitForCleanup()
	for {
		select {
		case <-done:
			return nil
		case err = <-errCh:
			return err
		}
	}
}
func (o *initProxyOpts) writeFiles() string {
	// TODO: write files
	return ""
}

func (o *initProxyOpts) deleteFiles() {
	// TODO: delete files
}

func (o *initProxyOpts) startSSHProxy() error {
	return nil
}

func (o *initProxyOpts) startTask(securityGroupId string) (string, error) {
	dockerFilePath := o.writeFiles()
	defer o.deleteFiles()

	// configure runner
	taskRunner, err := newTaskRunOpts(runTaskVars{
		count:                 1,
		cpu:                   256,
		memory:                512,
		dockerfilePath:        dockerFilePath,
		dockerfileContextPath: filepath.Dir(dockerFilePath),
		securityGroups:        []string{securityGroupId},
		env:                   o.envName,
		appName:               o.appName,
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
		var err error
		// Kill SSH tunnel
		// Stop task
		// Destroy CF stack
		if err != nil {
			errCh <- err
		}
		done <- true
	}()
	return done, errCh
}

// BuildProxyInitCmd build the command for creating a new proxy.
func BuildProxyInitCmd() *cobra.Command {
	vars := initProxyVars{}
	cmd := &cobra.Command{
		Use:     "init",
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
			log.Warningln("It's best to run this command in the root of your workspace.")
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
