// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	awscloudformation "github.com/aws/copilot-cli/internal/pkg/aws/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/aws/identity"
	"github.com/aws/copilot-cli/internal/pkg/term/color"
	"os"

	"github.com/aws/copilot-cli/internal/pkg/aws/sessions"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/deploy"
	"github.com/aws/copilot-cli/internal/pkg/deploy/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/initialize"
	"github.com/aws/copilot-cli/internal/pkg/manifest"
	"github.com/aws/copilot-cli/internal/pkg/term/log"
	termprogress "github.com/aws/copilot-cli/internal/pkg/term/progress"
	"github.com/aws/copilot-cli/internal/pkg/term/prompt"
	"github.com/aws/copilot-cli/internal/pkg/term/selector"
	"github.com/aws/copilot-cli/internal/pkg/workspace"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
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
	fs       afero.Fs
	init     svcInitializer
	prompt   prompter
	store    store
	provider sessionProvider
	sess     *session.Session
	deployer proxyDeployer
	//dockerEngine configSelector
	sel       configSelector
	topicSel  topicSelector
	mftReader manifestReader

	// Outputs stored on successful actions.
	manifestPath string
	platform     *manifest.PlatformString
	topics       []manifest.TopicSubscription

	// For workspace validation.
	wsAppName         string
	wsPendingCreation bool

	// Cache variables
	df             dockerfileParser
	manifestExists bool

	// Init a Dockerfile parser using fs and input path
	dockerfile func(string) dockerfileParser
}

type CreateProxyResourcesInput struct {
	AppName string
	EnvName string
}

func newInitProxyOpts(vars initProxyVars) (*initProxyOpts, error) {
	ws, err := workspace.New()
	if err != nil {
		return nil, fmt.Errorf("workspace cannot be created: %w", err)
	}

	sessProvider := sessions.ImmutableProvider(sessions.UserAgentExtras("svc init"))
	sess, err := sessProvider.Default()
	if err != nil {
		return nil, err
	}
	store := config.NewSSMStore(identity.New(sess), ssm.New(sess), aws.StringValue(sess.Config.Region))
	prompter := prompt.New()
	deployStore, err := deploy.NewStore(sessProvider, store)
	if err != nil {
		return nil, err
	}
	snsSel := selector.NewDeploySelect(prompter, store, deployStore)
	deployer := cloudformation.New(sess)
	initSvc := &initialize.WorkloadInitializer{
		Store:    store,
		Ws:       ws,
		Prog:     termprogress.NewSpinner(log.DiagnosticWriter),
		Deployer: cloudformation.New(sess),
	}
	opts := &initProxyOpts{
		initProxyVars: vars,
		store:         store,
		fs:            &afero.Afero{Fs: afero.NewOsFs()},
		init:          initSvc,
		prompt:        prompter,
		deployer:      deployer,
		sel:           selector.NewConfigSelector(prompter, store),
		topicSel:      snsSel,
		mftReader:     ws,
		wsAppName:     tryReadingAppName(),
	}
	return opts, nil
}

// Validate returns an error for any invalid optional flags.
func (o *initProxyOpts) Validate() error {
	// If this app is pending creation, we'll skip validation.
	return nil
}

// Ask prompts for and validates any required flags.
func (o *initProxyOpts) Ask() error {
	// NOTE: we optimize the case where `name` is given as a flag while `wkldType` is not.
	// In this case, we can try reading the manifest, and set `wkldType` to the value found in the manifest
	// without having to validate it. We can then short circuit the rest of the prompts for an optimal UX.
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

	if err := o.configureSessForProxy(); err != nil {
		return err
	}

	if err := o.deployProxyResources(); err != nil {
		return err
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
