// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package stack

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/deploy"
	"github.com/aws/copilot-cli/internal/pkg/template"
)

type ProxyReadParser interface {
	template.ReadParser
	ParseProxy(data *template.ProxyOpts) (*template.Content, error)
	//ParseEnvBootstrap(data *template.EnvOpts, options ...template.ParseOption) (*template.Content, error)
}

// NewProxyStackConfig return o CloudFormation stack configuration for deploying a brand new proxy.
func NewProxyStackConfig(input *deploy.CreateProxyResourcesInput) *ProxyStackConfig {
	return &ProxyStackConfig{
		in:     input,
		parser: template.New(),
	}
}

type ProxyStackConfig struct {
	in         *deploy.CreateProxyResourcesInput
	prevParams []*cloudformation.Parameter
	parser     ProxyReadParser
}

// ProxyOpts holds data that can be provided to enable features in an environment stack template.
type ProxyOpts struct {
	AppName string
	EnvName string
	Version string
}

// Template returns the proxy CloudFormation template.
func (e *ProxyStackConfig) Template() (string, error) {

	content, err := e.parser.ParseProxy(&template.ProxyOpts{
		AppName: e.in.AppName,
		EnvName: e.in.EnvName,
	})
	if err != nil {
		return "", err
	}
	return content.String(), nil
}

// StackName returns the name of the CloudFormation stack for the proxy.
func (t *ProxyStackConfig) StackName() string {
	return "Proxy"
}

func (s *ProxyStackConfig) SerializedParameters() (string, error) {
	// No-op for now.
	return "", nil
}

// Parameters returns the parameter values to be passed to the task CloudFormation template.
func (t *ProxyStackConfig) Parameters() ([]*cloudformation.Parameter, error) {
	return []*cloudformation.Parameter{
		{
			ParameterKey:   aws.String("App"),
			ParameterValue: aws.String(t.in.AppName),
		},
		{
			ParameterKey:   aws.String("Env"),
			ParameterValue: aws.String(t.in.EnvName),
		},
	}, nil
}

// Tags returns the tags that should be applied to the task CloudFormation.
func (t *ProxyStackConfig) Tags() []*cloudformation.Tag {
	return nil
}
