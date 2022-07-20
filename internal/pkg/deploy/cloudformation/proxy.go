// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudformation

import (
	"errors"
	"github.com/aws/copilot-cli/internal/pkg/aws/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/deploy"
	"github.com/aws/copilot-cli/internal/pkg/term/progress"

	"github.com/aws/copilot-cli/internal/pkg/deploy/cloudformation/stack"
)

const proxyStackName = "Proxy"

// DeployTask deploys proxy stack
func (cf CloudFormation) DeployProxy(out progress.FileWriter, input *deploy.CreateProxyResourcesInput, opts ...cloudformation.StackOption) error {
	conf := stack.NewProxyStackConfig(input)
	stack, err := toStack(conf)
	if err != nil {
		return err
	}
	for _, opt := range opts {
		opt(stack)
	}

	if err := cf.renderStackChanges(cf.newRenderWorkloadInput(out, stack)); err != nil {
		var errChangeSetEmpty *cloudformation.ErrChangeSetEmpty
		if !errors.As(err, &errChangeSetEmpty) {
			return err
		}
	}
	return nil
}

func (cf CloudFormation) DeleteProxy() error {
	return cf.cfnClient.DeleteAndWait(proxyStackName)
}
