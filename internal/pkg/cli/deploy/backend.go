// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/copilot-cli/internal/pkg/aws/acm"
	awsecs "github.com/aws/copilot-cli/internal/pkg/aws/ecs"
	"github.com/aws/copilot-cli/internal/pkg/aws/partitions"
	"github.com/aws/copilot-cli/internal/pkg/deploy/cloudformation/stack"
	"github.com/aws/copilot-cli/internal/pkg/deploy/upload/customresource"
	"github.com/aws/copilot-cli/internal/pkg/ecs"
	"github.com/aws/copilot-cli/internal/pkg/manifest"
	"github.com/aws/copilot-cli/internal/pkg/template"
)

type backendSvcDeployer struct {
	*svcDeployer
	backendMft         *manifest.BackendService
	customResources    customResourcesFunc
	aliasCertValidator aliasCertValidator
}

// NewBackendDeployer is the constructor for backendSvcDeployer.
func NewBackendDeployer(in *WorkloadDeployerInput) (*backendSvcDeployer, error) {
	svcDeployer, err := newSvcDeployer(in)
	if err != nil {
		return nil, err
	}
	bsMft, ok := in.Mft.(*manifest.BackendService)
	if !ok {
		return nil, fmt.Errorf("manifest is not of type %s", manifest.BackendServiceType)
	}
	return &backendSvcDeployer{
		svcDeployer:        svcDeployer,
		backendMft:         bsMft,
		aliasCertValidator: acm.New(svcDeployer.envSess),
		customResources: func(fs template.Reader) ([]*customresource.CustomResource, error) {
			crs, err := customresource.Backend(fs)
			if err != nil {
				return nil, fmt.Errorf("read custom resources for a %q: %w", manifest.BackendServiceType, err)
			}
			return crs, nil
		},
	}, nil
}

// IsServiceAvailableInRegion checks if service type exist in the given region.
func (backendSvcDeployer) IsServiceAvailableInRegion(region string) (bool, error) {
	return partitions.IsAvailableInRegion(awsecs.EndpointsID, region)
}

// UploadArtifacts uploads the deployment artifacts such as the container image, custom resources, addons and env files.
func (d *backendSvcDeployer) UploadArtifacts() (*UploadArtifactsOutput, error) {
	return d.uploadArtifacts(d.customResources)
}

// GenerateCloudFormationTemplate generates a CloudFormation template and parameters for a workload.
func (d *backendSvcDeployer) GenerateCloudFormationTemplate(in *GenerateCloudFormationTemplateInput) (
	*GenerateCloudFormationTemplateOutput, error) {
	output, err := d.stackConfiguration(&in.StackRuntimeConfiguration)
	if err != nil {
		return nil, err
	}
	return d.generateCloudFormationTemplate(output.conf)
}

// DeployWorkload deploys a backend service using CloudFormation.
func (d *backendSvcDeployer) DeployWorkload(in *DeployWorkloadInput) (ActionRecommender, error) {
	stackConfigOutput, err := d.stackConfiguration(&in.StackRuntimeConfiguration)
	if err != nil {
		return nil, err
	}
	if err := d.deploy(in.Options, *stackConfigOutput); err != nil {
		return nil, err
	}
	return nil, nil
}

func (d *backendSvcDeployer) stackConfiguration(in *StackRuntimeConfiguration) (*svcStackConfigurationOutput, error) {
	rc, err := d.runtimeConfig(in)
	if err != nil {
		return nil, err
	}
	if err := d.validateALBRuntime(); err != nil {
		return nil, err
	}
	conf, err := stack.NewBackendService(stack.BackendServiceConfig{
		App:           d.app,
		EnvManifest:   d.envConfig,
		Manifest:      d.backendMft,
		RawManifest:   d.rawMft,
		RuntimeConfig: *rc,
		Addons:        d.addons,
	})
	if err != nil {
		return nil, fmt.Errorf("create stack configuration: %w", err)
	}
	return &svcStackConfigurationOutput{
		conf: conf,
		svcUpdater: d.newSvcUpdater(func(s *session.Session) serviceForceUpdater {
			return ecs.New(s)
		}),
	}, nil
}

func (d *backendSvcDeployer) validateALBRuntime() error {
	if d.backendMft.RoutingRule.IsEmpty() {
		return nil
	}
	hasImportedCerts := len(d.envConfig.HTTPConfig.Private.Certificates) != 0
	switch {
	case d.backendMft.RoutingRule.PrimaryRoutingRule.Alias.IsEmpty() && hasImportedCerts:
		return &errSvcWithNoALBAliasDeployingToEnvWithImportedCerts{
			name:    d.name,
			envName: d.env.Name,
		}
	case d.backendMft.RoutingRule.PrimaryRoutingRule.Alias.IsEmpty():
		return nil
	case !hasImportedCerts:
		return fmt.Errorf(`cannot specify "alias" in an environment without imported certs`)
	}

	aliases, err := d.backendMft.RoutingRule.PrimaryRoutingRule.Alias.ToStringSlice()
	if err != nil {
		return fmt.Errorf("convert aliases to string slice: %w", err)
	}

	if err := d.aliasCertValidator.ValidateCertAliases(aliases, d.envConfig.HTTPConfig.Private.Certificates); err != nil {
		return fmt.Errorf("validate aliases against the imported certificate for env %s: %w", d.env.Name, err)
	}

	return nil
}
