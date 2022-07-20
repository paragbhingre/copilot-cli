// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package deploy holds the structures to deploy infrastructure resources.
// This file defines service deployment resources.
package deploy

// CreateTaskResourcesInput holds the fields required to create a task stack.
type CreateProxyResourcesInput struct {
	AppName string
	EnvName string
}
