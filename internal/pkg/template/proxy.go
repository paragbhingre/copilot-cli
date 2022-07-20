// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"bytes"
	"fmt"
)

const (
	ProxyCFTemplatePath = "proxy/cf.yml"
)

// ProxyOpts holds data that can be provided to enable features in proxy stack template.
type ProxyOpts struct {
	AppName string
	EnvName string
}

// ParseProxy parses an proxy's CloudFormation template with the specified data object and returns its content.
func (t *Template) ParseProxy(data *ProxyOpts) (*Content, error) {
	tpl, err := t.parse("base", ProxyCFTemplatePath, withEnvParsingFuncs())
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	if err := tpl.Execute(buf, data); err != nil {
		return nil, fmt.Errorf("execute environment template with data %v: %w", data, err)
	}
	return &Content{buf}, nil
}
