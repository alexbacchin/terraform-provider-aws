// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build generate
// +build generate

package main

import (
	_ "embed"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-provider-aws/internal/generate/common"
	"github.com/hashicorp/terraform-provider-aws/names/data"
)

type serviceDatum struct {
	ProviderPackage  string
	Aliases          []string
	TfAwsEnvVar      string
	DeprecatedEnvVar string
	AwsEnvVar        string
}

type TemplateData struct {
	Services []serviceDatum
}

func main() {
	const (
		filename = `../../../internal/provider/provider_gen.go`
	)
	g := common.NewGenerator()

	g.Infof("Generating %s", strings.TrimPrefix(filename, "../../../"))

	data, err := data.ReadAllServiceData()
	if err != nil {
		g.Fatalf("error reading service data: %s", err)
	}

	td := TemplateData{}

	for _, l := range data {
		if l.Exclude() {
			continue
		}

		if l.NotImplemented() && !l.EndpointOnly() {
			continue
		}

		sd := serviceDatum{
			ProviderPackage:  l.ProviderPackage(),
			Aliases:          l.Aliases(),
			TfAwsEnvVar:      l.TFAWSEnvVar(),
			DeprecatedEnvVar: l.DeprecatedEnvVar(),
			AwsEnvVar:        l.AWSServiceEnvVar(),
		}

		td.Services = append(td.Services, sd)
	}

	sort.Slice(td.Services, func(i, j int) bool {
		return td.Services[i].ProviderPackage < td.Services[j].ProviderPackage
	})

	d := g.NewGoFileDestination(filename)

	if err := d.WriteTemplate("endpoints-schema", tmpl, td); err != nil {
		g.Fatalf("generating file (%s): %s", filename, err)
	}

	if err := d.Write(); err != nil {
		g.Fatalf("generating file (%s): %s", filename, err)
	}
}

//go:embed file.gtpl
var tmpl string