// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package function_test
// **PLEASE DELETE THIS AND ALL TIP COMMENTS BEFORE SUBMITTING A PR FOR REVIEW!**
//
// TIP: ==== INTRODUCTION ====
// Thank you for trying the skaff tool!
//
// You have opted to include these helpful comments. They all include "TIP:"
// to help you find and remove them when you're done with them.
//
// While some aspects of this file are customized to your input, the
// scaffold tool does *not* produce any function logic.
//
// In other words, as generated, this is a rough outline of the work you will
// need to do. If something doesn't make sense for your situation, get rid of
// it.

import (
	// TIP: ==== IMPORTS ====
	// This is a common set of imports but not customized to your code since
	// your code hasn't been written yet. Make sure you, your IDE, or
	// goimports -w <file> fixes these imports.
	//
	// The provider linter wants your imports to be in two groups: first,
	// standard library (i.e., "fmt" or "strings"), second, everything else.
	"fmt"
	"testing"

	"github.com/YakDriver/regexache"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
)

// TIP: File Structure. The basic outline for all test files should be as
// follows. Improve this resource's maintainability by following this
// outline.
//
// 1. Package declaration (add "_test" since this is a test file)
// 2. Imports
// 3. Unit tests
// 4. Function that returns a Terraform configuration

// TIP: ==== UNIT TESTS ====
// All provider function tests are unit tests (versus acceptance tests for
// resources and data sources). Because functions do not recieve provider
// configuation details, setup is limited and exeuction is fast (relative
// to acceptance tests).
func TestBuildIAMPolicyFunction_valid(t *testing.T) {
	t.Parallel()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		// TIP: ==== TERRAFORM VERSION CHECKS ====
		// Provider defined functions were introduced in Terraform 1.8. To avoid
		// errors processing the provider function syntax, a pre-check is
		// always included to skip tests when a pre-1.8 version of Terraform
		// is detected.
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.8.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: testBuildIAMPolicyFunctionConfig("foo"),
				Check:  resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckOutput("test", "foo-updated"),
				),
			},
		},
	})
}

// TIP: ==== TESTING ERROR CASES ====
// Known error cases should include a corresponding test validating that
// the expected error text is returned.
func TestBuildIAMPolicyFunction_invalid(t *testing.T) {
	t.Parallel()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.8.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: testBuildIAMPolicyFunctionConfig("notfoo"),
				ExpectError: regexache.MustCompile("argument isn't foo"),
			},
		},
	})
}

// TIP: ==== TERRAFORM FUNCTION CONFIGURATION ====
// For provider function unit tests, this configuration is typically just
// an output block where the function is called with the argument(s) provided
// by the test cases.
func testBuildIAMPolicyFunctionConfig(arg string) string {
	return fmt.Sprintf(`
output "test" {
  value = provider::aws::build_iam_policy(%[1]q)
}
`, arg)
}
