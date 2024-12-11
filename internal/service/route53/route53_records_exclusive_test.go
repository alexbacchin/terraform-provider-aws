// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package route53_test

// **PLEASE DELETE THIS AND ALL TIP COMMENTS BEFORE SUBMITTING A PR FOR REVIEW!**
//
// TIP: ==== INTRODUCTION ====
// Thank you for trying the skaff tool!
//
// You have opted to include these helpful comments. They all include "TIP:"
// to help you find and remove them when you're done with them.
//
// While some aspects of this file are customized to your input, the
// scaffold tool does *not* look at the AWS API and ensure it has correct
// function, structure, and variable names. It makes guesses based on
// commonalities. You will need to make significant adjustments.
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
	//
	// Also, AWS Go SDK v2 may handle nested structures differently than v1,
	// using the services/route53/types package. If so, you'll
	// need to import types and reference the nested types, e.g., as
	// types.<Type Name>.
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/names"

	// TIP: You will often need to import the package that this test file lives
	// in. Since it is in the "test" context, it must import the package to use
	// any normal context constants, variables, or functions.
	tfroute53 "github.com/hashicorp/terraform-provider-aws/internal/service/route53"
)

// TIP: File Structure. The basic outline for all test files should be as
// follows. Improve this resource's maintainability by following this
// outline.
//
// 1. Package declaration (add "_test" since this is a test file)
// 2. Imports
// 3. Unit tests
// 4. Basic test
// 5. Disappears test
// 6. All the other tests
// 7. Helper functions (exists, destroy, check, etc.)
// 8. Functions that return Terraform configurations

// TIP: ==== UNIT TESTS ====
// This is an example of a unit test. Its name is not prefixed with
// "TestAcc" like an acceptance test.
//
// Unlike acceptance tests, unit tests do not access AWS and are focused on a
// function (or method). Because of this, they are quick and cheap to run.
//
// In designing a resource's implementation, isolate complex bits from AWS bits
// so that they can be tested through a unit test. We encourage more unit tests
// in the provider.
//
// Cut and dry functions using well-used patterns, like typical flatteners and
// expanders, don't need unit testing. However, if they are complex or
// intricate, they should be unit tested.
func TestRoute53RecordsExclusiveExampleUnitTest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		TestName string
		Input    string
		Expected string
		Error    bool
	}{
		{
			TestName: "empty",
			Input:    "",
			Expected: "",
			Error:    true,
		},
		{
			TestName: "descriptive name",
			Input:    "some input",
			Expected: "some output",
			Error:    false,
		},
		{
			TestName: "another descriptive name",
			Input:    "more input",
			Expected: "more output",
			Error:    false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			t.Parallel()
			got, err := tfroute53.FunctionFromResource(testCase.Input)

			if err != nil && !testCase.Error {
				t.Errorf("got error (%s), expected no error", err)
			}

			if err == nil && testCase.Error {
				t.Errorf("got (%s) and no error, expected error", got)
			}

			if got != testCase.Expected {
				t.Errorf("got %s, expected %s", got, testCase.Expected)
			}
		})
	}
}

// TIP: ==== ACCEPTANCE TESTS ====
// This is an example of a basic acceptance test. This should test as much of
// standard functionality of the resource as possible, and test importing, if
// applicable. We prefix its name with "TestAcc", the service, and the
// resource name.
//
// Acceptance test access AWS and cost money to run.
func TestAccRoute53Route53RecordsExclusive_basic(t *testing.T) {
	ctx := acctest.Context(t)
	// TIP: This is a long-running test guard for tests that run longer than
	// 300s (5 min) generally.
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var route53recordsexclusive route53.DescribeRoute53RecordsExclusiveResponse
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_route53_route53_records_exclusive.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.Route53EndpointID)
			testAccPreCheck(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.Route53ServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRoute53RecordsExclusiveDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRoute53RecordsExclusiveConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRoute53RecordsExclusiveExists(ctx, resourceName, &route53recordsexclusive),
					resource.TestCheckResourceAttr(resourceName, "auto_minor_version_upgrade", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "maintenance_window_start_time.0.day_of_week"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "user.*", map[string]string{
						"console_access": "false",
						"groups.#":       "0",
						"username":       "Test",
						"password":       "TestTest1234",
					}),
					acctest.MatchResourceAttrRegionalARN(resourceName, "arn", "route53", regexache.MustCompile(`route53recordsexclusive:+.`)),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"apply_immediately", "user"},
			},
		},
	})
}

func TestAccRoute53Route53RecordsExclusive_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var route53recordsexclusive route53.DescribeRoute53RecordsExclusiveResponse
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_route53_route53_records_exclusive.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.Route53EndpointID)
			testAccPreCheck(t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.Route53ServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckRoute53RecordsExclusiveDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccRoute53RecordsExclusiveConfig_basic(rName, testAccRoute53RecordsExclusiveVersionNewer),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRoute53RecordsExclusiveExists(ctx, resourceName, &route53recordsexclusive),
					// TIP: The Plugin-Framework disappears helper is similar to the Plugin-SDK version,
					// but expects a new resource factory function as the third argument. To expose this
					// private function to the testing package, you may need to add a line like the following
					// to exports_test.go:
					//
					//   var ResourceRoute53RecordsExclusive = newResourceRoute53RecordsExclusive
					acctest.CheckFrameworkResourceDisappears(ctx, acctest.Provider, tfroute53.ResourceRoute53RecordsExclusive, resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckRoute53RecordsExclusiveDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).Route53Client(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_route53_route53_records_exclusive" {
				continue
			}

			input := &route53.DescribeRoute53RecordsExclusiveInput{
				Route53RecordsExclusiveId: aws.String(rs.Primary.ID),
			}
			_, err := conn.DescribeRoute53RecordsExclusive(ctx, &route53.DescribeRoute53RecordsExclusiveInput{
				Route53RecordsExclusiveId: aws.String(rs.Primary.ID),
			})
			if errs.IsA[*types.ResourceNotFoundException](err) {
				return nil
			}
			if err != nil {
				return create.Error(names.Route53, create.ErrActionCheckingDestroyed, tfroute53.ResNameRoute53RecordsExclusive, rs.Primary.ID, err)
			}

			return create.Error(names.Route53, create.ErrActionCheckingDestroyed, tfroute53.ResNameRoute53RecordsExclusive, rs.Primary.ID, errors.New("not destroyed"))
		}

		return nil
	}
}

func testAccCheckRoute53RecordsExclusiveExists(ctx context.Context, name string, route53recordsexclusive *route53.DescribeRoute53RecordsExclusiveResponse) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return create.Error(names.Route53, create.ErrActionCheckingExistence, tfroute53.ResNameRoute53RecordsExclusive, name, errors.New("not found"))
		}

		if rs.Primary.ID == "" {
			return create.Error(names.Route53, create.ErrActionCheckingExistence, tfroute53.ResNameRoute53RecordsExclusive, name, errors.New("not set"))
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).Route53Client(ctx)
		resp, err := conn.DescribeRoute53RecordsExclusive(ctx, &route53.DescribeRoute53RecordsExclusiveInput{
			Route53RecordsExclusiveId: aws.String(rs.Primary.ID),
		})

		if err != nil {
			return create.Error(names.Route53, create.ErrActionCheckingExistence, tfroute53.ResNameRoute53RecordsExclusive, rs.Primary.ID, err)
		}

		*route53recordsexclusive = *resp

		return nil
	}
}

func testAccPreCheck(ctx context.Context, t *testing.T) {
	conn := acctest.Provider.Meta().(*conns.AWSClient).Route53Client(ctx)

	input := &route53.ListRoute53RecordsExclusivesInput{}
	_, err := conn.ListRoute53RecordsExclusives(ctx, input)

	if acctest.PreCheckSkipError(err) {
		t.Skipf("skipping acceptance testing: %s", err)
	}
	if err != nil {
		t.Fatalf("unexpected PreCheck error: %s", err)
	}
}

func testAccCheckRoute53RecordsExclusiveNotRecreated(before, after *route53.DescribeRoute53RecordsExclusiveResponse) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if before, after := aws.ToString(before.Route53RecordsExclusiveId), aws.ToString(after.Route53RecordsExclusiveId); before != after {
			return create.Error(names.Route53, create.ErrActionCheckingNotRecreated, tfroute53.ResNameRoute53RecordsExclusive, aws.ToString(before.Route53RecordsExclusiveId), errors.New("recreated"))
		}

		return nil
	}
}

func testAccRoute53RecordsExclusiveConfig_basic(rName, version string) string {
	return fmt.Sprintf(`
resource "aws_security_group" "test" {
  name = %[1]q
}

resource "aws_route53_route53_records_exclusive" "test" {
  route53_records_exclusive_name             = %[1]q
  engine_type             = "ActiveRoute53"
  engine_version          = %[2]q
  host_instance_type      = "route53.t2.micro"
  security_groups         = [aws_security_group.test.id]
  authentication_strategy = "simple"
  storage_type            = "efs"

  logs {
    general = true
  }

  user {
    username = "Test"
    password = "TestTest1234"
  }
}
`, rName, version)
}
