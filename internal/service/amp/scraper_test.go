// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package amp_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/amp"
	"github.com/aws/aws-sdk-go-v2/service/amp/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfamp "github.com/hashicorp/terraform-provider-aws/internal/service/amp"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccAMPScraper_basic(t *testing.T) {
	ctx := acctest.Context(t)

	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var scraper types.ScraperDescription
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_prometheus_scraper.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.AMPServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckScraperDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccScraperConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckScraperExists(ctx, resourceName, &scraper),
					resource.TestCheckNoResourceAttr(resourceName, names.AttrAlias),
					acctest.CheckResourceAttrRegionalARNFormat(ctx, resourceName, names.AttrARN, "aps", "scraper/{id}"),
					resource.TestCheckResourceAttr(resourceName, "destination.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "destination.0.amp.#", "1"),
					func(s *terraform.State) error {
						return resource.TestCheckResourceAttr(resourceName, names.AttrID, aws.ToString(scraper.ScraperId))(s)
					},
					resource.TestCheckResourceAttrSet(resourceName, names.AttrRoleARN),
					resource.TestCheckResourceAttrSet(resourceName, "scrape_configuration"),
					resource.TestCheckResourceAttr(resourceName, "source.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "source.0.eks.#", "1"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAMPScraper_disappears(t *testing.T) {
	ctx := acctest.Context(t)

	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var scraper types.ScraperDescription
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_prometheus_scraper.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.AMPServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckScraperDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccScraperConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckScraperExists(ctx, resourceName, &scraper),
					acctest.CheckFrameworkResourceDisappears(ctx, acctest.Provider, tfamp.ResourceScraper, resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccAMPScraper_alias(t *testing.T) {
	ctx := acctest.Context(t)

	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var scraper types.ScraperDescription
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	aliasName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	aliasName2 := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_prometheus_scraper.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.AMPServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckScraperDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccScraperConfig_alias(rName, aliasName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckScraperExists(ctx, resourceName, &scraper),
					resource.TestCheckResourceAttr(resourceName, names.AttrAlias, aliasName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccScraperConfig_alias(rName, aliasName2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckScraperExists(ctx, resourceName, &scraper),
					resource.TestCheckResourceAttr(resourceName, names.AttrAlias, aliasName2),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAMPScraper_securityGroups(t *testing.T) {
	ctx := acctest.Context(t)

	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var scraper types.ScraperDescription
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_prometheus_scraper.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.AMPServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckScraperDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccScraperConfig_securityGroups(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckScraperExists(ctx, resourceName, &scraper),
					resource.TestCheckResourceAttr(resourceName, "source.0.eks.0.security_group_ids.#", "1"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
func TestAccAMPScraper_roleConfiguration(t *testing.T) {
	ctx := acctest.Context(t)

	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var scraper types.ScraperDescription
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_prometheus_scraper.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			testAccPreCheck(ctx, t)
			acctest.PreCheckAlternateAccount(t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.AMPServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5FactoriesAlternate(ctx, t),
		CheckDestroy:             testAccCheckScraperDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccScraperConfig_roleConfiguration(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckScraperExists(ctx, resourceName, &scraper),
					resource.TestCheckResourceAttrSet(resourceName, "role_configuration.0.source_role_arn"),
					resource.TestCheckResourceAttrSet(resourceName, "role_configuration.0.target_role_arn"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccScraperConfig_alias(rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckScraperExists(ctx, resourceName, &scraper),
					resource.TestCheckResourceAttr(resourceName, "role_configuration.#", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckScraperDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).AMPClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_prometheus_scraper" {
				continue
			}

			_, err := tfamp.FindScraperByID(ctx, conn, rs.Primary.ID)

			if tfresource.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("Prometheus Scraper %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckScraperExists(ctx context.Context, n string, v *types.ScraperDescription) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).AMPClient(ctx)

		output, err := tfamp.FindScraperByID(ctx, conn, rs.Primary.ID)

		if err != nil {
			return err
		}

		*v = *output

		return nil
	}
}

func testAccPreCheck(ctx context.Context, t *testing.T) {
	conn := acctest.Provider.Meta().(*conns.AWSClient).AMPClient(ctx)

	input := amp.ListScrapersInput{}

	_, err := conn.ListScrapers(ctx, &input)

	if acctest.PreCheckSkipError(err) {
		t.Skipf("skipping acceptance testing: %s", err)
	}

	if err != nil {
		t.Fatalf("unexpected PreCheck error: %s", err)
	}
}

var scrapeConfigBlob = `
global:
  scrape_interval: 30s
scrape_configs:
  # pod metrics
  - job_name: pod_exporter
    kubernetes_sd_configs:
      - role: pod
  # container metrics
  - job_name: cadvisor
    scheme: https
    authorization:
      credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)
      - replacement: kubernetes.default.svc:443
        target_label: __address__
      - source_labels: [__meta_kubernetes_node_name]
        regex: (.+)
        target_label: __metrics_path__
        replacement: /api/v1/nodes/$1/proxy/metrics/cadvisor
  # apiserver metrics
  - bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    job_name: kubernetes-apiservers
    kubernetes_sd_configs:
    - role: endpoints
    relabel_configs:
    - action: keep
      regex: default;kubernetes;https
      source_labels:
      - __meta_kubernetes_namespace
      - __meta_kubernetes_service_name
      - __meta_kubernetes_endpoint_port_name
    scheme: https
  # kube proxy metrics
  - job_name: kube-proxy
    honor_labels: true
    kubernetes_sd_configs:
    - role: pod
    relabel_configs:
    - action: keep
      source_labels:
      - __meta_kubernetes_namespace
      - __meta_kubernetes_pod_name
      separator: '/'
      regex: 'kube-system/kube-proxy.+'
    - source_labels:
      - __address__
      action: replace
      target_label: __address__
      regex: (.+?)(\\:\\d+)?
      replacement: $1:10249
`

func testAccScraperConfig_base(rName string) string {
	return acctest.ConfigCompose(acctest.ConfigAvailableAZsNoOptIn(), fmt.Sprintf(`
data "aws_partition" "current" {}

resource "aws_iam_role" "test" {
  name = %[1]q

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.${data.aws_partition.current.dns_suffix}"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "test-AmazonEKSClusterPolicy" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.test.name
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  assign_generated_ipv6_cidr_block = true

  tags = {
    Name                          = %[1]q
    "kubernetes.io/cluster/%[1]s" = "shared"
  }
}

resource "aws_subnet" "test" {
  count = 2

  availability_zone = data.aws_availability_zones.available.names[count.index]
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = aws_vpc.test.id

  ipv6_cidr_block                 = cidrsubnet(aws_vpc.test.ipv6_cidr_block, 8, count.index)
  assign_ipv6_address_on_creation = true

  tags = {
    Name                          = %[1]q
    "kubernetes.io/cluster/%[1]s" = "shared"
  }
}

resource "aws_eks_cluster" "test" {
  name     = %[1]q
  role_arn = aws_iam_role.test.arn

  vpc_config {
    subnet_ids = aws_subnet.test[*].id
  }

  depends_on = [aws_iam_role_policy_attachment.test-AmazonEKSClusterPolicy]
}

resource "aws_prometheus_workspace" "test" {
  alias = %[1]q

  tags = {
    AMPAgentlessScraper = ""
  }
}
`, rName))
}

func testAccScraperConfig_basic(rName string) string {
	return acctest.ConfigCompose(testAccScraperConfig_base(rName), fmt.Sprintf(`
resource "aws_prometheus_scraper" "test" {
  scrape_configuration = %[1]q

  source {
    eks {
      cluster_arn = aws_eks_cluster.test.arn
      subnet_ids  = aws_subnet.test[*].id
    }
  }

  destination {
    amp {
      workspace_arn = aws_prometheus_workspace.test.arn
    }
  }
}
`, scrapeConfigBlob))
}

func testAccScraperConfig_alias(rName, alias string) string {
	return acctest.ConfigCompose(testAccScraperConfig_base(rName), fmt.Sprintf(`
resource "aws_prometheus_scraper" "test" {
  alias                = %[2]q
  scrape_configuration = %[3]q

  source {
    eks {
      cluster_arn = aws_eks_cluster.test.arn
      subnet_ids  = aws_subnet.test[*].id
    }
  }

  destination {
    amp {
      workspace_arn = aws_prometheus_workspace.test.arn
    }
  }
}
`, rName, alias, scrapeConfigBlob))
}

func testAccScraperConfig_securityGroups(rName string) string {
	return acctest.ConfigCompose(testAccScraperConfig_base(rName), fmt.Sprintf(`
resource "aws_prometheus_scraper" "test" {
  alias                = %[1]q
  scrape_configuration = %[2]q

  source {
    eks {
      cluster_arn        = aws_eks_cluster.test.arn
      subnet_ids         = aws_subnet.test[*].id
      security_group_ids = [aws_eks_cluster.test.vpc_config[0].cluster_security_group_id]
    }
  }

  destination {
    amp {
      workspace_arn = aws_prometheus_workspace.test.arn
    }
  }
}
`, rName, scrapeConfigBlob))
}

func testAccScraperConfig_roleConfiguration(rName string) string {
	return acctest.ConfigCompose(acctest.ConfigAlternateAccountProvider(), testAccScraperConfig_base(rName), fmt.Sprintf(`
resource "aws_prometheus_workspace" "target" {
  provider = "awsalternate"

  alias = %[1]q

  tags = {
    AMPAgentlessScraper = ""
  }
}

resource "aws_iam_role" "source" {
  name = "%[1]s-source"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "scraper.aps.${data.aws_partition.current.dns_suffix}"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "target" {
  provider = "awsalternate"

  name = "%[1]s-target"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.source.arn}"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "target" {
  provider = "awsalternate"

  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonPrometheusRemoteWriteAccess"
  role       = aws_iam_role.target.name
}

resource "aws_prometheus_scraper" "test" {
  alias                = %[1]q
  scrape_configuration = %[2]q

  source {
    eks {
      cluster_arn = aws_eks_cluster.test.arn
      subnet_ids  = aws_subnet.test[*].id
    }
  }

  destination {
    amp {
      workspace_arn = aws_prometheus_workspace.target.arn
    }
  }

  role_configuration {
    source_role_arn = aws_iam_role.source.arn
    target_role_arn = aws_iam_role.target.arn
  }
}
`, rName, scrapeConfigBlob))
}
