---
subcategory: "EventBridge V2"
layout: "aws"
page_title: "AWS: aws_eventbridgev2_resource_policy"
description: |-
  Manages the resource policy of an Amazon EventBridge V2 event bus.
---

# Resource: aws_eventbridgev2_resource_policy

Manages the resource policy of an Amazon EventBridge V2 event bus. Use a resource policy to grant other AWS accounts access to the event bus.

-> **Note:** This resource manages the customer-managed (`default`) policy only. The `AWS_RAM` policy is managed exclusively by AWS Resource Access Manager.

## Example Usage

```terraform
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

resource "aws_eventbridgev2_event_bus" "example" {
  name = "example"
}

resource "aws_eventbridgev2_resource_policy" "example" {
  resource_arn = aws_eventbridgev2_event_bus.example.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowAccount"
      Effect = "Allow"
      Principal = {
        AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Action   = "events:PutEvents"
      Resource = aws_eventbridgev2_event_bus.example.arn
    }]
  })
}
```

## Argument Reference

The following arguments are required:

* `policy` - (Required) Resource policy document, in JSON format.
* `resource_arn` - (Required) ARN of the event bus the policy is attached to. Changing this value creates a new resource.

The following arguments are optional:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `revision_id` - Revision ID of the policy. A new revision ID is generated each time the policy is updated.

## Import

In Terraform v1.12.0 and later, the [`import` block](https://developer.hashicorp.com/terraform/language/import) can be used with the `identity` attribute. For example:

```terraform
import {
  to = aws_eventbridgev2_resource_policy.example
  identity = {
    "resource_arn" = "arn:aws:events:us-east-1:123456789012:event-busv2/example/abcdefghij0123456789abcde"
  }
}

resource "aws_eventbridgev2_resource_policy" "example" {
  ### Configuration omitted for brevity ###
}
```

### Identity Schema

#### Required

- `resource_arn` (String) ARN of the event bus the policy is attached to.

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import EventBridge V2 resource policies using the `resource_arn`. For example:

```terraform
import {
  to = aws_eventbridgev2_resource_policy.example
  id = "arn:aws:events:us-east-1:123456789012:event-busv2/example/abcdefghij0123456789abcde"
}
```

Using `terraform import`, import EventBridge V2 resource policies using the `resource_arn`. For example:

```console
% terraform import aws_eventbridgev2_resource_policy.example arn:aws:events:us-east-1:123456789012:event-busv2/example/abcdefghij0123456789abcde
```
