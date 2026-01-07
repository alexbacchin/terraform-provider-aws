---
subcategory: "Network Firewall"
layout: "aws"
page_title: "AWS: aws_networkfirewall_proxy_configuration_rule_group_attachment"
description: |-
  Manages an AWS Network Firewall Proxy Configuration Rule Group Attachment.
---

# Resource: aws_networkfirewall_proxy_configuration_rule_group_attachment

Manages an AWS Network Firewall Proxy Configuration Rule Group Attachment.

## Example Usage

### Basic Usage

```terraform
resource "aws_networkfirewall_proxy_configuration_rule_group_attachment" "example" {
}
```

## Argument Reference

The following arguments are required:

* `example_arg` - (Required) Brief description of the required argument.

The following arguments are optional:

* `optional_arg` - (Optional) Brief description of the optional argument.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN of the Proxy Configuration Rule Group Attachment.
* `example_attribute` - Brief description of the attribute.

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `60m`)
* `update` - (Default `180m`)
* `delete` - (Default `90m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Network Firewall Proxy Configuration Rule Group Attachment using the `example_id_arg`. For example:

```terraform
import {
  to = aws_networkfirewall_proxy_configuration_rule_group_attachment.example
  id = "proxy_configuration_rule_group_attachment-id-12345678"
}
```

Using `terraform import`, import Network Firewall Proxy Configuration Rule Group Attachment using the `example_id_arg`. For example:

```console
% terraform import aws_networkfirewall_proxy_configuration_rule_group_attachment.example proxy_configuration_rule_group_attachment-id-12345678
```
