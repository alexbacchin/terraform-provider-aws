---
subcategory: "API Gateway V2"
layout: "aws"
page_title: "AWS: aws_apigatewayv2_routing_rule"
description: |-
  Manages an AWS API Gateway V2 Routing Rule.
---
<!---
Documentation guidelines:
- Begin resource descriptions with "Manages..."
- Use simple language and avoid jargon
- Focus on brevity and clarity
- Use present tense and active voice
- Don't begin argument/attribute descriptions with "An", "The", "Defines", "Indicates", or "Specifies"
- Boolean arguments should begin with "Whether to"
- Use "example" instead of "test" in examples
--->

# Resource: aws_apigatewayv2_routing_rule

Manages an AWS API Gateway V2 Routing Rule.

## Example Usage

### Basic Usage

```terraform
resource "aws_apigatewayv2_routing_rule" "example" {
}
```

## Argument Reference

The following arguments are required:

* `example_arg` - (Required) Brief description of the required argument.

The following arguments are optional:

* `optional_arg` - (Optional) Brief description of the optional argument.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - ARN of the Routing Rule.
* `example_attribute` - Brief description of the attribute.

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

* `create` - (Default `60m`)
* `update` - (Default `180m`)
* `delete` - (Default `90m`)

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import API Gateway V2 Routing Rule using the `example_id_arg`. For example:

```terraform
import {
  to = aws_apigatewayv2_routing_rule.example
  id = "routing_rule-id-12345678"
}
```

Using `terraform import`, import API Gateway V2 Routing Rule using the `example_id_arg`. For example:

```console
% terraform import aws_apigatewayv2_routing_rule.example routing_rule-id-12345678
```
