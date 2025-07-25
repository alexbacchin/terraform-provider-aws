---
subcategory: "VPC (Virtual Private Cloud)"
layout: "aws"
page_title: "AWS: aws_vpcs"
description: |-
    Provides a list of VPC Ids in a region
---


<!-- Please do not edit this file, it is generated. -->
# Data Source: aws_vpcs

This resource can be useful for getting back a list of VPC Ids for a region.

The following example retrieves a list of VPC Ids with a custom tag of `service` set to a value of "production".

## Example Usage

The following shows outputting all VPC Ids.

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import { TerraformOutput, TerraformStack } from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsVpcs } from "./.gen/providers/aws/data-aws-vpcs";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const foo = new DataAwsVpcs(this, "foo", {
      tags: {
        service: "production",
      },
    });
    const cdktfTerraformOutputFoo = new TerraformOutput(this, "foo_1", {
      value: foo.ids,
    });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    cdktfTerraformOutputFoo.overrideLogicalId("foo");
  }
}

```

An example use case would be interpolate the `aws_vpcs` output into `count` of an aws_flow_log resource.

```typescript
// DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
import { Construct } from "constructs";
import {
  TerraformOutput,
  Fn,
  Token,
  TerraformCount,
  TerraformStack,
} from "cdktf";
/*
 * Provider bindings are generated by running `cdktf get`.
 * See https://cdk.tf/provider-generation for more details.
 */
import { DataAwsVpc } from "./.gen/providers/aws/data-aws-vpc";
import { DataAwsVpcs } from "./.gen/providers/aws/data-aws-vpcs";
import { FlowLog } from "./.gen/providers/aws/flow-log";
class MyConvertedCode extends TerraformStack {
  constructor(scope: Construct, name: string) {
    super(scope, name);
    const foo = new DataAwsVpcs(this, "foo", {});
    const cdktfTerraformOutputFoo = new TerraformOutput(this, "foo_1", {
      value: foo.ids,
    });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    cdktfTerraformOutputFoo.overrideLogicalId("foo");
    /*In most cases loops should be handled in the programming language context and 
    not inside of the Terraform context. If you are looping over something external, e.g. a variable or a file input
    you should consider using a for loop. If you are looping over something only known to Terraform, e.g. a result of a data source
    you need to keep this like it is.*/
    const fooCount = TerraformCount.of(Token.asNumber(Fn.lengthOf(foo.ids)));
    const dataAwsVpcFoo = new DataAwsVpc(this, "foo_2", {
      id: Token.asString(Fn.lookupNested(Fn.tolist(foo.ids), [fooCount.index])),
      count: fooCount,
    });
    /*This allows the Terraform resource name to match the original name. You can remove the call if you don't need them to match.*/
    dataAwsVpcFoo.overrideLogicalId("foo");
    /*In most cases loops should be handled in the programming language context and 
    not inside of the Terraform context. If you are looping over something external, e.g. a variable or a file input
    you should consider using a for loop. If you are looping over something only known to Terraform, e.g. a result of a data source
    you need to keep this like it is.*/
    const testFlowLogCount = TerraformCount.of(
      Token.asNumber(Fn.lengthOf(foo.ids))
    );
    new FlowLog(this, "test_flow_log", {
      vpcId: Token.asString(
        Fn.lookupNested(
          Fn.lookupNested(dataAwsVpcFoo, [testFlowLogCount.index]),
          ["id"]
        )
      ),
      count: testFlowLogCount,
    });
  }
}

```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `tags` - (Optional) Map of tags, each pair of which must exactly match
  a pair on the desired vpcs.
* `filter` - (Optional) Custom filter block as described below.

### `filter`

More complex filters can be expressed using one or more `filter` sub-blocks, which take the following arguments:

* `name` - (Required) Name of the field to filter by, as defined by
  [the underlying AWS API](http://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html).
* `values` - (Required) Set of values that are accepted for the given field.
  A VPC will be selected if any one of the given values matches.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `id` - AWS Region.
* `ids` - List of all the VPC Ids found.

## Timeouts

[Configuration options](https://developer.hashicorp.com/terraform/language/resources/syntax#operation-timeouts):

- `read` - (Default `20m`)

<!-- cache-key: cdktf-0.20.8 input-0e0eaf339a99122aea452b9e85e5a920685e0201bdcf9e4ac09af83da7f285e2 -->