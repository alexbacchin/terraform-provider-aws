---
subcategory: "IAM (Identity & Access Management)"
layout: "aws"
page_title: "AWS: aws_iam_account_password_policy"
description: |-
  Manages Password Policy for the AWS Account.
---


<!-- Please do not edit this file, it is generated. -->
# Resource: aws_iam_account_password_policy

-> **Note:** There is only a single policy allowed per AWS account. An existing policy will be lost when using this resource as an effect of this limitation.

Manages Password Policy for the AWS Account.
See more about [Account Password Policy](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html)
in the official AWS docs.

## Example Usage

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.iam_account_password_policy import IamAccountPasswordPolicy
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        IamAccountPasswordPolicy(self, "strict",
            allow_users_to_change_password=True,
            minimum_password_length=8,
            require_lowercase_characters=True,
            require_numbers=True,
            require_symbols=True,
            require_uppercase_characters=True
        )
```

## Argument Reference

This resource supports the following arguments:

* `allow_users_to_change_password` - (Optional) Whether to allow users to change their own password
* `hard_expiry` - (Optional) Whether users are prevented from setting a new password after their password has expired (i.e., require administrator reset)
* `max_password_age` - (Optional) The number of days that an user password is valid.
* `minimum_password_length` - (Optional) Minimum length to require for user passwords.
* `password_reuse_prevention` - (Optional) The number of previous passwords that users are prevented from reusing.
* `require_lowercase_characters` - (Optional) Whether to require lowercase characters for user passwords.
* `require_numbers` - (Optional) Whether to require numbers for user passwords.
* `require_symbols` - (Optional) Whether to require symbols for user passwords.
* `require_uppercase_characters` - (Optional) Whether to require uppercase characters for user passwords.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `expire_passwords` - Indicates whether passwords in the account expire. Returns `true` if `max_password_age` contains a value greater than `0`. Returns `false` if it is `0` or _not present_.

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import IAM Account Password Policy using the word `iam-account-password-policy`. For example:

```python
# DO NOT EDIT. Code generated by 'cdktf convert' - Please report bugs at https://cdk.tf/bug
from constructs import Construct
from cdktf import TerraformStack
#
# Provider bindings are generated by running `cdktf get`.
# See https://cdk.tf/provider-generation for more details.
#
from imports.aws.iam_account_password_policy import IamAccountPasswordPolicy
class MyConvertedCode(TerraformStack):
    def __init__(self, scope, name):
        super().__init__(scope, name)
        IamAccountPasswordPolicy.generate_config_for_import(self, "strict", "iam-account-password-policy")
```

Using `terraform import`, import IAM Account Password Policy using the word `iam-account-password-policy`. For example:

```console
% terraform import aws_iam_account_password_policy.strict iam-account-password-policy
```

<!-- cache-key: cdktf-0.20.8 input-bc08150f6477fe05b7c648840dff00a4154ffcf28a4c1cad6ceaf55d1d45f131 -->