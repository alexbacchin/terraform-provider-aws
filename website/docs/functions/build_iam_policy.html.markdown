---
subcategory: ""
layout: "aws"
page_title: "AWS: build_iam_policy"
description: |-
  Build IAM Policy documents.
---
<!---
TIP: A few guiding principles for writing documentation:
1. Use simple language while avoiding jargon and figures of speech.
2. Focus on brevity and clarity to keep a reader's attention.
3. Use active voice and present tense whenever you can.
4. Document your feature as it exists now; do not mention the future or past if you can help it.
5. Use accessible and inclusive language.
--->`
# Function: build_iam_policy

~> Provider-defined functions are supported in Terraform 1.8 and later.

Build IAM Policy documents.

## Example Usage

```terraform
# result: foo-bar
output "example" {
  value = provider::aws::build_iam_policy("foo")
}
```

## Signature

```text
build_iam_policy(arg string) string
```

## Arguments

1. `arg` (String) Example argument description.
