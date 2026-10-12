// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MPL-2.0

package eventbridgev2

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridgev2"
	"github.com/hashicorp/terraform-plugin-framework/list"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/fwdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	"github.com/hashicorp/terraform-provider-aws/internal/logging"
	"github.com/hashicorp/terraform-provider-aws/internal/retry"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkListResource("aws_eventbridgev2_resource_policy")
func newResourcePolicyResourceAsListResource() list.ListResourceWithConfigure {
	return &resourcePolicyListResource{}
}

var _ list.ListResource = &resourcePolicyListResource{}

type resourcePolicyListResource struct {
	resourcePolicyResource
	framework.WithList
}

func (l *resourcePolicyListResource) List(ctx context.Context, request list.ListRequest, stream *list.ListResultsStream) {
	conn := l.Meta().EventBridgeV2Client(ctx)

	accountID := l.Meta().AccountID(ctx)
	input := eventbridgev2.ListEventBusesInput{
		EventBusAccountId: aws.String(accountID),
	}

	stream.Results = func(yield func(list.ListResult) bool) {
		for bus, err := range listEventBuses(ctx, conn, &input) {
			if err != nil {
				yield(fwdiag.NewListResultErrorDiagnostic(err))
				return
			}

			// Buses shared from other accounts through AWS RAM cannot be managed.
			if v := aws.ToString(bus.EventBusAccountId); v != "" && v != accountID {
				continue
			}

			arn := aws.ToString(bus.EventBusArn)
			ctx := tflog.SetField(ctx, logging.ResourceAttributeKey(names.AttrResourceARN), arn)

			output, err := findResourcePolicyByARN(ctx, conn, arn)
			if retry.NotFound(err) {
				continue
			}
			if err != nil {
				yield(fwdiag.NewListResultErrorDiagnostic(err))
				return
			}

			result := request.NewListResult(ctx)

			var data resourcePolicyResourceModel
			l.SetResult(ctx, l.Meta(), request.IncludeResource, &data, &result, func() {
				data.ResourceARN = fwtypes.ARNValue(arn)

				if request.IncludeResource {
					result.Diagnostics.Append(l.flatten(ctx, output, &data)...)
					if result.Diagnostics.HasError() {
						return
					}
				}

				result.DisplayName = aws.ToString(bus.Name)
			})

			if result.Diagnostics.HasError() {
				yield(list.ListResult{Diagnostics: result.Diagnostics})
				return
			}

			if !yield(result) {
				return
			}
		}
	}
}
