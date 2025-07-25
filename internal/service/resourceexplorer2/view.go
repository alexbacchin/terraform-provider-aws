// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package resourceexplorer2

import (
	"context"
	"fmt"
	"strings"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	awstypes "github.com/aws/aws-sdk-go-v2/service/resourceexplorer2/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	sdkid "github.com/hashicorp/terraform-plugin-sdk/v2/helper/id"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/fwdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	fwflex "github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkResource("aws_resourceexplorer2_view", name="View")
// @Tags(identifierAttribute="arn")
// @ArnIdentity(identityDuplicateAttributes="id")
// @Testing(existsType="github.com/aws/aws-sdk-go-v2/service/resourceexplorer2;resourceexplorer2.GetViewOutput")
// @Testing(serialize=true)
func newViewResource(context.Context) (resource.ResourceWithConfigure, error) {
	return &viewResource{}, nil
}

type viewResource struct {
	framework.ResourceWithModel[viewResourceModel]
	framework.WithImportByIdentity
}

func (r *viewResource) Schema(ctx context.Context, request resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			names.AttrARN: schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"default_view": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			names.AttrID: framework.IDAttribute(),
			names.AttrName: schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtMost(64),
					stringvalidator.RegexMatches(regexache.MustCompile(`^[0-9A-Za-z-]+$`), `can include letters, digits, and the dash (-) character`),
				},
			},
			names.AttrScope: schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			names.AttrTags:    tftags.TagsAttribute(),
			names.AttrTagsAll: tftags.TagsAttributeComputedOnly(),
		},
		Blocks: map[string]schema.Block{
			"filters": schema.ListNestedBlock{
				CustomType: fwtypes.NewListNestedObjectTypeOf[searchFilterModel](ctx),
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"filter_string": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.LengthAtMost(2048),
							},
						},
					},
				},
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
			},
			"included_property": schema.ListNestedBlock{
				CustomType: fwtypes.NewListNestedObjectTypeOf[includedPropertyModel](ctx),
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						names.AttrName: schema.StringAttribute{
							CustomType: fwtypes.StringEnumType[propertyName](),
							Required:   true,
						},
					},
				},
			},
		},
	}
}

func (r *viewResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var data viewResourceModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	conn := r.Meta().ResourceExplorer2Client(ctx)

	input := &resourceexplorer2.CreateViewInput{}
	response.Diagnostics.Append(fwflex.Expand(ctx, data, input)...)
	if response.Diagnostics.HasError() {
		return
	}

	input.ClientToken = aws.String(sdkid.UniqueId())
	input.Tags = getTagsIn(ctx)

	output, err := conn.CreateView(ctx, input)

	if err != nil {
		response.Diagnostics.AddError("creating Resource Explorer View", err.Error())

		return
	}

	arn := aws.ToString(output.View.ViewArn)
	// Set values for unknowns.
	data.Scope = types.StringValue(aws.ToString(output.View.Scope))
	data.ViewARN = types.StringValue(arn)
	data.setID()

	if data.DefaultView.ValueBool() {
		input := &resourceexplorer2.AssociateDefaultViewInput{
			ViewArn: aws.String(arn),
		}

		_, err := conn.AssociateDefaultView(ctx, input)

		if err != nil {
			response.State.SetAttribute(ctx, path.Root(names.AttrID), data.ID) // Set 'id' so as to taint the resource.
			response.Diagnostics.AddError(fmt.Sprintf("setting Resource Explorer View (%s) as the default", arn), err.Error())

			return
		}
	}

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

func (r *viewResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var data viewResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	if err := data.initFromID(); err != nil {
		response.Diagnostics.AddError("parsing resource ID", err.Error())

		return
	}

	conn := r.Meta().ResourceExplorer2Client(ctx)

	output, err := findViewByARN(ctx, conn, data.ViewARN.ValueString())

	if tfresource.NotFound(err) {
		response.Diagnostics.Append(fwdiag.NewResourceNotFoundWarningDiagnostic(err))
		response.State.RemoveResource(ctx)

		return
	}

	if err != nil {
		response.Diagnostics.AddError(fmt.Sprintf("reading Resource Explorer View (%s)", data.ID.ValueString()), err.Error())

		return
	}

	defaultViewARN, err := findDefaultViewARN(ctx, conn)

	if err != nil {
		response.Diagnostics.AddError("reading Resource Explorer Default View", err.Error())

		return
	}

	view := output.View
	// The default is
	//
	//   "Filters": {
	// 	   "FilterString": ""
	//   },
	//
	// a view that performs no filtering.
	// See https://docs.aws.amazon.com/resource-explorer/latest/apireference/API_CreateView.html#API_CreateView_Example_1.
	if view.Filters != nil && len(aws.ToString(view.Filters.FilterString)) == 0 {
		view.Filters = nil
	}

	response.Diagnostics.Append(fwflex.Flatten(ctx, view, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	data.DefaultView = types.BoolValue(defaultViewARN == data.ViewARN.ValueString())

	setTagsOut(ctx, output.Tags)

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

func (r *viewResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var old, new viewResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &old)...)
	if response.Diagnostics.HasError() {
		return
	}
	response.Diagnostics.Append(request.Plan.Get(ctx, &new)...)
	if response.Diagnostics.HasError() {
		return
	}

	if new.Scope.IsUnknown() {
		new.Scope = types.StringValue(old.Scope.ValueString())
	}

	conn := r.Meta().ResourceExplorer2Client(ctx)

	if !new.Filters.Equal(old.Filters) || !new.IncludedProperties.Equal(old.IncludedProperties) {
		input := &resourceexplorer2.UpdateViewInput{}
		response.Diagnostics.Append(fwflex.Expand(ctx, new, input)...)
		if response.Diagnostics.HasError() {
			return
		}

		_, err := conn.UpdateView(ctx, input)

		if err != nil {
			response.Diagnostics.AddError(fmt.Sprintf("updating Resource Explorer View (%s)", new.ID.ValueString()), err.Error())

			return
		}
	}

	if !new.DefaultView.Equal(old.DefaultView) {
		if new.DefaultView.ValueBool() {
			input := &resourceexplorer2.AssociateDefaultViewInput{
				ViewArn: fwflex.StringFromFramework(ctx, new.ViewARN),
			}

			_, err := conn.AssociateDefaultView(ctx, input)

			if err != nil {
				response.Diagnostics.AddError(fmt.Sprintf("setting Resource Explorer View (%s) as the default", new.ID.ValueString()), err.Error())

				return
			}
		} else {
			input := &resourceexplorer2.DisassociateDefaultViewInput{}

			_, err := conn.DisassociateDefaultView(ctx, input)

			if err != nil {
				response.Diagnostics.AddError(fmt.Sprintf("unsetting Resource Explorer View (%s) as the default", new.ID.ValueString()), err.Error())

				return
			}
		}
	}

	response.Diagnostics.Append(response.State.Set(ctx, &new)...)
}

func (r *viewResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var data viewResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &data)...)
	if response.Diagnostics.HasError() {
		return
	}

	conn := r.Meta().ResourceExplorer2Client(ctx)

	tflog.Debug(ctx, "deleting Resource Explorer View", map[string]any{
		names.AttrID: data.ID.ValueString(),
	})
	_, err := conn.DeleteView(ctx, &resourceexplorer2.DeleteViewInput{
		ViewArn: fwflex.StringFromFramework(ctx, data.ViewARN),
	})

	if errs.IsA[*awstypes.UnauthorizedException](err) {
		return
	}

	if err != nil {
		response.Diagnostics.AddError(fmt.Sprintf("deleting Resource Explorer View (%s)", data.ID.ValueString()), err.Error())

		return
	}
}

// See https://docs.aws.amazon.com/resource-explorer/latest/apireference/API_View.html.
type viewResourceModel struct {
	framework.WithRegionModel
	DefaultView        types.Bool                                             `tfsdk:"default_view"`
	Filters            fwtypes.ListNestedObjectValueOf[searchFilterModel]     `tfsdk:"filters"`
	ID                 types.String                                           `tfsdk:"id"`
	IncludedProperties fwtypes.ListNestedObjectValueOf[includedPropertyModel] `tfsdk:"included_property"`
	Scope              types.String                                           `tfsdk:"scope"`
	Tags               tftags.Map                                             `tfsdk:"tags"`
	TagsAll            tftags.Map                                             `tfsdk:"tags_all"`
	ViewARN            types.String                                           `tfsdk:"arn"`
	ViewName           types.String                                           `tfsdk:"name"`
}

func (data *viewResourceModel) initFromID() error {
	data.ViewARN = data.ID
	arn, err := arn.Parse(data.ViewARN.ValueString())
	if err != nil {
		return err
	}
	// view/${ViewName}/${ViewUuid}
	parts := strings.Split(arn.Resource, "/")
	if n := len(parts); n != 3 {
		return fmt.Errorf("incorrect Resource Explorer View ARN format: %d parts", n)
	}
	name := parts[1]
	data.ViewName = types.StringValue(name)

	return nil
}

func (data *viewResourceModel) setID() {
	data.ID = data.ViewARN
}

type searchFilterModel struct {
	FilterString types.String `tfsdk:"filter_string"`
}

type includedPropertyModel struct {
	Name fwtypes.StringEnum[propertyName] `tfsdk:"name"`
}

func findDefaultViewARN(ctx context.Context, conn *resourceexplorer2.Client) (string, error) {
	input := &resourceexplorer2.GetDefaultViewInput{}

	output, err := conn.GetDefaultView(ctx, input)

	if err != nil {
		return "", err
	}

	if output == nil {
		return "", nil
	}

	return aws.ToString(output.ViewArn), nil
}

func findViewByARN(ctx context.Context, conn *resourceexplorer2.Client, arn string) (*resourceexplorer2.GetViewOutput, error) {
	input := &resourceexplorer2.GetViewInput{
		ViewArn: aws.String(arn),
	}

	output, err := conn.GetView(ctx, input)

	if errs.IsA[*awstypes.ResourceNotFoundException](err) || errs.IsA[*awstypes.UnauthorizedException](err) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.View == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output, nil
}

type propertyName string

// Enum values for propertyName.
const (
	propertyNameTags propertyName = names.AttrTags
)

func (propertyName) Values() []propertyName {
	return []propertyName{
		propertyNameTags,
	}
}
