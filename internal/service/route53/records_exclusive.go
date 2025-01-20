// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package route53

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	awstypes "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/enum"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkResource("aws_route53_records_exclusive", name="Records Exclusive")
func newResourceRecordsExclusive(_ context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceRecordsExclusive{}

	r.SetDefaultCreateTimeout(30 * time.Minute)
	r.SetDefaultUpdateTimeout(30 * time.Minute)
	r.SetDefaultDeleteTimeout(30 * time.Minute)

	return r, nil
}

const (
	ResNameRecordsExclusive = "Records Exclusive"
)

type resourceRecordsExclusive struct {
	framework.ResourceWithConfigure
	framework.WithTimeouts
	framework.WithImportByID
}

func (r *resourceRecordsExclusive) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "aws_route53_records_exclusive"
}

func (r *resourceRecordsExclusive) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"zone_id": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"resource_record_set": schema.ListNestedBlock{
				CustomType: fwtypes.NewListNestedObjectTypeOf[resourceRecordSetModel](ctx),
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						names.AttrType: schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								enum.FrameworkValidate[awstypes.RRType](),
							},
						},
						names.AttrName: schema.StringAttribute{
							Required: true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
						},
						"ttl": schema.Int32Attribute{
							Optional: true,
							Validators: []validator.Int32{
								int32validator.Between(0, 2147483647),
							},
						},
						"weight": schema.Int32Attribute{
							Optional: true,
							Validators: []validator.Int32{
								int32validator.Between(0, 255),
							},
						},
						"failover": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								enum.FrameworkValidate[awstypes.ResourceRecordSetFailover](),
							},
						},
						"multi_value_answer": schema.BoolAttribute{
							Optional: true,
						},
						"set_identifier": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.LengthAtMost(128),
							},
						},
						"health_check_id": schema.StringAttribute{
							Optional: true,
						},
						"region": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 64),
							},
						},
						"traffic_policy_instance_id": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 36),
							},
						},
					},
					Blocks: map[string]schema.Block{
						"resource_records": schema.ListNestedBlock{
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
							},
							NestedObject: schema.NestedBlockObject{
								CustomType: fwtypes.NewListNestedObjectTypeOf[resourceRecordModel](ctx),
								Blocks: map[string]schema.Block{
									"resource_record": schema.ListNestedBlock{
										Validators: []validator.List{
											listvalidator.SizeAtLeast(1),
										},
										Attributes: map[string]schema.Attribute{
											"value": schema.StringAttribute{
												Required: true,
												Validators: []validator.String{
													stringvalidator.LengthAtMost(4000),
												},
											},
										},
									},
								},
							},
						},
						"alias_target": schema.ListNestedBlock{
							CustomType: fwtypes.NewListNestedObjectTypeOf[aliasTargetModel](ctx),
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
								listvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("ttl")),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"dns_name": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.LengthAtMost(1024),
										},
									},
									"evaluate_target_health": schema.BoolAttribute{
										Required: true,
									},
									"hosted_zone_id": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.LengthAtMost(32),
										},
									},
								},
							},
						},
						"cidr_routing_config": schema.ListNestedBlock{
							CustomType: fwtypes.NewListNestedObjectTypeOf[cidrRoutingConfigModel](ctx),
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
								listvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("set_identifier")),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"collection_id": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.RegexMatches(regexache.MustCompile(`[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}`), ""),
										},
									},
									"location_name": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.All(
												stringvalidator.LengthBetween(1, 16),
												stringvalidator.RegexMatches(regexache.MustCompile(`[0-9A-Za-z_\-\*]+`), ""),
											),
										},
									},
								},
							},
						},
						"geo_location": schema.ListNestedBlock{
							CustomType: fwtypes.NewListNestedObjectTypeOf[geoLocationModel](ctx),
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
								listvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName(names.AttrName), path.MatchRelative().AtParent().AtName(names.AttrType)),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"continent_code": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf("AF", "AN", "AS", "EU", "OC", "NA", "SA"),
										},
									},
									"country_code": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.LengthBetween(1, 2),
										},
									},
									"subdivision_code": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.LengthBetween(1, 3),
										},
									},
								},
							},
						},
						"geo_proximity_location": schema.ListNestedBlock{
							CustomType: fwtypes.NewListNestedObjectTypeOf[geoProximityLocationModel](ctx),
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
								listvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName(names.AttrName), path.MatchRelative().AtParent().AtName(names.AttrType)),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"aws_region": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.LengthBetween(1, 64),
										},
									},
									"bias": schema.Int32Attribute{
										Optional: true,
										Validators: []validator.Int32{
											int32validator.Between(-99, 99),
										},
									},
									"local_zone_group": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.LengthBetween(1, 64),
										},
									},
								},
								Blocks: map[string]schema.Block{
									"coordinates": schema.ListNestedBlock{
										CustomType: fwtypes.NewListNestedObjectTypeOf[coordinatesModel](ctx),
										Validators: []validator.List{
											listvalidator.SizeAtMost(1),
										},
										NestedObject: schema.NestedBlockObject{
											Attributes: map[string]schema.Attribute{
												"latitude": schema.StringAttribute{
													Required: true,
													Validators: []validator.String{
														stringvalidator.RegexMatches(regexache.MustCompile(`[-+]?[0-9]{1,2}(\.[0-9]{0,2})?`), ""),
													},
												},
												"longitude": schema.StringAttribute{
													Required: true,
													Validators: []validator.String{
														stringvalidator.RegexMatches(regexache.MustCompile(`[-+]?[0-9]{1,3}(\.[0-9]{0,2})?`), ""),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"timeouts": timeouts.Block(ctx, timeouts.Opts{
				Create: true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

func (r *resourceRecordsExclusive) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {

	conn := r.Meta().Route53Client(ctx)

	var plan resourceRecordsExclusiveModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var resourceRecordSets []awstypes.ResourceRecordSet
	resp.Diagnostics.Append(flex.Expand(ctx, plan.ResourceRecordSets, &resourceRecordSets)...)
	if resp.Diagnostics.HasError() {
		return
	}
	changes := make([]awstypes.Change, 0, len(resourceRecordSets))
	for index, resourceRecordSet := range resourceRecordSets {
		changes[index] = awstypes.Change{
			Action:            awstypes.ChangeActionCreate,
			ResourceRecordSet: &resourceRecordSet,
		}
	}
	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: plan.ID.ValueStringPointer(),
		ChangeBatch: &awstypes.ChangeBatch{
			Changes: changes,
		},
	}

	out, err := conn.ChangeResourceRecordSets(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.Route53, create.ErrActionCreating, ResNameRecordsExclusive, plan.ID.String(), err),
			err.Error(),
		)
		return
	}
	if out == nil || out.ChangeInfo == nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.Route53, create.ErrActionCreating, ResNameRecordsExclusive, plan.ID.String(), nil),
			errors.New("empty output").Error(),
		)
		return
	}

	createTimeout := r.CreateTimeout(ctx, plan.Timeouts)
	_, err = waitChangeSync(ctx, conn, *out.ChangeInfo.Id, createTimeout)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.Route53, create.ErrActionWaitingForCreation, ResNameRecordsExclusive, plan.ID.String(), err),
			err.Error(),
		)
		return
	}
	// TIP: -- 7. Save the request plan to response state
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceRecordsExclusive) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().Route53Client(ctx)

	var state resourceRecordsExclusiveModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TIP: -- 3. Get the resource from AWS using an API Get, List, or Describe-
	// type function, or, better yet, using a finder.
	out, err := findRecordsExclusiveByID(ctx, conn, state.ID.ValueString())
	// TIP: -- 4. Remove resource from state if it is not found
	if tfresource.NotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.Route53, create.ErrActionSetting, ResNameRecordsExclusive, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	// TIP: -- 5. Set the arguments and attributes
	resp.Diagnostics.Append(flex.Flatten(ctx, out, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TIP: -- 6. Set the state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceRecordsExclusive) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// TIP: ==== RESOURCE UPDATE ====
	// Not all resources have Update functions. There are a few reasons:
	// a. The AWS API does not support changing a resource
	// b. All arguments have RequiresReplace() plan modifiers
	// c. The AWS API uses a create call to modify an existing resource
	//
	// In the cases of a. and b., the resource will not have an update method
	// defined. In the case of c., Update and Create can be refactored to call
	// the same underlying function.
	//
	// The rest of the time, there should be an Update function and it should
	// do the following things. Make sure there is a good reason if you don't
	// do one of these.
	//
	// 1. Get a client connection to the relevant service
	// 2. Fetch the plan and state
	// 3. Populate a modify input structure and check for changes
	// 4. Call the AWS modify/update function
	// 5. Use a waiter to wait for update to complete
	// 6. Save the request plan to response state
	// TIP: -- 1. Get a client connection to the relevant service
	conn := r.Meta().Client(ctx)

	// TIP: -- 2. Fetch the plan
	var plan, state resourceRecordsExclusiveModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TIP: -- 3. Populate a modify input structure and check for changes
	if !plan.Name.Equal(state.Name) ||
		!plan.Description.Equal(state.Description) ||
		!plan.ComplexArgument.Equal(state.ComplexArgument) ||
		!plan.Type.Equal(state.Type) {

		var input awstypes.UpdateRecordsExclusiveInput
		resp.Diagnostics.Append(flex.Expand(ctx, plan, &input, flex.WithFieldNamePrefix("Test"))...)
		if resp.Diagnostics.HasError() {
			return
		}

		// TIP: -- 4. Call the AWS modify/update function
		out, err := conn.UpdateRecordsExclusive(ctx, &input)
		if err != nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.Route53, create.ErrActionUpdating, ResNameRecordsExclusive, plan.ID.String(), err),
				err.Error(),
			)
			return
		}
		if out == nil || out.RecordsExclusive == nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.Route53, create.ErrActionUpdating, ResNameRecordsExclusive, plan.ID.String(), nil),
				errors.New("empty output").Error(),
			)
			return
		}

		// TIP: Using the output from the update function, re-set any computed attributes
		resp.Diagnostics.Append(flex.Flatten(ctx, out, &plan)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// TIP: -- 5. Use a waiter to wait for update to complete
	updateTimeout := r.UpdateTimeout(ctx, plan.Timeouts)
	_, err := waitRecordsExclusiveUpdated(ctx, conn, plan.ID.ValueString(), updateTimeout)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.Route53, create.ErrActionWaitingForUpdate, ResNameRecordsExclusive, plan.ID.String(), err),
			err.Error(),
		)
		return
	}

	// TIP: -- 6. Save the request plan to response state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resourceRecordsExclusive) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// TIP: ==== RESOURCE DELETE ====
	// Most resources have Delete functions. There are rare situations
	// where you might not need a delete:
	// a. The AWS API does not provide a way to delete the resource
	// b. The point of your resource is to perform an action (e.g., reboot a
	//    server) and deleting serves no purpose.
	//
	// The Delete function should do the following things. Make sure there
	// is a good reason if you don't do one of these.
	//
	// 1. Get a client connection to the relevant service
	// 2. Fetch the state
	// 3. Populate a delete input structure
	// 4. Call the AWS delete function
	// 5. Use a waiter to wait for delete to complete
	// TIP: -- 1. Get a client connection to the relevant service
	conn := r.Meta().Route53Client(ctx)

	// TIP: -- 2. Fetch the state
	var state resourceRecordsExclusiveModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TIP: -- 3. Populate a delete input structure
	input := route53.DeleteRecordsExclusiveInput{
		RecordsExclusiveId: state.ID.ValueStringPointer(),
	}

	// TIP: -- 4. Call the AWS delete function
	_, err := conn.DeleteRecordsExclusive(ctx, &input)
	// TIP: On rare occassions, the API returns a not found error after deleting a
	// resource. If that happens, we don't want it to show up as an error.
	if err != nil {
		if errs.IsA[*awstypes.ResourceNotFoundException](err) {
			return
		}
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.Route53, create.ErrActionDeleting, ResNameRecordsExclusive, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	// TIP: -- 5. Use a waiter to wait for delete to complete
	deleteTimeout := r.DeleteTimeout(ctx, state.Timeouts)
	_, err = waitRecordsExclusiveDeleted(ctx, conn, state.ID.ValueString(), deleteTimeout)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.Route53, create.ErrActionWaitingForDeletion, ResNameRecordsExclusive, state.ID.String(), err),
			err.Error(),
		)
		return
	}
}

// TIP: ==== TERRAFORM IMPORTING ====
// If Read can get all the information it needs from the Identifier
// (i.e., path.Root("id")), you can use the PassthroughID importer. Otherwise,
// you'll need a custom import function.
//
// See more:
// https://developer.hashicorp.com/terraform/plugin/framework/resources/import
func (r *resourceRecordsExclusive) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func findResourceRecordSetByID(ctx context.Context, conn *route53.Client, id string) (*[]awstypes.ResourceRecordSet, error) {
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(id),
	}
	var output []awstypes.ResourceRecordSet

	pages := route53.NewListResourceRecordSetsPaginator(conn, input)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, v := range page.ResourceRecordSets {
			output = append(output, v)
		}
	}
	return &output, nil
}

func waitChangeSync(ctx context.Context, conn *route53.Client, id string, timeout time.Duration) (*awstypes.ChangeInfo, error) {
	stateConf := &retry.StateChangeConf{
		Pending:                   enum.Slice(awstypes.ChangeStatusPending),
		Target:                    enum.Slice(awstypes.ChangeStatusInsync),
		Refresh:                   statusChange(ctx, conn, id),
		Timeout:                   timeout,
		NotFoundChecks:            20,
		ContinuousTargetOccurence: 2,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*awstypes.ChangeInfo); ok {
		return output, err
	}

	return nil, err
}

func statusChangeInfo(ctx context.Context, conn *route53.Client, id string) retry.StateRefreshFunc {
	return func() (interface{}, string, error) {
		output, err := findChangeInfoByID(ctx, conn, id)

		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return output, string(output.Status), nil
	}
}

func findChangeInfoByID(ctx context.Context, conn *route53.Client, id string) (*awstypes.ChangeInfo, error) {
	input := &route53.GetChangeInput{
		Id: aws.String(id),
	}

	output, err := conn.GetChange(ctx, input)

	if errs.IsA[*awstypes.NoSuchChange](err) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.ChangeInfo == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output.ChangeInfo, nil
}

// function to sort awstypes.ResourceRecordSet by name, type
func sortResourceRecordSets(resourceRecordSets []resourceRecordSetModel) {
	sort.Slice(resourceRecordSets, func(i, j int) bool {
		if reverseDNSName(resourceRecordSets[i].Name.ValueString()) != reverseDNSName(resourceRecordSets[j].Name.ValueString()) {
			return resourceRecordSets[i].Name.ValueString() < resourceRecordSets[j].Name.ValueString()
		}
		return resourceRecordSets[i].Type.ValueString() < resourceRecordSets[j].Type.ValueString()
	})
}

// reverseDNSName reverses the order of a DNS hostname string.
// This is useful for sorting DNS names in a way that groups subdomains together.
// For example, "www.example.com." becomes "com.example.www.".
func reverseDNSName(dnsName string) string {
	// Remove trailing dot if present
	hasTrailingDot := strings.HasSuffix(dnsName, ".")
	if hasTrailingDot {
		dnsName = dnsName[:len(dnsName)-1]
	}
	segments := strings.Split(dnsName, ".")
	for left, right := 0, len(segments)-1; left < right; left, right = left+1, right-1 {
		segments[left], segments[right] = segments[right], segments[left]
	}
	reversed := strings.Join(segments, ".")
	// Add trailing dot back if it was present
	if hasTrailingDot {
		reversed += "."
	}
	return reversed
}

type resourceRecordsExclusiveModel struct {
	ID                 types.String                                            `tfsdk:"zone_id"`
	ResourceRecordSets fwtypes.ListNestedObjectValueOf[resourceRecordSetModel] `tfsdk:"resource_record_set"`
	Timeouts           timeouts.Value                                          `tfsdk:"timeouts"`
}

type resourceRecordSetModel struct {
	Name                    types.String                                               `tfsdk:"name"`
	Type                    types.String                                               `tfsdk:"type"`
	TTL                     types.Int32                                                `tfsdk:"ttl"`
	Weight                  types.Int32                                                `tfsdk:"weight"`
	Failover                types.String                                               `tfsdk:"failover"`
	MultiValueAnswer        types.Bool                                                 `tfsdk:"multi_value_answer"`
	SetIdentifier           types.String                                               `tfsdk:"set_identifier"`
	HealthCheckId           types.String                                               `tfsdk:"health_check_id"`
	Region                  types.String                                               `tfsdk:"region"`
	TrafficPolicyInstanceId types.String                                               `tfsdk:"traffic_policy_instance_id"`
	Alias                   fwtypes.ListNestedObjectValueOf[aliasTargetModel]          `tfsdk:"alias"`
	CIDRRoutingConfig       fwtypes.ListNestedObjectValueOf[cidrRoutingConfigModel]    `tfsdk:"cidr_routing_config"`
	GeoLocation             fwtypes.ListNestedObjectValueOf[geoLocationModel]          `tfsdk:"geo_location"`
	GeoProximityLocation    fwtypes.ListNestedObjectValueOf[geoProximityLocationModel] `tfsdk:"geo_proximity_location"`
	ResourceRecords         fwtypes.ListNestedObjectValueOf[resourceRecordModel]       `tfsdk:"resource_records"`
}

type resourceRecordModel struct {
	Value types.String `tfsdk:"value"`
}

type aliasTargetModel struct {
	DNSName              types.String `tfsdk:"dns_name"`
	EvaluateTargetHealth types.Bool   `tfsdk:"evaluate_target_health"`
	HostedZoneId         types.String `tfsdk:"hosted_zone_id"`
}

type cidrRoutingConfigModel struct {
	CollectionId types.String `tfsdk:"collection_id"`
	LocationName types.String `tfsdk:"location_name"`
}

type geoLocationModel struct {
	ContinentCode   types.String `tfsdk:"continent_code"`
	CountryCode     types.String `tfsdk:"country_code"`
	SubdivisionCode types.String `tfsdk:"subdivision_code"`
}

type geoProximityLocationModel struct {
	AWSRegion      types.String                                      `tfsdk:"aws_region"`
	Bias           types.Int32                                       `tfsdk:"bias"`
	LocalZoneGroup types.String                                      `tfsdk:"local_zone_group"`
	Coordinates    fwtypes.ListNestedObjectValueOf[coordinatesModel] `tfsdk:"coordinates"`
}

type coordinatesModel struct {
	Latitude  types.String `tfsdk:"latitude"`
	Longitude types.String `tfsdk:"longitude"`
}
