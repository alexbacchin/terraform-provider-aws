// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package networkfirewall

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	awstypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/fwdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	tfretry "github.com/hashicorp/terraform-provider-aws/internal/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/smerr"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkResource("aws_networkfirewall_proxy_rules", name="Proxy Rules")
func newResourceProxyRules(_ context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceProxyRules{}

	return r, nil
}

const (
	ResNameProxyRules = "Proxy Rules"
)

type resourceProxyRules struct {
	framework.ResourceWithModel[resourceProxyRulesModel]
}

func (r *resourceProxyRules) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			names.AttrID: framework.IDAttribute(),
			"proxy_rule_group_arn": schema.StringAttribute{
				CustomType: fwtypes.ARNType,
				Optional:   true,
				Computed:   true,
				Validators: []validator.String{
					stringvalidator.AtLeastOneOf(path.MatchRoot("proxy_rule_group_name")),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"proxy_rule_group_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.AtLeastOneOf(path.MatchRoot("proxy_rule_group_arn")),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"post_response": schema.ListNestedBlock{
				CustomType: fwtypes.NewListNestedObjectTypeOf[proxyRuleModel](ctx),
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"action": schema.StringAttribute{
							CustomType: fwtypes.StringEnumType[awstypes.ProxyRulePhaseAction](),
							Required:   true,
						},
						names.AttrDescription: schema.StringAttribute{
							Optional: true,
						},
						"insert_position": schema.Int64Attribute{
							Optional: true,
						},
						"proxy_rule_name": schema.StringAttribute{
							Required: true,
						},
					},
					Blocks: map[string]schema.Block{
						"conditions": schema.ListNestedBlock{
							CustomType: fwtypes.NewListNestedObjectTypeOf[conditionModel](ctx),
							Validators: []validator.List{
								listvalidator.SizeAtLeast(1),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"condition_key": schema.StringAttribute{
										Required: true,
									},
									"condition_operator": schema.StringAttribute{
										Required: true,
									},
									"condition_values": schema.ListAttribute{
										CustomType:  fwtypes.ListOfStringType,
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
						},
					},
				},
			},
			"pre_dns": schema.ListNestedBlock{
				CustomType: fwtypes.NewListNestedObjectTypeOf[proxyRuleModel](ctx),
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"action": schema.StringAttribute{
							CustomType: fwtypes.StringEnumType[awstypes.ProxyRulePhaseAction](),
							Required:   true,
						},
						names.AttrDescription: schema.StringAttribute{
							Optional: true,
						},
						"insert_position": schema.Int64Attribute{
							Optional: true,
						},
						"proxy_rule_name": schema.StringAttribute{
							Required: true,
						},
					},
					Blocks: map[string]schema.Block{
						"conditions": schema.ListNestedBlock{
							CustomType: fwtypes.NewListNestedObjectTypeOf[conditionModel](ctx),
							Validators: []validator.List{
								listvalidator.SizeAtLeast(1),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"condition_key": schema.StringAttribute{
										Required: true,
									},
									"condition_operator": schema.StringAttribute{
										Required: true,
									},
									"condition_values": schema.ListAttribute{
										CustomType:  fwtypes.ListOfStringType,
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
						},
					},
				},
			},
			"pre_request": schema.ListNestedBlock{
				CustomType: fwtypes.NewListNestedObjectTypeOf[proxyRuleModel](ctx),
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"action": schema.StringAttribute{
							CustomType: fwtypes.StringEnumType[awstypes.ProxyRulePhaseAction](),
							Required:   true,
						},
						names.AttrDescription: schema.StringAttribute{
							Optional: true,
						},
						"insert_position": schema.Int64Attribute{
							Optional: true,
						},
						"proxy_rule_name": schema.StringAttribute{
							Required: true,
						},
					},
					Blocks: map[string]schema.Block{
						"conditions": schema.ListNestedBlock{
							CustomType: fwtypes.NewListNestedObjectTypeOf[conditionModel](ctx),
							Validators: []validator.List{
								listvalidator.SizeAtLeast(1),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"condition_key": schema.StringAttribute{
										Required: true,
									},
									"condition_operator": schema.StringAttribute{
										Required: true,
									},
									"condition_values": schema.ListAttribute{
										CustomType:  fwtypes.ListOfStringType,
										ElementType: types.StringType,
										Required:    true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *resourceProxyRules) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().NetworkFirewallClient(ctx)

	var plan resourceProxyRulesModel
	smerr.AddEnrich(ctx, &resp.Diagnostics, req.Plan.Get(ctx, &plan))
	if resp.Diagnostics.HasError() {
		return
	}

	var input networkfirewall.CreateProxyRulesInput
	input.ProxyRuleGroupArn = plan.ProxyRuleGroupArn.ValueStringPointer()

	// Create the Rules structure organized by phase
	var rulesByPhase awstypes.CreateProxyRulesByRequestPhase

	// Process PostRESPONSE rules
	if !plan.PostRESPONSE.IsNull() && !plan.PostRESPONSE.IsUnknown() {
		var postRules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PostRESPONSE.ElementsAs(ctx, &postRules, false))
		if resp.Diagnostics.HasError() {
			return
		}

		for _, ruleModel := range postRules {
			var rule awstypes.CreateProxyRule
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, ruleModel, &rule))
			if resp.Diagnostics.HasError() {
				return
			}
			rulesByPhase.PostRESPONSE = append(rulesByPhase.PostRESPONSE, rule)
		}
	}

	// Process PreDNS rules
	if !plan.PreDNS.IsNull() && !plan.PreDNS.IsUnknown() {
		var preDNSRules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PreDNS.ElementsAs(ctx, &preDNSRules, false))
		if resp.Diagnostics.HasError() {
			return
		}

		for _, ruleModel := range preDNSRules {
			var rule awstypes.CreateProxyRule
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, ruleModel, &rule))
			if resp.Diagnostics.HasError() {
				return
			}
			rulesByPhase.PreDNS = append(rulesByPhase.PreDNS, rule)
		}
	}

	// Process PreREQUEST rules
	if !plan.PreREQUEST.IsNull() && !plan.PreREQUEST.IsUnknown() {
		var preRequestRules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PreREQUEST.ElementsAs(ctx, &preRequestRules, false))
		if resp.Diagnostics.HasError() {
			return
		}

		for _, ruleModel := range preRequestRules {
			var rule awstypes.CreateProxyRule
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, ruleModel, &rule))
			if resp.Diagnostics.HasError() {
				return
			}
			rulesByPhase.PreREQUEST = append(rulesByPhase.PreREQUEST, rule)
		}
	}

	input.Rules = &rulesByPhase

	out, err := conn.CreateProxyRules(ctx, &input)
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ProxyRuleGroupArn.String())
		return
	}
	if out == nil || out.ProxyRuleGroup == nil {
		smerr.AddError(ctx, &resp.Diagnostics, errors.New("empty output"), smerr.ID, plan.ProxyRuleGroupArn.String())
		return
	}

	// Set ID to the proxy rule group ARN
	plan.ID = plan.ProxyRuleGroupArn.StringValue

	// Read back to get full state
	readOut, err := findProxyRulesByGroupARN(ctx, conn, plan.ProxyRuleGroupArn.ValueString())
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ProxyRuleGroupArn.String())
		return
	}

	smerr.AddEnrich(ctx, &resp.Diagnostics, flattenProxyRules(ctx, readOut, &plan))
	if resp.Diagnostics.HasError() {
		return
	}

	smerr.AddEnrich(ctx, &resp.Diagnostics, resp.State.Set(ctx, plan))
}

func (r *resourceProxyRules) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().NetworkFirewallClient(ctx)

	var state resourceProxyRulesModel
	smerr.AddEnrich(ctx, &resp.Diagnostics, req.State.Get(ctx, &state))
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := findProxyRulesByGroupARN(ctx, conn, state.ID.ValueString())
	if tfretry.NotFound(err) {
		resp.Diagnostics.Append(fwdiag.NewResourceNotFoundWarningDiagnostic(err))
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ID.String())
		return
	}

	smerr.AddEnrich(ctx, &resp.Diagnostics, flattenProxyRules(ctx, out, &state))
	if resp.Diagnostics.HasError() {
		return
	}

	smerr.AddEnrich(ctx, &resp.Diagnostics, resp.State.Set(ctx, &state))
}

func (r *resourceProxyRules) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	conn := r.Meta().NetworkFirewallClient(ctx)

	var plan, state resourceProxyRulesModel
	smerr.AddEnrich(ctx, &resp.Diagnostics, req.Plan.Get(ctx, &plan))
	smerr.AddEnrich(ctx, &resp.Diagnostics, req.State.Get(ctx, &state))
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current state to obtain update token
	currentRules, err := findProxyRulesByGroupARN(ctx, conn, state.ProxyRuleGroupArn.ValueString())
	if err != nil && !tfretry.NotFound(err) {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ID.String())
		return
	}

	updateToken := currentRules.UpdateToken

	// Build maps of rules by name for each phase
	stateRulesByName := make(map[string]proxyRuleModel)
	planRulesByName := make(map[string]proxyRuleModel)

	// Extract state rules
	if !state.PostRESPONSE.IsNull() && !state.PostRESPONSE.IsUnknown() {
		var rules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, state.PostRESPONSE.ElementsAs(ctx, &rules, false))
		for _, rule := range rules {
			stateRulesByName[rule.ProxyRuleName.ValueString()] = rule
		}
	}
	if !state.PreDNS.IsNull() && !state.PreDNS.IsUnknown() {
		var rules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, state.PreDNS.ElementsAs(ctx, &rules, false))
		for _, rule := range rules {
			stateRulesByName[rule.ProxyRuleName.ValueString()] = rule
		}
	}
	if !state.PreREQUEST.IsNull() && !state.PreREQUEST.IsUnknown() {
		var rules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, state.PreREQUEST.ElementsAs(ctx, &rules, false))
		for _, rule := range rules {
			stateRulesByName[rule.ProxyRuleName.ValueString()] = rule
		}
	}

	// Extract plan rules
	if !plan.PostRESPONSE.IsNull() && !plan.PostRESPONSE.IsUnknown() {
		var rules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PostRESPONSE.ElementsAs(ctx, &rules, false))
		for _, rule := range rules {
			planRulesByName[rule.ProxyRuleName.ValueString()] = rule
		}
	}
	if !plan.PreDNS.IsNull() && !plan.PreDNS.IsUnknown() {
		var rules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PreDNS.ElementsAs(ctx, &rules, false))
		for _, rule := range rules {
			planRulesByName[rule.ProxyRuleName.ValueString()] = rule
		}
	}
	if !plan.PreREQUEST.IsNull() && !plan.PreREQUEST.IsUnknown() {
		var rules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PreREQUEST.ElementsAs(ctx, &rules, false))
		for _, rule := range rules {
			planRulesByName[rule.ProxyRuleName.ValueString()] = rule
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Determine which rules to add, update, or delete
	var rulesToCreate []proxyRuleModel
	var rulesToUpdate []proxyRuleModel
	var rulesToDelete []string

	// Check for new or modified rules
	for name, planRule := range planRulesByName {
		if stateRule, exists := stateRulesByName[name]; !exists {
			// New rule - needs to be created
			rulesToCreate = append(rulesToCreate, planRule)
		} else if !ruleModelsEqual(ctx, stateRule, planRule) {
			// Modified rule - needs to be updated
			rulesToUpdate = append(rulesToUpdate, planRule)
		}
	}

	// Check for deleted rules
	for name := range stateRulesByName {
		if _, exists := planRulesByName[name]; !exists {
			rulesToDelete = append(rulesToDelete, name)
		}
	}

	// Delete removed rules
	if len(rulesToDelete) > 0 {
		deleteInput := networkfirewall.DeleteProxyRulesInput{
			ProxyRuleGroupArn: plan.ProxyRuleGroupArn.ValueStringPointer(),
			Rules:             rulesToDelete,
		}

		_, err = conn.DeleteProxyRules(ctx, &deleteInput)
		if err != nil && !errs.IsA[*awstypes.ResourceNotFoundException](err) {
			smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ID.String())
			return
		}

		// Refresh update token after deletion
		currentRules, err = findProxyRulesByGroupARN(ctx, conn, plan.ProxyRuleGroupArn.ValueString())
		if err != nil {
			smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ID.String())
			return
		}
		updateToken = currentRules.UpdateToken
	}

	// Update modified rules
	for _, ruleModel := range rulesToUpdate {
		updateInput := networkfirewall.UpdateProxyRuleInput{
			ProxyRuleGroupArn: plan.ProxyRuleGroupArn.ValueStringPointer(),
			ProxyRuleName:     ruleModel.ProxyRuleName.ValueStringPointer(),
			UpdateToken:       updateToken,
		}

		// Set action if not null
		if !ruleModel.Action.IsNull() && !ruleModel.Action.IsUnknown() {
			updateInput.Action = ruleModel.Action.ValueEnum()
		}

		// Set description if not null
		if !ruleModel.Description.IsNull() && !ruleModel.Description.IsUnknown() {
			updateInput.Description = ruleModel.Description.ValueStringPointer()
		}

		// Handle conditions update by removing all old conditions and adding new ones
		if stateRule, exists := stateRulesByName[ruleModel.ProxyRuleName.ValueString()]; exists {
			// Remove old conditions
			if !stateRule.Conditions.IsNull() && !stateRule.Conditions.IsUnknown() {
				var oldConditions []conditionModel
				smerr.AddEnrich(ctx, &resp.Diagnostics, stateRule.Conditions.ElementsAs(ctx, &oldConditions, false))
				for _, cond := range oldConditions {
					var removeCondition awstypes.ProxyRuleCondition
					smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, cond, &removeCondition))
					updateInput.RemoveConditions = append(updateInput.RemoveConditions, removeCondition)
				}
			}
		}

		// Add new conditions
		if !ruleModel.Conditions.IsNull() && !ruleModel.Conditions.IsUnknown() {
			var newConditions []conditionModel
			smerr.AddEnrich(ctx, &resp.Diagnostics, ruleModel.Conditions.ElementsAs(ctx, &newConditions, false))
			for _, cond := range newConditions {
				var addCondition awstypes.ProxyRuleCondition
				smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, cond, &addCondition))
				updateInput.AddConditions = append(updateInput.AddConditions, addCondition)
			}
		}

		if resp.Diagnostics.HasError() {
			return
		}

		out, err := conn.UpdateProxyRule(ctx, &updateInput)
		if err != nil {
			smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ID.String())
			return
		}

		// Update token for next operation
		updateToken = out.UpdateToken
	}

	// Create new rules
	if len(rulesToCreate) > 0 {
		var rulesByPhase awstypes.CreateProxyRulesByRequestPhase

		// Organize rules to create by phase
		for _, ruleModel := range rulesToCreate {
			var createRule awstypes.CreateProxyRule
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, ruleModel, &createRule))
			if resp.Diagnostics.HasError() {
				return
			}

			// Determine which phase this rule belongs to
			ruleName := ruleModel.ProxyRuleName.ValueString()
			if _, exists := planRulesByName[ruleName]; exists {
				// Check plan to determine phase
				if !plan.PostRESPONSE.IsNull() {
					var postRules []proxyRuleModel
					smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PostRESPONSE.ElementsAs(ctx, &postRules, false))
					for _, r := range postRules {
						if r.ProxyRuleName.ValueString() == ruleName {
							rulesByPhase.PostRESPONSE = append(rulesByPhase.PostRESPONSE, createRule)
							goto nextRule
						}
					}
				}
				if !plan.PreDNS.IsNull() {
					var preDNSRules []proxyRuleModel
					smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PreDNS.ElementsAs(ctx, &preDNSRules, false))
					for _, r := range preDNSRules {
						if r.ProxyRuleName.ValueString() == ruleName {
							rulesByPhase.PreDNS = append(rulesByPhase.PreDNS, createRule)
							goto nextRule
						}
					}
				}
				if !plan.PreREQUEST.IsNull() {
					var preRequestRules []proxyRuleModel
					smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PreREQUEST.ElementsAs(ctx, &preRequestRules, false))
					for _, r := range preRequestRules {
						if r.ProxyRuleName.ValueString() == ruleName {
							rulesByPhase.PreREQUEST = append(rulesByPhase.PreREQUEST, createRule)
							goto nextRule
						}
					}
				}
			}
		nextRule:
		}

		createInput := networkfirewall.CreateProxyRulesInput{
			ProxyRuleGroupArn: plan.ProxyRuleGroupArn.ValueStringPointer(),
			Rules:             &rulesByPhase,
		}

		_, err = conn.CreateProxyRules(ctx, &createInput)
		if err != nil {
			smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ID.String())
			return
		}
	}

	// Read back to get full state
	readOut, err := findProxyRulesByGroupARN(ctx, conn, plan.ProxyRuleGroupArn.ValueString())
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ProxyRuleGroupArn.String())
		return
	}

	smerr.AddEnrich(ctx, &resp.Diagnostics, flattenProxyRules(ctx, readOut, &plan))
	if resp.Diagnostics.HasError() {
		return
	}

	smerr.AddEnrich(ctx, &resp.Diagnostics, resp.State.Set(ctx, &plan))
}

// ruleModelsEqual compares two proxyRuleModel instances to determine if they're equal
func ruleModelsEqual(ctx context.Context, a, b proxyRuleModel) bool {
	// Compare action
	if a.Action.ValueEnum() != b.Action.ValueEnum() {
		return false
	}

	// Compare description
	if a.Description.ValueString() != b.Description.ValueString() {
		return false
	}

	// Compare insert position
	if a.InsertPosition.ValueInt64() != b.InsertPosition.ValueInt64() {
		return false
	}

	// Compare conditions count
	if a.Conditions.IsNull() != b.Conditions.IsNull() {
		return false
	}

	if !a.Conditions.IsNull() {
		var aConditions, bConditions []conditionModel
		a.Conditions.ElementsAs(ctx, &aConditions, false)
		b.Conditions.ElementsAs(ctx, &bConditions, false)

		if len(aConditions) != len(bConditions) {
			return false
		}

		// Compare each condition
		for i := range aConditions {
			if aConditions[i].ConditionKey.ValueString() != bConditions[i].ConditionKey.ValueString() {
				return false
			}
			if aConditions[i].ConditionOperator.ValueString() != bConditions[i].ConditionOperator.ValueString() {
				return false
			}

			var aValues, bValues []types.String
			aConditions[i].ConditionValues.ElementsAs(ctx, &aValues, false)
			bConditions[i].ConditionValues.ElementsAs(ctx, &bValues, false)

			if len(aValues) != len(bValues) {
				return false
			}

			for j := range aValues {
				if aValues[j].ValueString() != bValues[j].ValueString() {
					return false
				}
			}
		}
	}

	return true
}

func (r *resourceProxyRules) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().NetworkFirewallClient(ctx)

	var state resourceProxyRulesModel
	smerr.AddEnrich(ctx, &resp.Diagnostics, req.State.Get(ctx, &state))
	if resp.Diagnostics.HasError() {
		return
	}

	// Get all rule names for this group
	out, err := findProxyRulesByGroupARN(ctx, conn, state.ID.ValueString())
	if err != nil && !tfretry.NotFound(err) {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ID.String())
		return
	}

	if out != nil && out.ProxyRuleGroup != nil && out.ProxyRuleGroup.Rules != nil {
		var ruleNames []string
		rules := out.ProxyRuleGroup.Rules

		// Collect rule names from all phases
		for _, rule := range rules.PostRESPONSE {
			if rule.ProxyRuleName != nil {
				ruleNames = append(ruleNames, *rule.ProxyRuleName)
			}
		}
		for _, rule := range rules.PreDNS {
			if rule.ProxyRuleName != nil {
				ruleNames = append(ruleNames, *rule.ProxyRuleName)
			}
		}
		for _, rule := range rules.PreREQUEST {
			if rule.ProxyRuleName != nil {
				ruleNames = append(ruleNames, *rule.ProxyRuleName)
			}
		}

		if len(ruleNames) > 0 {
			input := networkfirewall.DeleteProxyRulesInput{
				ProxyRuleGroupArn: state.ProxyRuleGroupArn.ValueStringPointer(),
				Rules:             ruleNames,
			}

			_, err = conn.DeleteProxyRules(ctx, &input)
			if err != nil {
				if errs.IsA[*awstypes.ResourceNotFoundException](err) {
					return
				}

				smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ID.String())
				return
			}
		}
	}
}

func (r *resourceProxyRules) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	conn := r.Meta().NetworkFirewallClient(ctx)

	// Parse the composite ID (ProxyRuleGroupArn,RuleName1,RuleName2,...)
	// Minimum 2 parts: ARN and at least one rule name
	parts := strings.Split(req.ID, ",")

	if len(parts) < 2 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected import ID format: 'proxy_rule_group_arn,rule_name1[,rule_name2,...]'. Got: %s", req.ID),
		)
		return
	}

	proxyRuleGroupArn := parts[0]
	ruleNames := parts[1:]

	// Fetch all rules for the group
	out, err := findProxyRulesByGroupARN(ctx, conn, proxyRuleGroupArn)
	if err != nil {
		resp.Diagnostics.AddError(
			"Import Failed",
			fmt.Sprintf("Could not find proxy rule group %s: %s", proxyRuleGroupArn, err.Error()),
		)
		return
	}

	if out.ProxyRuleGroup == nil || out.ProxyRuleGroup.Rules == nil {
		resp.Diagnostics.AddError(
			"Import Failed",
			fmt.Sprintf("Proxy rule group %s has no rules", proxyRuleGroupArn),
		)
		return
	}

	rules := out.ProxyRuleGroup.Rules

	// Create a map to track which rule names we're looking for
	ruleNamesToFind := make(map[string]bool)
	for _, name := range ruleNames {
		ruleNamesToFind[name] = true
	}

	// Collect rules by phase
	var postResponseRules []proxyRuleModel
	var preDNSRules []proxyRuleModel
	var preRequestRules []proxyRuleModel
	var diags diag.Diagnostics

	// Search for rules in PostRESPONSE phase
	for _, rule := range rules.PostRESPONSE {
		if rule.ProxyRuleName != nil && ruleNamesToFind[*rule.ProxyRuleName] {
			var ruleModel proxyRuleModel
			diags.Append(flex.Flatten(ctx, &rule, &ruleModel)...)
			if diags.HasError() {
				resp.Diagnostics.Append(diags...)
				return
			}
			postResponseRules = append(postResponseRules, ruleModel)
			delete(ruleNamesToFind, *rule.ProxyRuleName) // Mark as found
		}
	}

	// Search for rules in PreDNS phase
	for _, rule := range rules.PreDNS {
		if rule.ProxyRuleName != nil && ruleNamesToFind[*rule.ProxyRuleName] {
			var ruleModel proxyRuleModel
			diags.Append(flex.Flatten(ctx, &rule, &ruleModel)...)
			if diags.HasError() {
				resp.Diagnostics.Append(diags...)
				return
			}
			preDNSRules = append(preDNSRules, ruleModel)
			delete(ruleNamesToFind, *rule.ProxyRuleName) // Mark as found
		}
	}

	// Search for rules in PreREQUEST phase
	for _, rule := range rules.PreREQUEST {
		if rule.ProxyRuleName != nil && ruleNamesToFind[*rule.ProxyRuleName] {
			var ruleModel proxyRuleModel
			diags.Append(flex.Flatten(ctx, &rule, &ruleModel)...)
			if diags.HasError() {
				resp.Diagnostics.Append(diags...)
				return
			}
			preRequestRules = append(preRequestRules, ruleModel)
			delete(ruleNamesToFind, *rule.ProxyRuleName) // Mark as found
		}
	}

	// Check if any rules were not found
	if len(ruleNamesToFind) > 0 {
		var notFoundRules []string
		for ruleName := range ruleNamesToFind {
			notFoundRules = append(notFoundRules, ruleName)
		}
		resp.Diagnostics.AddError(
			"Import Failed",
			fmt.Sprintf("The following rules were not found in proxy rule group %s: %v", proxyRuleGroupArn, notFoundRules),
		)
		return
	}

	// Create model with the found rules
	var model resourceProxyRulesModel
	model.ID = types.StringValue(proxyRuleGroupArn)
	model.ProxyRuleGroupArn = fwtypes.ARNValue(proxyRuleGroupArn)

	if out.ProxyRuleGroup.ProxyRuleGroupName != nil {
		model.ProxyRuleGroupName = flex.StringToFramework(ctx, out.ProxyRuleGroup.ProxyRuleGroupName)
	}

	// Set rules for each phase
	if len(postResponseRules) > 0 {
		postList, d := fwtypes.NewListNestedObjectValueOfValueSlice(ctx, postResponseRules)
		diags.Append(d...)
		model.PostRESPONSE = postList
	}

	if len(preDNSRules) > 0 {
		preDNSList, d := fwtypes.NewListNestedObjectValueOfValueSlice(ctx, preDNSRules)
		diags.Append(d...)
		model.PreDNS = preDNSList
	}

	if len(preRequestRules) > 0 {
		preRequestList, d := fwtypes.NewListNestedObjectValueOfValueSlice(ctx, preRequestRules)
		diags.Append(d...)
		model.PreREQUEST = preRequestList
	}

	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func findProxyRulesByGroupARN(ctx context.Context, conn *networkfirewall.Client, groupARN string) (*networkfirewall.DescribeProxyRuleGroupOutput, error) {
	input := networkfirewall.DescribeProxyRuleGroupInput{
		ProxyRuleGroupArn: aws.String(groupARN),
	}

	out, err := conn.DescribeProxyRuleGroup(ctx, &input)
	if err != nil {
		if errs.IsA[*awstypes.ResourceNotFoundException](err) {
			return nil, &tfretry.NotFoundError{
				LastError: err,
			}
		}

		return nil, err
	}

	if out == nil || out.ProxyRuleGroup == nil {
		return nil, &tfretry.NotFoundError{
			Message: "proxy rule group not found",
		}
	}

	return out, nil
}

func flattenProxyRules(ctx context.Context, out *networkfirewall.DescribeProxyRuleGroupOutput, model *resourceProxyRulesModel) diag.Diagnostics {
	var diags diag.Diagnostics

	if out.ProxyRuleGroup == nil || out.ProxyRuleGroup.Rules == nil {
		return diags
	}

	rules := out.ProxyRuleGroup.Rules

	// Process PostRESPONSE rules
	if len(rules.PostRESPONSE) > 0 {
		var postResponseRules []proxyRuleModel
		for _, rule := range rules.PostRESPONSE {
			var ruleModel proxyRuleModel
			diags.Append(flex.Flatten(ctx, &rule, &ruleModel)...)
			if diags.HasError() {
				return diags
			}
			postResponseRules = append(postResponseRules, ruleModel)
		}
		postList, d := fwtypes.NewListNestedObjectValueOfValueSlice(ctx, postResponseRules)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.PostRESPONSE = postList
	}

	// Process PreDNS rules
	if len(rules.PreDNS) > 0 {
		var preDNSRules []proxyRuleModel
		for _, rule := range rules.PreDNS {
			var ruleModel proxyRuleModel
			diags.Append(flex.Flatten(ctx, &rule, &ruleModel)...)
			if diags.HasError() {
				return diags
			}
			preDNSRules = append(preDNSRules, ruleModel)
		}
		preDNSList, d := fwtypes.NewListNestedObjectValueOfValueSlice(ctx, preDNSRules)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.PreDNS = preDNSList
	}

	// Process PreREQUEST rules
	if len(rules.PreREQUEST) > 0 {
		var preRequestRules []proxyRuleModel
		for _, rule := range rules.PreREQUEST {
			var ruleModel proxyRuleModel
			diags.Append(flex.Flatten(ctx, &rule, &ruleModel)...)
			if diags.HasError() {
				return diags
			}
			preRequestRules = append(preRequestRules, ruleModel)
		}
		preRequestList, d := fwtypes.NewListNestedObjectValueOfValueSlice(ctx, preRequestRules)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.PreREQUEST = preRequestList
	}

	if out.ProxyRuleGroup.ProxyRuleGroupName != nil {
		model.ProxyRuleGroupName = flex.StringToFramework(ctx, out.ProxyRuleGroup.ProxyRuleGroupName)
	}

	if out.ProxyRuleGroup.ProxyRuleGroupArn != nil {
		model.ProxyRuleGroupArn = fwtypes.ARNValue(aws.ToString(out.ProxyRuleGroup.ProxyRuleGroupArn))
	}

	return diags
}

type resourceProxyRulesModel struct {
	framework.WithRegionModel
	ID                 types.String                                    `tfsdk:"id"`
	PostRESPONSE       fwtypes.ListNestedObjectValueOf[proxyRuleModel] `tfsdk:"post_response"`
	PreDNS             fwtypes.ListNestedObjectValueOf[proxyRuleModel] `tfsdk:"pre_dns"`
	PreREQUEST         fwtypes.ListNestedObjectValueOf[proxyRuleModel] `tfsdk:"pre_request"`
	ProxyRuleGroupArn  fwtypes.ARN                                     `tfsdk:"proxy_rule_group_arn"`
	ProxyRuleGroupName types.String                                    `tfsdk:"proxy_rule_group_name"`
}

type proxyRuleModel struct {
	Action         fwtypes.StringEnum[awstypes.ProxyRulePhaseAction] `tfsdk:"action"`
	Conditions     fwtypes.ListNestedObjectValueOf[conditionModel]   `tfsdk:"conditions"`
	Description    types.String                                      `tfsdk:"description"`
	InsertPosition types.Int64                                       `tfsdk:"insert_position"`
	ProxyRuleName  types.String                                      `tfsdk:"proxy_rule_name"`
}

type conditionModel struct {
	ConditionKey      types.String                      `tfsdk:"condition_key"`
	ConditionOperator types.String                      `tfsdk:"condition_operator"`
	ConditionValues   fwtypes.ListValueOf[types.String] `tfsdk:"condition_values"`
}
