// Copyright IBM Corp. 2014, 2025
// SPDX-License-Identifier: MPL-2.0

package networkfirewall

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	awstypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
// @ArnIdentity("proxy_rule_group_arn",identityDuplicateAttributes="id")
// @ArnFormat("proxy-rule-group/{name}")
func newResourceProxyRules(_ context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceProxyRules{}

	return r, nil
}

const (
	ResNameProxyRules = "Proxy Rules"
)

type resourceProxyRules struct {
	framework.ResourceWithModel[resourceProxyRulesModel]
	framework.WithImportByIdentity
}

func (r *resourceProxyRules) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			names.AttrID: framework.IDAttribute(),
			"proxy_rule_group_arn": schema.StringAttribute{
				CustomType: fwtypes.ARNType,
				Optional:   true,
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

	input := networkfirewall.CreateProxyRulesInput{
		ProxyRuleGroupArn: plan.ProxyRuleGroupArn.ValueStringPointer(),
	}

	// Create the Rules structure organized by phase
	var rulesByPhase awstypes.CreateProxyRulesByRequestPhase

	// Process PostRESPONSE rules
	if !plan.PostRESPONSE.IsNull() && !plan.PostRESPONSE.IsUnknown() {
		var postRules []proxyRuleModel
		smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PostRESPONSE.ElementsAs(ctx, &postRules, false))
		if resp.Diagnostics.HasError() {
			return
		}

		for i, ruleModel := range postRules {
			var rule awstypes.CreateProxyRule
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, ruleModel, &rule))
			if resp.Diagnostics.HasError() {
				return
			}
			// Set InsertPosition based on index
			insertPos := int32(i)
			rule.InsertPosition = &insertPos
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

		for i, ruleModel := range preDNSRules {
			var rule awstypes.CreateProxyRule
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, ruleModel, &rule))
			if resp.Diagnostics.HasError() {
				return
			}
			// Set InsertPosition based on index
			insertPos := int32(i)
			rule.InsertPosition = &insertPos
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

		for i, ruleModel := range preRequestRules {
			var rule awstypes.CreateProxyRule
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, ruleModel, &rule))
			if resp.Diagnostics.HasError() {
				return
			}
			// Set InsertPosition based on index
			insertPos := int32(i)
			rule.InsertPosition = &insertPos
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
	plan.setID()

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

	out, err := findProxyRulesByGroupARN(ctx, conn, state.ProxyRuleGroupArn.ValueString())
	if tfretry.NotFound(err) {
		resp.Diagnostics.Append(fwdiag.NewResourceNotFoundWarningDiagnostic(err))
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ProxyRuleGroupArn.String())
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

	// Get current state to obtain update token and existing rules from AWS
	currentRules, err := findProxyRulesByGroupARN(ctx, conn, state.ProxyRuleGroupArn.ValueString())
	if err != nil && !tfretry.NotFound(err) {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ID.String())
		return
	}

	updateToken := currentRules.UpdateToken

	// Build maps of rules by name for each phase
	stateRulesByName := make(map[string]proxyRuleModel)
	planRulesByName := make(map[string]proxyRuleModel)

	// Extract existing rules from AWS (currentRules) instead of Terraform state
	// This ensures we correctly identify which rules already exist in AWS
	if currentRules != nil && currentRules.ProxyRuleGroup != nil && currentRules.ProxyRuleGroup.Rules != nil {
		rules := currentRules.ProxyRuleGroup.Rules

		for _, rule := range rules.PostRESPONSE {
			var ruleModel proxyRuleModel
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Flatten(ctx, &rule, &ruleModel))
			stateRulesByName[ruleModel.ProxyRuleName.ValueString()] = ruleModel
		}
		for _, rule := range rules.PreDNS {
			var ruleModel proxyRuleModel
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Flatten(ctx, &rule, &ruleModel))
			stateRulesByName[ruleModel.ProxyRuleName.ValueString()] = ruleModel
		}
		for _, rule := range rules.PreREQUEST {
			var ruleModel proxyRuleModel
			smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Flatten(ctx, &rule, &ruleModel))
			stateRulesByName[ruleModel.ProxyRuleName.ValueString()] = ruleModel
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

		// Refresh update token after deletion for subsequent UpdateProxyRule calls
		currentRules, err = findProxyRulesByGroupARN(ctx, conn, plan.ProxyRuleGroupArn.ValueString())
		if err != nil {
			smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ID.String())
			return
		}
		updateToken = currentRules.UpdateToken
	}

	// Update modified rules
	for _, ruleModel := range rulesToUpdate {
		// Refresh the update token before each update to ensure we have the latest
		currentRules, err = findProxyRulesByGroupARN(ctx, conn, plan.ProxyRuleGroupArn.ValueString())
		if err != nil {
			smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ID.String())
			return
		}
		updateToken = currentRules.UpdateToken

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

		// Process each phase separately with proper InsertPosition
		// Process PostRESPONSE rules
		if !plan.PostRESPONSE.IsNull() {
			var postRules []proxyRuleModel
			smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PostRESPONSE.ElementsAs(ctx, &postRules, false))
			for i, r := range postRules {
				if _, exists := planRulesByName[r.ProxyRuleName.ValueString()]; exists {
					// Check if this rule is in the create list
					for _, createRule := range rulesToCreate {
						if createRule.ProxyRuleName.ValueString() == r.ProxyRuleName.ValueString() {
							var rule awstypes.CreateProxyRule
							smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, createRule, &rule))
							if resp.Diagnostics.HasError() {
								return
							}
							// Set InsertPosition based on index
							insertPos := int32(i)
							rule.InsertPosition = &insertPos
							rulesByPhase.PostRESPONSE = append(rulesByPhase.PostRESPONSE, rule)
							break
						}
					}
				}
			}
		}

		// Process PreDNS rules
		if !plan.PreDNS.IsNull() {
			var preDNSRules []proxyRuleModel
			smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PreDNS.ElementsAs(ctx, &preDNSRules, false))
			for i, r := range preDNSRules {
				if _, exists := planRulesByName[r.ProxyRuleName.ValueString()]; exists {
					// Check if this rule is in the create list
					for _, createRule := range rulesToCreate {
						if createRule.ProxyRuleName.ValueString() == r.ProxyRuleName.ValueString() {
							var rule awstypes.CreateProxyRule
							smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, createRule, &rule))
							if resp.Diagnostics.HasError() {
								return
							}
							// Set InsertPosition based on index
							insertPos := int32(i)
							rule.InsertPosition = &insertPos
							rulesByPhase.PreDNS = append(rulesByPhase.PreDNS, rule)
							break
						}
					}
				}
			}
		}

		// Process PreREQUEST rules
		if !plan.PreREQUEST.IsNull() {
			var preRequestRules []proxyRuleModel
			smerr.AddEnrich(ctx, &resp.Diagnostics, plan.PreREQUEST.ElementsAs(ctx, &preRequestRules, false))
			for i, r := range preRequestRules {
				if _, exists := planRulesByName[r.ProxyRuleName.ValueString()]; exists {
					// Check if this rule is in the create list
					for _, createRule := range rulesToCreate {
						if createRule.ProxyRuleName.ValueString() == r.ProxyRuleName.ValueString() {
							var rule awstypes.CreateProxyRule
							smerr.AddEnrich(ctx, &resp.Diagnostics, flex.Expand(ctx, createRule, &rule))
							if resp.Diagnostics.HasError() {
								return
							}
							// Set InsertPosition based on index
							insertPos := int32(i)
							rule.InsertPosition = &insertPos
							rulesByPhase.PreREQUEST = append(rulesByPhase.PreREQUEST, rule)
							break
						}
					}
				}
			}
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

	// Note: InsertPosition is not compared as it's auto-populated and not stored in state

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
	} else {
		model.PostRESPONSE = fwtypes.NewListNestedObjectValueOfNull[proxyRuleModel](ctx)
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
	} else {
		model.PreDNS = fwtypes.NewListNestedObjectValueOfNull[proxyRuleModel](ctx)
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
	} else {
		model.PreREQUEST = fwtypes.NewListNestedObjectValueOfNull[proxyRuleModel](ctx)
	}

	if out.ProxyRuleGroup.ProxyRuleGroupArn != nil {
		model.ProxyRuleGroupArn = fwtypes.ARNValue(aws.ToString(out.ProxyRuleGroup.ProxyRuleGroupArn))
	}

	return diags
}

type resourceProxyRulesModel struct {
	framework.WithRegionModel
	ID                types.String                                    `tfsdk:"id"`
	PostRESPONSE      fwtypes.ListNestedObjectValueOf[proxyRuleModel] `tfsdk:"post_response"`
	PreDNS            fwtypes.ListNestedObjectValueOf[proxyRuleModel] `tfsdk:"pre_dns"`
	PreREQUEST        fwtypes.ListNestedObjectValueOf[proxyRuleModel] `tfsdk:"pre_request"`
	ProxyRuleGroupArn fwtypes.ARN                                     `tfsdk:"proxy_rule_group_arn"`
}

type proxyRuleModel struct {
	Action        fwtypes.StringEnum[awstypes.ProxyRulePhaseAction] `tfsdk:"action"`
	Conditions    fwtypes.ListNestedObjectValueOf[conditionModel]   `tfsdk:"conditions"`
	Description   types.String                                      `tfsdk:"description"`
	ProxyRuleName types.String                                      `tfsdk:"proxy_rule_name"`
}

type conditionModel struct {
	ConditionKey      types.String                      `tfsdk:"condition_key"`
	ConditionOperator types.String                      `tfsdk:"condition_operator"`
	ConditionValues   fwtypes.ListValueOf[types.String] `tfsdk:"condition_values"`
}

func (data *resourceProxyRulesModel) setID() {
	data.ID = data.ProxyRuleGroupArn.StringValue
}
