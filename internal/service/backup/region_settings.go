// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package backup

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
)

// @SDKResource("aws_backup_region_settings", name="Region Settings")
// @SingletonIdentity
// @V60SDKv2Fix
// @Testing(existsType="github.com/aws/aws-sdk-go-v2/service/backup;backup.DescribeRegionSettingsOutput")
// @Testing(checkDestroyNoop=true)
// @Testing(preCheck="testAccPreCheck")
// @Testing(generator=false)
func resourceRegionSettings() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceRegionSettingsUpdate,
		UpdateWithoutTimeout: resourceRegionSettingsUpdate,
		ReadWithoutTimeout:   resourceRegionSettingsRead,
		DeleteWithoutTimeout: schema.NoopContext,

		Schema: map[string]*schema.Schema{
			"resource_type_management_preference": {
				Type:     schema.TypeMap,
				Optional: true,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeBool},
			},
			"resource_type_opt_in_preference": {
				Type:     schema.TypeMap,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeBool},
			},
		},
	}
}

func resourceRegionSettingsUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BackupClient(ctx)

	input := &backup.UpdateRegionSettingsInput{}

	if v, ok := d.GetOk("resource_type_management_preference"); ok && len(v.(map[string]any)) > 0 {
		input.ResourceTypeManagementPreference = flex.ExpandBoolValueMap(v.(map[string]any))
	}

	if v, ok := d.GetOk("resource_type_opt_in_preference"); ok && len(v.(map[string]any)) > 0 {
		input.ResourceTypeOptInPreference = flex.ExpandBoolValueMap(v.(map[string]any))
	}

	_, err := conn.UpdateRegionSettings(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "updating Backup Region Settings: %s", err)
	}

	if d.IsNewResource() {
		d.SetId(meta.(*conns.AWSClient).Region(ctx))
	}

	return append(diags, resourceRegionSettingsRead(ctx, d, meta)...)
}

func resourceRegionSettingsRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BackupClient(ctx)

	output, err := findRegionSettings(ctx, conn)

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Backup Region Settings (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Backup Region Settings (%s): %s", d.Id(), err)
	}

	d.Set("resource_type_opt_in_preference", output.ResourceTypeOptInPreference)
	d.Set("resource_type_management_preference", output.ResourceTypeManagementPreference)

	return diags
}

func findRegionSettings(ctx context.Context, conn *backup.Client) (*backup.DescribeRegionSettingsOutput, error) {
	input := &backup.DescribeRegionSettingsInput{}
	output, err := conn.DescribeRegionSettings(ctx, input)

	if err != nil {
		return nil, err
	}

	if output == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output, nil
}
