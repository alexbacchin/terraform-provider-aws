// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package neptune

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	awstypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/hashicorp/aws-sdk-go-base/v2/endpoints"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_neptune_cluster_endpoint", name="Cluster Endpoint")
// @Tags(identifierAttribute="arn")
func resourceClusterEndpoint() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceClusterEndpointCreate,
		ReadWithoutTimeout:   resourceClusterEndpointRead,
		UpdateWithoutTimeout: resourceClusterEndpointUpdate,
		DeleteWithoutTimeout: resourceClusterEndpointDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cluster_endpoint_identifier": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validIdentifier,
			},
			names.AttrClusterIdentifier: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validIdentifier,
			},
			names.AttrEndpoint: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrEndpointType: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice(clusterEndpointType_Values(), false),
			},
			"excluded_members": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"static_members": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
		},
	}
}

func resourceClusterEndpointCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).NeptuneClient(ctx)

	input := &neptune.CreateDBClusterEndpointInput{
		DBClusterEndpointIdentifier: aws.String(d.Get("cluster_endpoint_identifier").(string)),
		DBClusterIdentifier:         aws.String(d.Get(names.AttrClusterIdentifier).(string)),
		EndpointType:                aws.String(d.Get(names.AttrEndpointType).(string)),
		Tags:                        getTagsIn(ctx),
	}

	if v, ok := d.GetOk("excluded_members"); ok && v.(*schema.Set).Len() > 0 {
		input.ExcludedMembers = flex.ExpandStringValueSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("static_members"); ok && v.(*schema.Set).Len() > 0 {
		input.StaticMembers = flex.ExpandStringValueSet(v.(*schema.Set))
	}

	// Tags are currently only supported in AWS Commercial.
	if meta.(*conns.AWSClient).Partition(ctx) != endpoints.AwsPartitionID {
		input.Tags = nil
	}

	output, err := conn.CreateDBClusterEndpoint(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Neptune Cluster Endpoint: %s", err)
	}

	clusterID, clusterEndpointID := aws.ToString(output.DBClusterIdentifier), aws.ToString(output.DBClusterEndpointIdentifier)
	d.SetId(clusterEndpointCreateResourceID(clusterID, clusterEndpointID))

	if _, err = waitClusterEndpointAvailable(ctx, conn, clusterID, clusterEndpointID); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for Neptune Cluster Endpoint (%s) create: %s", d.Id(), err)
	}

	return append(diags, resourceClusterEndpointRead(ctx, d, meta)...)
}

func resourceClusterEndpointRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).NeptuneClient(ctx)

	clusterID, clusterEndpointID, err := clusterEndpointParseResourceID(d.Id())
	if err != nil {
		return sdkdiag.AppendFromErr(diags, err)
	}

	ep, err := findClusterEndpointByTwoPartKey(ctx, conn, clusterID, clusterEndpointID)

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Neptune Cluster Endpoint (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Neptune Cluster Endpoint (%s): %s", d.Id(), err)
	}

	d.Set(names.AttrARN, ep.DBClusterEndpointArn)
	d.Set("cluster_endpoint_identifier", ep.DBClusterEndpointIdentifier)
	d.Set(names.AttrClusterIdentifier, ep.DBClusterIdentifier)
	d.Set(names.AttrEndpoint, ep.Endpoint)
	d.Set(names.AttrEndpointType, ep.CustomEndpointType)
	d.Set("excluded_members", ep.ExcludedMembers)
	d.Set("static_members", ep.StaticMembers)

	return diags
}

func resourceClusterEndpointUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).NeptuneClient(ctx)

	if d.HasChangesExcept(names.AttrTags, names.AttrTagsAll) {
		clusterID, clusterEndpointID, err := clusterEndpointParseResourceID(d.Id())
		if err != nil {
			return sdkdiag.AppendFromErr(diags, err)
		}

		input := &neptune.ModifyDBClusterEndpointInput{
			DBClusterEndpointIdentifier: aws.String(clusterEndpointID),
		}

		if d.HasChange(names.AttrEndpointType) {
			input.EndpointType = aws.String(d.Get(names.AttrEndpointType).(string))
		}

		if d.HasChange("excluded_members") {
			input.ExcludedMembers = flex.ExpandStringValueSet(d.Get("excluded_members").(*schema.Set))
		}

		if d.HasChange("static_members") {
			input.StaticMembers = flex.ExpandStringValueSet(d.Get("static_members").(*schema.Set))
		}

		_, err = conn.ModifyDBClusterEndpoint(ctx, input)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating Neptune Cluster Endpoint (%s): %s", d.Id(), err)
		}

		if _, err = waitClusterEndpointAvailable(ctx, conn, clusterID, clusterEndpointID); err != nil {
			return sdkdiag.AppendErrorf(diags, "waiting for Neptune Cluster Endpoint (%s) update: %s", d.Id(), err)
		}
	}

	return append(diags, resourceClusterEndpointRead(ctx, d, meta)...)
}

func resourceClusterEndpointDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).NeptuneClient(ctx)

	clusterID, clusterEndpointID, err := clusterEndpointParseResourceID(d.Id())
	if err != nil {
		return sdkdiag.AppendFromErr(diags, err)
	}

	_, err = conn.DeleteDBClusterEndpoint(ctx, &neptune.DeleteDBClusterEndpointInput{
		DBClusterEndpointIdentifier: aws.String(clusterEndpointID),
	})

	if errs.IsA[*awstypes.DBClusterNotFoundFault](err) || errs.IsA[*awstypes.DBClusterEndpointNotFoundFault](err) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Neptune Cluster Endpoint (%s): %s", d.Id(), err)
	}

	if _, err = waitClusterEndpointDeleted(ctx, conn, clusterID, clusterEndpointID); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for Neptune Cluster Endpoint (%s) delete: %s", d.Id(), err)
	}

	return diags
}

const clusterEndpointResourceIDSeparator = ":"

func clusterEndpointCreateResourceID(clusterID, clusterEndpointID string) string {
	parts := []string{clusterID, clusterEndpointID}
	id := strings.Join(parts, clusterEndpointResourceIDSeparator)

	return id
}

func clusterEndpointParseResourceID(id string) (string, string, error) {
	parts := strings.Split(id, clusterEndpointResourceIDSeparator)

	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], nil
	}

	return "", "", fmt.Errorf("unexpected format for ID (%[1]s), expected CLUSTER-ID%[2]sCLUSTER-ENDPOINT-ID", id, clusterEndpointResourceIDSeparator)
}

func findClusterEndpointByTwoPartKey(ctx context.Context, conn *neptune.Client, clusterID, clusterEndpointID string) (*awstypes.DBClusterEndpoint, error) {
	input := &neptune.DescribeDBClusterEndpointsInput{
		DBClusterIdentifier:         aws.String(clusterID),
		DBClusterEndpointIdentifier: aws.String(clusterEndpointID),
	}

	return findClusterEndpoint(ctx, conn, input)
}

func findClusterEndpoint(ctx context.Context, conn *neptune.Client, input *neptune.DescribeDBClusterEndpointsInput) (*awstypes.DBClusterEndpoint, error) {
	output, err := findClusterEndpoints(ctx, conn, input)

	if err != nil {
		return nil, err
	}

	return tfresource.AssertSingleValueResult(output)
}

func findClusterEndpoints(ctx context.Context, conn *neptune.Client, input *neptune.DescribeDBClusterEndpointsInput) ([]awstypes.DBClusterEndpoint, error) {
	var output []awstypes.DBClusterEndpoint

	pages := neptune.NewDescribeDBClusterEndpointsPaginator(conn, input)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)

		if errs.IsA[*awstypes.DBClusterNotFoundFault](err) || errs.IsA[*awstypes.DBClusterEndpointNotFoundFault](err) {
			return nil, &retry.NotFoundError{
				LastError:   err,
				LastRequest: input,
			}
		}

		if err != nil {
			return nil, err
		}

		output = append(output, page.DBClusterEndpoints...)
	}

	return output, nil
}

func statusClusterEndpoint(ctx context.Context, conn *neptune.Client, clusterID, clusterEndpointID string) retry.StateRefreshFunc {
	return func() (any, string, error) {
		output, err := findClusterEndpointByTwoPartKey(ctx, conn, clusterID, clusterEndpointID)

		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return output, aws.ToString(output.Status), nil
	}
}

func waitClusterEndpointAvailable(ctx context.Context, conn *neptune.Client, clusterID, clusterEndpointID string) (*awstypes.DBClusterEndpoint, error) { //nolint:unparam
	const (
		timeout = 10 * time.Minute
	)
	stateConf := &retry.StateChangeConf{
		Pending: []string{clusterEndpointStatusCreating, clusterEndpointStatusModifying},
		Target:  []string{clusterEndpointStatusAvailable},
		Refresh: statusClusterEndpoint(ctx, conn, clusterID, clusterEndpointID),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*awstypes.DBClusterEndpoint); ok {
		return output, err
	}

	return nil, err
}

func waitClusterEndpointDeleted(ctx context.Context, conn *neptune.Client, clusterID, clusterEndpointID string) (*awstypes.DBClusterEndpoint, error) {
	const (
		timeout = 10 * time.Minute
	)
	stateConf := &retry.StateChangeConf{
		Pending: []string{clusterEndpointStatusDeleting},
		Target:  []string{},
		Refresh: statusClusterEndpoint(ctx, conn, clusterID, clusterEndpointID),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*awstypes.DBClusterEndpoint); ok {
		return output, err
	}

	return nil, err
}
