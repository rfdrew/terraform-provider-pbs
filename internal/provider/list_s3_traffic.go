package provider

import (
	"context"
	"net"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// NewS3EndpointListResource returns the pbs_s3_endpoint list resource.
func NewS3EndpointListResource() list.ListResource {
	return &importedList{
		newResource:   NewS3EndpointResource,
		identityOrder: []string{"id"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the S3 endpoints of a Proxmox Backup Server, for `terraform query`, to import " +
				"them as `pbs_s3_endpoint` resources. S3 endpoints exist from PBS 4.0.\n\n" +
				"~> **The generated configuration needs the access key.** PBS returns it, but it is sensitive, so " +
				"the results leave it out, and `access_key` is required: the generated configuration of an endpoint " +
				"has `access_key = null # sensitive`, and validating it fails with `Missing Configuration for " +
				"Required Attribute` until `access_key` is filled in. The secret key is write-only and never read: " +
				"the generated configuration has `secret_key_wo = null # sensitive` and `secret_key_wo_version = " +
				"null`, and the endpoint keeps the secret key PBS has. PBS needs it only to create the endpoint " +
				"again, when a change of `id` replaces it: the plan fails without both filled in then.\n\n" +
				"PBS lists the endpoints on which the provider's user has `Sys.Audit` on `/system/s3-endpoint/<id>`, " +
				"and leaves out the others without an error.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: listS3Endpoints,
	}
}

// listS3Endpoints names the S3 endpoints PBS shows: those the caller may
// audit (src/api2/config/s3.rs, list_s3_client_config, which anybody may
// call). An endpoint has no comment, so its display name says where it
// points.
func listS3Endpoints(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	endpoints, err := data.client.ListS3Endpoints(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS S3 endpoints", apiErrorDetail(data.client, s3EndpointReadPrivilege, err))
		return nil
	}
	objects := make([]listedObject, 0, len(endpoints))
	for _, endpoint := range endpoints {
		address := endpoint.Endpoint
		if endpoint.Port != nil {
			address = net.JoinHostPort(address, strconv.FormatInt(*endpoint.Port, 10))
		}
		objects = append(objects, listedObject{
			identity:    map[string]any{"id": endpoint.ID},
			displayName: displayNameWithComment(endpoint.ID, address),
		})
	}
	return objects
}

// NewTrafficControlRuleListResource returns the pbs_traffic_control_rule list
// resource.
func NewTrafficControlRuleListResource() list.ListResource {
	return &importedList{
		newResource:   NewTrafficControlRuleResource,
		identityOrder: []string{"name"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the traffic control rules of a Proxmox Backup Server, for `terraform query`, " +
				"to import them as `pbs_traffic_control_rule` resources. A rule has no secrets: the generated " +
				"configuration of every one plans no change.\n\n" +
				"Needs `" + trafficControlReadPrivilege + "`; without it, PBS refuses the list.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: listTrafficControlRules,
	}
}

// listTrafficControlRules names the traffic control rules. PBS's own list of
// them, GET /config/traffic-control, needs Sys.Modify on /, more than
// reading a rule does; the list of their current rates, which the
// pbs_traffic_control_rules data source reads too, needs Sys.Audit on /, as
// reading one (src/api2/config/traffic_control.rs,
// src/api2/admin/traffic_control.rs).
func listTrafficControlRules(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	rules, err := data.client.ListTrafficControlRates(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS traffic control rules", apiErrorDetail(data.client, trafficControlReadPrivilege, err))
		return nil
	}
	objects := make([]listedObject, 0, len(rules))
	for _, rule := range rules {
		objects = append(objects, listedObject{
			identity:    map[string]any{"name": rule.Name},
			displayName: displayNameWithComment(rule.Name, rule.Comment),
		})
	}
	return objects
}
