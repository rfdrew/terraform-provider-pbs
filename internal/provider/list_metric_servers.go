package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// The list resources of the metric servers: pbs_metric_server_influxdb_http
// and pbs_metric_server_influxdb_udp. Servers of both types share one
// namespace, but PBS lists each type on its own,
// GET /config/metrics/{influxdb-http,influxdb-udp}, with Sys.Audit on /
// (src/api2/config/metrics/{influxdbhttp,influxdbudp}.rs), so each list asks
// for its type alone. The HTTP list drops the tokens, as every read does.

// metricServerListDescription describes the list resource of the servers of
// kind; secrets says what the generated configuration cannot know.
func metricServerListDescription(kind sectionKind, resourceType, secrets string) string {
	return "Lists the " + kind.name + " metric servers of a Proxmox Backup Server, for `terraform query`, to import " +
		"them as `" + resourceType + "` resources. InfluxDB HTTP and UDP servers share one namespace, and each type " +
		"has its own list resource.\n\n" + secrets +
		"Needs `" + metricServerReadPrivilege + "`; without it, PBS refuses the list.\n\n" + listRequirementNote
}

// NewInfluxDBHTTPListResource returns the pbs_metric_server_influxdb_http
// list resource.
func NewInfluxDBHTTPListResource() list.ListResource {
	return &importedList{
		newResource:   NewInfluxDBHTTPResource,
		identityOrder: []string{"name"},
		schema: listschema.Schema{
			MarkdownDescription: metricServerListDescription(influxDBHTTPKind, "pbs_metric_server_influxdb_http",
				"The token is write-only and never read: the generated configuration has `token_wo = null # "+
					"sensitive` and `token_wo_version = null`, which plans no change, and the server keeps the token "+
					"PBS has. Fill in both only to set the token with Terraform.\n\n"),
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: listInfluxDBHTTPServers,
	}
}

func listInfluxDBHTTPServers(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	servers, err := data.client.ListInfluxDBHTTPServers(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS InfluxDB HTTP metric servers", apiErrorDetail(data.client, metricServerReadPrivilege, err))
		return nil
	}
	objects := make([]listedObject, 0, len(servers))
	for _, server := range servers {
		objects = append(objects, listedObject{
			identity:    map[string]any{"name": server.Name},
			displayName: displayNameWithComment(server.Name, server.Comment),
		})
	}
	return objects
}

// NewInfluxDBUDPListResource returns the pbs_metric_server_influxdb_udp list
// resource.
func NewInfluxDBUDPListResource() list.ListResource {
	return &importedList{
		newResource:   NewInfluxDBUDPResource,
		identityOrder: []string{"name"},
		schema: listschema.Schema{
			MarkdownDescription: metricServerListDescription(influxDBUDPKind, "pbs_metric_server_influxdb_udp",
				"A UDP server has no secrets: the generated configuration of every one plans no change.\n\n"),
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: listInfluxDBUDPServers,
	}
}

func listInfluxDBUDPServers(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	servers, err := data.client.ListInfluxDBUDPServers(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS InfluxDB UDP metric servers", apiErrorDetail(data.client, metricServerReadPrivilege, err))
		return nil
	}
	objects := make([]listedObject, 0, len(servers))
	for _, server := range servers {
		objects = append(objects, listedObject{
			identity:    map[string]any{"name": server.Name},
			displayName: displayNameWithComment(server.Name, server.Comment),
		})
	}
	return objects
}
