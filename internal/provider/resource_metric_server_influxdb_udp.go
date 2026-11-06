package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &influxDBUDPResource{}
	_ resource.ResourceWithConfigure   = &influxDBUDPResource{}
	_ resource.ResourceWithIdentity    = &influxDBUDPResource{}
	_ resource.ResourceWithImportState = &influxDBUDPResource{}
)

// NewInfluxDBUDPResource returns the pbs_metric_server_influxdb_udp
// resource.
func NewInfluxDBUDPResource() resource.Resource { return &influxDBUDPResource{} }

type influxDBUDPResource struct {
	data *providerData
}

type influxDBUDPModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	Host    types.String `tfsdk:"host"`
	MTU     types.Int64  `tfsdk:"mtu"`
	Enable  types.Bool   `tfsdk:"enable"`
	Comment types.String `tfsdk:"comment"`
}

// influxDBUDPDeletable are the properties PBS lets an update of an InfluxDB
// UDP server delete. host is required.
var influxDBUDPDeletable = []string{"enable", "mtu", "comment"}

// The MTU of an InfluxDB UDP server. PBS takes any 16-bit number, but fills
// datagrams with up to the MTU less 50 bytes, for the headers, and that size
// wraps around below 50 and is nothing at 50.
const (
	minInfluxDBMTU = 51
	maxInfluxDBMTU = 65535
)

func (r *influxDBUDPResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_metric_server_influxdb_udp"
}

func (r *influxDBUDPResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attributes := metricServerCommonAttributes("resolves the host")
	attributes["host"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "Address of InfluxDB's UDP listener, `<host>:<port>`: a DNS name, an IPv4 address or " +
			"an IPv6 address in brackets, and the port, such as `influxdb.example.com:8089` or " +
			"`[2001:db8::10]:8089`.",
		Validators: []validator.String{metricServerHostPortValidator()},
	}
	attributes["mtu"] = schema.Int64Attribute{
		Optional: true,
		Computed: true,
		Default:  int64default.StaticInt64(pbsclient.DefaultInfluxDBMTU),
		MarkdownDescription: fmt.Sprintf("Largest datagram PBS sends, in bytes, %d to %d: PBS fills datagrams with "+
			"up to this many bytes less 50, for the headers. Defaults to `%d`.", minInfluxDBMTU, maxInfluxDBMTU,
			pbsclient.DefaultInfluxDBMTU),
		Validators: []validator.Int64{int64validator.Between(minInfluxDBMTU, maxInfluxDBMTU)},
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server InfluxDB UDP metric server: an InfluxDB UDP listener " +
			"— InfluxDB 1.x, or Telegraf's `socket_listener` in front of InfluxDB 2 or 3 — that PBS sends its " +
			"metrics to as line protocol every 10 seconds: CPU, memory, network and disk usage of the host, and the " +
			"usage of every datastore. UDP has no acknowledgement: metrics lost on the way go unnoticed.\n\n" +
			"On every create or update that leaves the server enabled, PBS resolves the host and connects a UDP " +
			"socket to it before it saves anything, from its own host: a name the PBS host cannot resolve fails " +
			"the apply. Nothing has to listen for that. Set `enable = false` to save a server whose " +
			"name does not resolve yet.\n\n" +
			"InfluxDB HTTP and UDP metric servers share one namespace: `pbs_metric_server_influxdb_http` cannot " +
			"take this name. Managing metric servers needs `" + metricServerModifyPrivilege + "`, reading them `" +
			metricServerReadPrivilege + "`.",
		Attributes: attributes,
	}
}

func (r *influxDBUDPResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Metric server name, such as `influxdb-udp`."})
}

func (r *influxDBUDPResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// influxDBUDPDefaults is the model of a server as PBS creates it when a
// property is left out, the prior state of a create.
var influxDBUDPDefaults = influxDBUDPModel{
	Host:    types.StringNull(),
	MTU:     types.Int64Value(pbsclient.DefaultInfluxDBMTU),
	Enable:  types.BoolValue(true),
	Comment: types.StringNull(),
}

// changes records the properties that differ between prior and m.
func (m *influxDBUDPModel) changes(prior influxDBUDPModel, c *propertyChanges) {
	c.String("host", m.Host, prior.Host)
	c.Int64Default("mtu", m.MTU, prior.MTU, pbsclient.DefaultInfluxDBMTU)
	c.BoolDefault("enable", m.Enable, prior.Enable, true)
	c.String("comment", m.Comment, prior.Comment)
}

// fromServer records a server as PBS reports it. The name is the one it was
// looked up by.
func (m *influxDBUDPModel) fromServer(name string, s pbsclient.InfluxDBUDPServer) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.Host = types.StringValue(s.Host)
	m.MTU = int64Or(s.MTU, pbsclient.DefaultInfluxDBMTU)
	m.Enable = boolOr(s.Enable, true)
	m.Comment = stringOrNull(s.Comment)
}

func (r *influxDBUDPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan influxDBUDPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(influxDBUDPDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigMetricServers, func() error {
		return client.CreateMetricServer(ctx, pbsclient.MetricServerTypeInfluxDBUDP, params)
	})
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			addMetricServerExistsError(&resp.Diagnostics, influxDBUDPKind, name, err)
			return
		}
		metricServerWriteError(&resp.Diagnostics, client, influxDBUDPKind, "Unable to create PBS InfluxDB UDP metric server",
			plan.Host.ValueString(), false, err)
		return
	}

	// From here on the server exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	server, _, err := client.GetInfluxDBUDPServer(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS InfluxDB UDP metric server back after creation",
			fmt.Sprintf("PBS created InfluxDB UDP metric server %q, and it was recorded in state, but reading it back "+
				"failed, so it is marked tainted: the next apply replaces it. %s", name,
				apiErrorDetail(client, metricServerReadPrivilege, err)))
		return
	}
	plan.fromServer(name, server)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

func (r *influxDBUDPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state influxDBUDPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the server gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	server, _, err := r.data.client.GetInfluxDBUDPServer(ctx, name)
	if err != nil {
		readSectionFailed(ctx, resp, r.data.client, influxDBUDPKind, name, metricServerReadPrivilege, err)
		return
	}
	state.fromServer(name, server)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *influxDBUDPResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state influxDBUDPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, influxDBUDPDeletable...)
	plan.changes(state, changes)
	if resp.Diagnostics.HasError() {
		return
	}
	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigMetricServers, func() error {
			return client.UpdateMetricServer(ctx, pbsclient.MetricServerTypeInfluxDBUDP, name, changes.Values())
		})
		if err != nil {
			metricServerWriteError(&resp.Diagnostics, client, influxDBUDPKind, "Unable to update PBS InfluxDB UDP metric server",
				plan.Host.ValueString(), false, err)
			return
		}
	}

	server, _, err := client.GetInfluxDBUDPServer(ctx, name)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS InfluxDB UDP metric server back after update",
			fmt.Sprintf("PBS updated InfluxDB UDP metric server %q, and the change was recorded in state, but reading "+
				"it back failed. %s", name, apiErrorDetail(client, metricServerReadPrivilege, err)))
		return
	}
	plan.fromServer(name, server)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// Delete deletes the server, only while it is still an InfluxDB UDP server.
func (r *influxDBUDPResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state influxDBUDPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteMetricServer(ctx, r.data.client, influxDBUDPKind, state.Name.ValueString(), &resp.Diagnostics)
}

// ImportState imports a server by name, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops a server that does not exist or is an HTTP server, which
// Terraform reports.
func (r *influxDBUDPResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "InfluxDB UDP metric server", "influxdb-udp")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
