package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &influxDBHTTPResource{}
	_ resource.ResourceWithConfigure   = &influxDBHTTPResource{}
	_ resource.ResourceWithIdentity    = &influxDBHTTPResource{}
	_ resource.ResourceWithImportState = &influxDBHTTPResource{}
)

// NewInfluxDBHTTPResource returns the pbs_metric_server_influxdb_http
// resource.
func NewInfluxDBHTTPResource() resource.Resource { return &influxDBHTTPResource{} }

type influxDBHTTPResource struct {
	data *providerData
}

type influxDBHTTPModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	URL            types.String `tfsdk:"url"`
	Organization   types.String `tfsdk:"organization"`
	Bucket         types.String `tfsdk:"bucket"`
	TokenWO        types.String `tfsdk:"token_wo"`
	TokenWOVersion types.Int64  `tfsdk:"token_wo_version"`
	MaxBodySize    types.Int64  `tfsdk:"max_body_size"`
	VerifyTLS      types.Bool   `tfsdk:"verify_tls"`
	Enable         types.Bool   `tfsdk:"enable"`
	Comment        types.String `tfsdk:"comment"`
}

// influxDBHTTPDeletable are the properties PBS lets an update of an InfluxDB
// HTTP server delete. url is required; the token is deletable, but removing
// token_wo leaves it, as with every write-only secret.
var influxDBHTTPDeletable = []string{"enable", "bucket", "organization", "max-body-size", "verify-tls", "comment"}

// maxInfluxDBNameLength bounds an InfluxDB organization or bucket, as PBS
// does.
const maxInfluxDBNameLength = 32

func (r *influxDBHTTPResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_metric_server_influxdb_http"
}

func (r *influxDBHTTPResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	token, tokenVersion := writeOnlySecretAttributes("token",
		"API token PBS writes the metrics with, sent as `Authorization: Token <token>`: an InfluxDB 2 token with "+
			"write access to `bucket`, or for InfluxDB 1.8, `<user>:<password>`. InfluxDB 2 and 3 take no write "+
			"without one: leave it out only for a server that needs none, such as InfluxDB 1.8 without "+
			"authentication. Removing it, with `token_wo_version`, leaves the token PBS has.",
		stringvalidator.LengthAtLeast(1),
		noControlOrPadding.secret(),
	)

	attributes := metricServerCommonAttributes("checks the URL")
	attributes["url"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "Base URL of the InfluxDB server, such as `https://influxdb.example.com:8086`: " +
			"`http://` or `https://`, the host, an optional port and an optional path, for a reverse proxy that " +
			"serves InfluxDB below one. PBS appends `/health` and `/api/v2/write` to the URL's path, so leave out " +
			"`/api/v2`.",
		Validators: []validator.String{influxDBURLValidator()},
	}
	attributes["organization"] = schema.StringAttribute{
		Optional: true,
		Computed: true,
		Default:  stringdefault.StaticString(pbsclient.DefaultInfluxDBOrganization),
		MarkdownDescription: "InfluxDB organization the bucket belongs to, up to 32 characters; InfluxDB 1.8 " +
			"ignores it. Defaults to `" + pbsclient.DefaultInfluxDBOrganization + "`.",
		Validators: textValidators(1, maxInfluxDBNameLength),
	}
	attributes["bucket"] = schema.StringAttribute{
		Optional: true,
		Computed: true,
		Default:  stringdefault.StaticString(pbsclient.DefaultInfluxDBBucket),
		MarkdownDescription: "InfluxDB bucket PBS writes the metrics to, up to 32 characters; for InfluxDB 1.8, " +
			"`<database>/<retention policy>`, or the database. Defaults to `" + pbsclient.DefaultInfluxDBBucket + "`.",
		Validators: textValidators(1, maxInfluxDBNameLength),
	}
	attributes["token_wo"] = token
	attributes["token_wo_version"] = tokenVersion
	attributes["max_body_size"] = schema.Int64Attribute{
		Optional: true,
		Computed: true,
		Default:  int64default.StaticInt64(pbsclient.DefaultInfluxDBMaxBodySize),
		MarkdownDescription: "Most bytes of metrics PBS sends in one request. Defaults to `" +
			fmt.Sprint(pbsclient.DefaultInfluxDBMaxBodySize) + "`.",
		Validators: []validator.Int64{int64validator.AtLeast(1)},
	}
	attributes["verify_tls"] = schema.BoolAttribute{
		Optional: true,
		Computed: true,
		Default:  booldefault.StaticBool(true),
		MarkdownDescription: "Whether PBS verifies the TLS certificate of an `https://` URL: it must be valid for " +
			"the URL's host and signed by a CA the PBS host trusts, so an internal CA goes into the PBS host's " +
			"trust store. With `false`, PBS accepts any certificate: the connection is encrypted, but whoever " +
			"answers in the server's place gets the token. Defaults to `true`.",
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server InfluxDB HTTP metric server: an InfluxDB server PBS " +
			"sends its metrics to over HTTP or HTTPS, every 10 seconds — CPU, memory, network and disk usage of " +
			"the host, and the usage of every datastore — with InfluxDB 2's write API, which InfluxDB 1.8 and 3 " +
			"serve too.\n\n" +
			"~> **PBS checks the server before it saves anything.** On every create or update that leaves the " +
			"server enabled — even one that changes only `comment` — PBS sends `GET <url>/health` from its own " +
			"host, with the token, and needs a 2xx answer; otherwise the apply fails, with what to check, and " +
			"nothing changes. The PBS host, not the machine running Terraform, must reach the server; PBS does not " +
			"use the node's HTTP proxy for it, and waits as long as the connection takes, so a server that drops " +
			"packets can outlast the provider's `request_timeout`. Set `enable = false` to save a server that is " +
			"not reachable yet.\n\n" +
			"The check proves only that PBS reaches InfluxDB: it writes nothing, so it tests neither `organization` " +
			"and `bucket` nor the token's write access, and InfluxDB 2 and 1.8 answer `/health` without looking at " +
			"the token at all. A server that passes can still refuse every write; PBS logs that only in its " +
			"journal, as `error sending to metric server <name>`.\n\n" +
			"InfluxDB HTTP and UDP metric servers share one namespace: `pbs_metric_server_influxdb_udp` cannot " +
			"take this name. Managing metric servers needs `" + metricServerModifyPrivilege + "`, reading them `" +
			metricServerReadPrivilege + "`.",
		Attributes: attributes,
	}
}

func (r *influxDBHTTPResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Metric server name, such as `influxdb`."})
}

func (r *influxDBHTTPResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// influxDBHTTPDefaults is the model of a server as PBS creates it when a
// property is left out, the prior state of a create.
var influxDBHTTPDefaults = influxDBHTTPModel{
	URL:          types.StringNull(),
	Organization: types.StringValue(pbsclient.DefaultInfluxDBOrganization),
	Bucket:       types.StringValue(pbsclient.DefaultInfluxDBBucket),
	MaxBodySize:  types.Int64Value(pbsclient.DefaultInfluxDBMaxBodySize),
	VerifyTLS:    types.BoolValue(true),
	Enable:       types.BoolValue(true),
	Comment:      types.StringNull(),
}

// changes records the properties that differ between prior and m. The token
// is not one of them.
func (m *influxDBHTTPModel) changes(prior influxDBHTTPModel, c *propertyChanges) {
	c.String("url", m.URL, prior.URL)
	c.StringDefault("organization", m.Organization, prior.Organization, pbsclient.DefaultInfluxDBOrganization)
	c.StringDefault("bucket", m.Bucket, prior.Bucket, pbsclient.DefaultInfluxDBBucket)
	c.Int64Default("max-body-size", m.MaxBodySize, prior.MaxBodySize, pbsclient.DefaultInfluxDBMaxBodySize)
	c.BoolDefault("verify-tls", m.VerifyTLS, prior.VerifyTLS, true)
	c.BoolDefault("enable", m.Enable, prior.Enable, true)
	c.String("comment", m.Comment, prior.Comment)
}

// fromServer records a server as PBS reports it. The name is the one it was
// looked up by. The token's version exists only in Terraform and keeps its
// value; the token itself is never stored.
func (m *influxDBHTTPModel) fromServer(name string, s pbsclient.InfluxDBHTTPServer) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.URL = types.StringValue(s.URL)
	m.Organization = stringOr(s.Organization, pbsclient.DefaultInfluxDBOrganization)
	m.Bucket = stringOr(s.Bucket, pbsclient.DefaultInfluxDBBucket)
	m.TokenWO = types.StringNull()
	m.MaxBodySize = int64Or(s.MaxBodySize, pbsclient.DefaultInfluxDBMaxBodySize)
	m.VerifyTLS = boolOr(s.VerifyTLS, true)
	m.Enable = boolOr(s.Enable, true)
	m.Comment = stringOrNull(s.Comment)
}

func (r *influxDBHTTPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan influxDBHTTPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(influxDBHTTPDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
	if writeOnlyChanged(plan.TokenWOVersion, types.Int64Null()) {
		token, ok := writeOnlySecret(ctx, req.Config, "token", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("token_wo"), "Missing token",
				"token_wo_version is set, but token_wo is not known.")
		}
		params.Set("token", token)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigMetricServers, func() error {
		return client.CreateMetricServer(ctx, pbsclient.MetricServerTypeInfluxDBHTTP, params)
	})
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			addMetricServerExistsError(&resp.Diagnostics, influxDBHTTPKind, name, err)
			return
		}
		metricServerWriteError(&resp.Diagnostics, client, influxDBHTTPKind, "Unable to create PBS InfluxDB HTTP metric server",
			plan.URL.ValueString(), plan.VerifyTLS.ValueBool(), err)
		return
	}

	// From here on the server exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	server, _, err := client.GetInfluxDBHTTPServer(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS InfluxDB HTTP metric server back after creation",
			fmt.Sprintf("PBS created InfluxDB HTTP metric server %q, and it was recorded in state, but reading it back "+
				"failed, so it is marked tainted: the next apply replaces it. %s", name,
				apiErrorDetail(client, metricServerReadPrivilege, err)))
		return
	}
	plan.fromServer(name, server)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

func (r *influxDBHTTPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state influxDBHTTPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the server gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	server, _, err := r.data.client.GetInfluxDBHTTPServer(ctx, name)
	if err != nil {
		readSectionFailed(ctx, resp, r.data.client, influxDBHTTPKind, name, metricServerReadPrivilege, err)
		return
	}
	state.fromServer(name, server)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update sends the properties that changed, and the token when its version
// did, in one call.
func (r *influxDBHTTPResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state influxDBHTTPModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, influxDBHTTPDeletable...)
	plan.changes(state, changes)
	params := changes.Values()
	if writeOnlyChanged(plan.TokenWOVersion, state.TokenWOVersion) {
		token, ok := writeOnlySecret(ctx, req.Config, "token", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("token_wo"), "Missing token",
				"token_wo_version changed, but token_wo is not known.")
		}
		params.Set("token", token)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if len(params) > 0 {
		err := client.WithConfigLock(pbsclient.ConfigMetricServers, func() error {
			return client.UpdateMetricServer(ctx, pbsclient.MetricServerTypeInfluxDBHTTP, name, params)
		})
		if err != nil {
			metricServerWriteError(&resp.Diagnostics, client, influxDBHTTPKind, "Unable to update PBS InfluxDB HTTP metric server",
				plan.URL.ValueString(), plan.VerifyTLS.ValueBool(), err)
			return
		}
	}

	server, _, err := client.GetInfluxDBHTTPServer(ctx, name)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS InfluxDB HTTP metric server back after update",
			fmt.Sprintf("PBS updated InfluxDB HTTP metric server %q, and the change was recorded in state, but reading "+
				"it back failed. %s", name, apiErrorDetail(client, metricServerReadPrivilege, err)))
		return
	}
	plan.fromServer(name, server)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// Delete deletes the server, only while it is still an InfluxDB HTTP server.
func (r *influxDBHTTPResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state influxDBHTTPModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteMetricServer(ctx, r.data.client, influxDBHTTPKind, state.Name.ValueString(), &resp.Diagnostics)
}

// ImportState imports a server by name, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops a server that does not exist or is a UDP server, which
// Terraform reports. The token cannot be imported: PBS never returns it.
func (r *influxDBHTTPResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "InfluxDB HTTP metric server", "influxdb")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
