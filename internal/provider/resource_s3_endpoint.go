package provider

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &s3EndpointResource{}
	_ resource.ResourceWithConfigure      = &s3EndpointResource{}
	_ resource.ResourceWithIdentity       = &s3EndpointResource{}
	_ resource.ResourceWithImportState    = &s3EndpointResource{}
	_ resource.ResourceWithModifyPlan     = &s3EndpointResource{}
	_ resource.ResourceWithValidateConfig = &s3EndpointResource{}
)

// NewS3EndpointResource returns the pbs_s3_endpoint resource.
func NewS3EndpointResource() resource.Resource { return &s3EndpointResource{} }

type s3EndpointResource struct {
	data *providerData
}

type s3EndpointModel struct {
	ID                   types.String     `tfsdk:"id"`
	Endpoint             types.String     `tfsdk:"endpoint"`
	Port                 types.Int64      `tfsdk:"port"`
	Region               types.String     `tfsdk:"region"`
	Fingerprint          fingerprintValue `tfsdk:"fingerprint"`
	AccessKey            types.String     `tfsdk:"access_key"`
	SecretKeyWO          types.String     `tfsdk:"secret_key_wo"`
	SecretKeyWOVersion   types.Int64      `tfsdk:"secret_key_wo_version"`
	PathStyle            types.Bool       `tfsdk:"path_style"`
	ProviderQuirks       types.Set        `tfsdk:"provider_quirks"`
	RateIn               byteSizeValue    `tfsdk:"rate_in"`
	BurstIn              byteSizeValue    `tfsdk:"burst_in"`
	RateOut              byteSizeValue    `tfsdk:"rate_out"`
	BurstOut             byteSizeValue    `tfsdk:"burst_out"`
	LimitActiveRequests  types.Int64      `tfsdk:"limit_active_requests"`
	LimitPassiveRequests types.Int64      `tfsdk:"limit_passive_requests"`
	UseNodeProxy         types.Bool       `tfsdk:"use_node_proxy"`
}

// s3EndpointDeletable are the properties PBS lets an S3 endpoint update
// delete. endpoint and access-key are required, and put-rate-limit, which
// this resource leaves alone, cannot be deleted.
var s3EndpointDeletable = []string{
	"port", "region", "fingerprint", "path-style", "rate-in", "burst-in", "rate-out", "burst-out",
	"limit-active-requests", "limit-passive-requests", "provider-quirks", "use-node-proxy",
}

// S3 provider quirks: features of the S3 API a provider lacks, which PBS
// then works around.
const (
	s3QuirkSkipIfNoneMatch   = "skip-if-none-match-header"
	s3QuirkDeleteObjectsSlow = "delete-objects-via-delete-object"
)

// Privileges the S3 endpoint resources need, for error messages.
const (
	s3EndpointReadPrivilege   = "Sys.Audit on /system/s3-endpoint/<id>"
	s3EndpointModifyPrivilege = "Sys.Modify on /system/s3-endpoint/<id>"
	s3EndpointCreatePrivilege = "Sys.Modify on /system/s3-endpoint"
)

// s3EndpointPrivilege names a privilege on the endpoint, for errors.
func s3EndpointPrivilege(privilege, id string) string {
	return strings.Replace(privilege, "<id>", id, 1)
}

// s3EndpointNamePattern is a host name as PBS takes it for an S3 endpoint:
// DNS labels separated by dots, optionally starting with the label
// {{bucket}}, with {{region}} allowed as any label but the last.
var s3EndpointNamePattern = regexp.MustCompile(`^(\{\{bucket\}\}\.)?(([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?|\{\{region\}\})\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

// s3RegionPattern is a region as PBS takes it: lower-case letters, digits,
// "_" and "-", not starting with "-".
var s3RegionPattern = regexp.MustCompile(`^[_a-z0-9][-_a-z0-9]+$`)

// maxS3RegionLength bounds a region, as PBS does.
const maxS3RegionLength = 32

// s3EndpointValidators check an endpoint: a host name with the templates PBS
// knows, or an IP address.
func s3EndpointValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(1, maxAddressLength),
		stringCheck{
			description: "must be a host name such as s3.example.com — optionally starting with {{bucket}}. and with " +
				"{{region}} as one of its labels but the last — or an IP address, without a scheme, port or path",
			check: func(s string) bool {
				return s3EndpointNamePattern.MatchString(s) || (!strings.Contains(s, "%") && net.ParseIP(s) != nil)
			},
		},
	}
}

// s3KeyValidators check an access key: a single line PBS keeps as given. The
// attribute is sensitive, so its errors leave out the value.
func s3KeyValidators() []validator.String {
	return []validator.String{stringvalidator.LengthAtLeast(1), noControlOrPadding.secret()}
}

func (r *s3EndpointResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_s3_endpoint"
}

func (r *s3EndpointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	secret, secretVersion := writeOnlySecretAttributes("secret_key",
		"Secret key of `access_key`. PBS needs it to create the endpoint, so it is required then; after an "+
			"import, leave it out to keep the secret key PBS has.",
		stringCheck{
			description: "must not be empty, contain control characters, or begin or end with white space",
			check: func(s string) bool {
				return s != "" && noControlOrPadding.check(s)
			},
		}.secret(),
	)

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server S3 endpoint: the connection to an S3-compatible " +
			"object store — Amazon S3, Ceph RGW, MinIO, Backblaze B2, Cloudflare R2 and the like — that datastores " +
			"on S3 keep their backups in. A `pbs_datastore` names it in `backend.client`.\n\n" +
			"PBS contacts nothing when it saves an endpoint: wrong keys, a wrong fingerprint or region show when a " +
			"datastore uses the endpoint, or when the `pbs_s3_buckets` data source lists its buckets.\n\n" +
			"S3 endpoints exist from PBS 4.0. Datastores on S3 were a technology preview until PBS 4.1.9.\n\n" +
			"~> **PBS refuses to delete an endpoint a datastore uses.** Destroy the datastore first. A datastore's " +
			"`backend` cannot change, so a change of `id`, which replaces the endpoint, replaces its datastores " +
			"too.\n\n" +
			"Managing endpoints needs `Sys.Modify` on `/system/s3-endpoint`, or on `/system/s3-endpoint/<id>` for " +
			"an existing one; reading them `Sys.Audit`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Endpoint ID, 3 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`. Datastores name it in `backend.client`. Changing it replaces the " +
					"endpoint.",
				Validators:    safeIDValidators(minSafeIDLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"endpoint": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Host name or IP address of the object store, without a scheme, port or path, " +
					"such as `s3.eu-central-1.amazonaws.com`. PBS replaces `{{bucket}}`, which may only start it, " +
					"with the bucket, and `{{region}}` with `region`: `{{bucket}}.s3.{{region}}.amazonaws.com`, " +
					"say. PBS connects over HTTPS only.",
				Validators: s3EndpointValidators(),
			},
			"port": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Port of the object store; 443, HTTPS's, when left out.",
				Validators:          []validator.Int64{int64validator.Between(1, 65535)},
			},
			"region": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Region of the object store, such as `eu-central-1`, which requests are signed " +
					"for and which replaces `{{region}}` in `endpoint`: 2 to 32 characters, lower-case letters, " +
					"digits, `_` and `-`, not starting with `-`. PBS signs for `us-west-1` when left out.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(2, maxS3RegionLength),
					stringvalidator.RegexMatches(s3RegionPattern, "must be lower-case letters, digits, _ and -, not starting with -"),
				},
			},
			"fingerprint": schema.StringAttribute{
				CustomType: fingerprintType{},
				Optional:   true,
				MarkdownDescription: "SHA-256 fingerprint of the object store's certificate, for a self-signed one: " +
					"64 hexadecimal digits, optionally separated by colons, in either case. PBS then accepts the " +
					"certificate with this fingerprint; a certificate its system's CAs validate it accepts either " +
					"way, so the fingerprint is no pin against those. When left out, PBS accepts only certificates " +
					"its CAs validate. The fingerprint changes with the certificate, so update it when the " +
					"certificate is renewed or replaced.",
				Validators: []validator.String{certFingerprintValidator()},
			},
			"access_key": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				MarkdownDescription: "Access key ID PBS signs its requests with. PBS returns it, so a change made " +
					"outside Terraform shows in the next plan; it is kept in state, marked sensitive.",
				Validators: s3KeyValidators(),
			},
			"secret_key_wo":         secret,
			"secret_key_wo_version": secretVersion,
			"path_style": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether PBS addresses a bucket in the path of its requests, " +
					"`https://<endpoint>/<bucket>/…`, as MinIO and Ceph RGW usually need, rather than in the host " +
					"name, `https://<bucket>.<endpoint>/…`. Defaults to `false`.",
			},
			"provider_quirks": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Features of the S3 API the object store lacks, which PBS then works around: " +
					"`" + s3QuirkSkipIfNoneMatch + "`, for a store that does not understand the `If-None-Match` " +
					"header, and `" + s3QuirkDeleteObjectsSlow + "`, for one without the `DeleteObjects` call, " +
					"which PBS then replaces by one request per object; that one needs PBS 4.1.6 or newer.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(stringvalidator.OneOf(s3QuirkSkipIfNoneMatch, s3QuirkDeleteObjectsSlow)),
				},
			},
			"rate_in": rateAttribute("Rate limit on the data the datastores on this endpoint download from the " +
				"object store together, in bytes per second; no limit when left out. Needs PBS 4.1 or newer."),
			"burst_in": rateAttribute("How many bytes over `rate_in` PBS may download at once, after a quiet period; " +
				"as much as `rate_in` when left out. PBS ignores it without `rate_in`. Needs PBS 4.1 or newer."),
			"rate_out": rateAttribute("Rate limit on the data the datastores on this endpoint upload to the object " +
				"store together, in bytes per second; no limit when left out. Needs PBS 4.1 or newer."),
			"burst_out": rateAttribute("How many bytes over `rate_out` PBS may upload at once, after a quiet period; " +
				"as much as `rate_out` when left out. PBS ignores it without `rate_out`. Needs PBS 4.1 or newer."),
			"limit_active_requests": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many `PUT`, `POST` and `DELETE` requests a second the datastores on this " +
					"endpoint send to the object store together, at most; no limit when left out. Needs PBS 4.2.4 " +
					"or newer, which also deprecated the `put-rate-limit` before it: the provider leaves that " +
					"alone. Before PBS 4.2.7, `limit_passive_requests` replaced this limit when both were set.",
				Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
			"limit_passive_requests": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "How many `GET` and `HEAD` requests a second the datastores on this endpoint " +
					"send to the object store together, at most; no limit when left out. Needs PBS 4.2.4 or newer.",
				Validators: []validator.Int64{int64validator.AtLeast(1)},
			},
			"use_node_proxy": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether PBS connects to the object store through the HTTP proxy of its node " +
					"configuration. Defaults to `false`, a direct connection. `true` needs PBS 4.2.4 or newer; " +
					"from 4.1.7 to 4.2.3, PBS always uses the node's proxy, whatever this says.",
			},
		},
	}
}

func (r *s3EndpointResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"id", "S3 endpoint ID, such as `backblaze`."})
}

func (r *s3EndpointResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig warns about endpoints PBS takes but cannot connect to, or
// not as meant: {{bucket}} together with path_style, which puts the bucket
// into the path as well; a host name without {{bucket}} and without
// path_style, which addresses no bucket at all; and an IPv6 address, which PBS
// writes into its requests without brackets.
func (r *s3EndpointResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config s3EndpointModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Endpoint.IsUnknown() || config.Endpoint.IsNull() {
		return
	}
	endpoint := config.Endpoint.ValueString()
	templated := strings.Contains(endpoint, "{{bucket}}")
	switch {
	case config.PathStyle.IsUnknown():
	case config.PathStyle.ValueBool() && templated:
		resp.Diagnostics.AddAttributeWarning(path.Root("endpoint"), "{{bucket}} with path_style",
			"With path_style = true, PBS puts the bucket into the path of its requests, and with {{bucket}} into the "+
				"host name as well, which is unlikely to be what the object store expects.")
	case !config.PathStyle.ValueBool() && !templated:
		resp.Diagnostics.AddAttributeWarning(path.Root("path_style"), "No bucket in the requests",
			"PBS addresses a bucket either in the host name, where endpoint has {{bucket}}, or in the path, with "+
				"path_style = true. This endpoint has neither, so the requests of a datastore would name no bucket: "+
				"start endpoint with {{bucket}}. or set path_style = true.")
	}
	if ip := net.ParseIP(endpoint); ip != nil && ip.To4() == nil {
		resp.Diagnostics.AddAttributeWarning(path.Root("endpoint"), "IPv6 address",
			"PBS takes an IPv6 address as endpoint, but writes it into its requests without brackets, which is no "+
				"valid address: use a host name.")
	}
}

// ModifyPlan requires the secret key for a create, which PBS cannot do
// without one, and refuses the attributes a server too old for them would.
func (r *s3EndpointResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan s3EndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, value := range map[string]byteSizeValue{
		"rate_in": plan.RateIn, "burst_in": plan.BurstIn, "rate_out": plan.RateOut, "burst_out": plan.BurstOut,
	} {
		r.data.requireRelease(&resp.Diagnostics, path.Root(name), value, pbs41)
	}
	if !plan.ProviderQuirks.IsUnknown() {
		for _, quirk := range sortedStrings(plan.ProviderQuirks.Elements()) {
			if quirk == s3QuirkDeleteObjectsSlow {
				r.data.requireRelease(&resp.Diagnostics, path.Root("provider_quirks"), plan.ProviderQuirks, pbs416)
			}
		}
	}
	r.data.requireRelease(&resp.Diagnostics, path.Root("limit_active_requests"), plan.LimitActiveRequests, pbs424)
	r.data.requireRelease(&resp.Diagnostics, path.Root("limit_passive_requests"), plan.LimitPassiveRequests, pbs424)
	if mayBeTrue(plan.UseNodeProxy) {
		r.data.requireRelease(&resp.Diagnostics, path.Root("use_node_proxy"), plan.UseNodeProxy, pbs424)
	}

	creates := req.State.Raw.IsNull()
	if !creates {
		var state s3EndpointModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		creates = !plan.ID.Equal(state.ID)
	}
	if creates && plan.SecretKeyWOVersion.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("secret_key_wo"), "Missing S3 secret key",
			"PBS creates an S3 endpoint only with the secret key of access_key. Set secret_key_wo, with "+
				"secret_key_wo_version.")
	}
}

// s3EndpointDefaults is the model of an S3 endpoint as PBS creates it when a
// property is left out, the prior state of a create.
var s3EndpointDefaults = s3EndpointModel{
	Port:                 types.Int64Null(),
	Region:               types.StringNull(),
	Fingerprint:          fingerprintOrNull(""),
	PathStyle:            types.BoolValue(false),
	ProviderQuirks:       types.SetNull(types.StringType),
	RateIn:               byteSizeOrNull(""),
	BurstIn:              byteSizeOrNull(""),
	RateOut:              byteSizeOrNull(""),
	BurstOut:             byteSizeOrNull(""),
	LimitActiveRequests:  types.Int64Null(),
	LimitPassiveRequests: types.Int64Null(),
	UseNodeProxy:         types.BoolValue(false),
}

// changes records the properties that differ between prior and m. The
// secret key is not one of them.
func (m *s3EndpointModel) changes(prior s3EndpointModel, c *propertyChanges) {
	c.String("endpoint", m.Endpoint, prior.Endpoint)
	c.Int64("port", m.Port, prior.Port)
	c.String("region", m.Region, prior.Region)
	c.String("fingerprint", pbsFingerprint(m.Fingerprint), pbsFingerprint(prior.Fingerprint))
	c.String("access-key", m.AccessKey, prior.AccessKey)
	c.BoolDefault("path-style", m.PathStyle, prior.PathStyle, false)
	c.StringSet("provider-quirks", m.ProviderQuirks, prior.ProviderQuirks)
	c.String("rate-in", sameSize(m.RateIn, prior.RateIn), prior.RateIn.StringValue)
	c.String("burst-in", sameSize(m.BurstIn, prior.BurstIn), prior.BurstIn.StringValue)
	c.String("rate-out", sameSize(m.RateOut, prior.RateOut), prior.RateOut.StringValue)
	c.String("burst-out", sameSize(m.BurstOut, prior.BurstOut), prior.BurstOut.StringValue)
	c.Int64("limit-active-requests", m.LimitActiveRequests, prior.LimitActiveRequests)
	c.Int64("limit-passive-requests", m.LimitPassiveRequests, prior.LimitPassiveRequests)
	c.BoolDefault("use-node-proxy", m.UseNodeProxy, prior.UseNodeProxy, false)
}

// fromS3Endpoint records an S3 endpoint as PBS reports it. The ID is the one
// it was looked up by. The secret key's version exists only in Terraform and
// keeps its value; the secret key itself is never stored.
func (m *s3EndpointModel) fromS3Endpoint(id string, endpoint pbsclient.S3Endpoint, diags *diag.Diagnostics) {
	m.ID = types.StringValue(id)
	m.Endpoint = types.StringValue(endpoint.Endpoint)
	m.Port = int64OrNull(endpoint.Port)
	m.Region = stringOrNull(endpoint.Region)
	m.Fingerprint = fingerprintOrNull(endpoint.Fingerprint)
	m.AccessKey = types.StringValue(endpoint.AccessKey)
	m.SecretKeyWO = types.StringNull()
	m.PathStyle = boolOr(endpoint.PathStyle, false)
	m.ProviderQuirks = stringSetOrNull(endpoint.ProviderQuirks, diags)
	m.RateIn = byteSizeOrNull(endpoint.RateIn)
	m.BurstIn = byteSizeOrNull(endpoint.BurstIn)
	m.RateOut = byteSizeOrNull(endpoint.RateOut)
	m.BurstOut = byteSizeOrNull(endpoint.BurstOut)
	m.LimitActiveRequests = int64OrNull(endpoint.LimitActiveRequests)
	m.LimitPassiveRequests = int64OrNull(endpoint.LimitPassiveRequests)
	m.UseNodeProxy = boolOr(endpoint.UseNodeProxy, false)
}

func (r *s3EndpointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan s3EndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(s3EndpointDefaults, changes)
	params := changes.Values()
	params.Set("id", id)
	secret, ok := writeOnlySecret(ctx, req.Config, "secret_key", &resp.Diagnostics)
	if !ok {
		resp.Diagnostics.AddAttributeError(path.Root("secret_key_wo"), "Missing S3 secret key",
			"PBS creates an S3 endpoint only with a secret key, but secret_key_wo is not known.")
	}
	params.Set("secret-key", secret)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigS3Endpoints, func() error { return client.CreateS3Endpoint(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS S3 endpoint already exists",
				fmt.Sprintf("PBS already has an S3 endpoint %q. To manage it with Terraform, import it, with an import "+
					"block whose id is %q or with `terraform import`. %s", id, id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS S3 endpoint", apiErrorDetail(client, s3EndpointCreatePrivilege, err))
		return
	}

	// From here on the endpoint exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	endpoint, err := client.GetS3Endpoint(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS S3 endpoint back after creation",
			fmt.Sprintf("PBS created S3 endpoint %q, and it was recorded in state, but reading it back failed, so it "+
				"is marked tainted: the next apply replaces it. %s", id,
				apiErrorDetail(client, s3EndpointPrivilege(s3EndpointReadPrivilege, id), err)))
		return
	}
	plan.fromS3Endpoint(id, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

func (r *s3EndpointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state s3EndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	// Before the lookup, so that a refresh finding the endpoint gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)

	endpoint, err := r.data.client.GetS3Endpoint(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS S3 endpoint",
			apiErrorDetail(r.data.client, s3EndpointPrivilege(s3EndpointReadPrivilege, id), err))
		return
	}
	state.fromS3Endpoint(id, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update sends the properties that changed, and the secret key when its
// version did, in one call.
func (r *s3EndpointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state s3EndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, s3EndpointDeletable...)
	plan.changes(state, changes)
	params := changes.Values()
	if writeOnlyChanged(plan.SecretKeyWOVersion, state.SecretKeyWOVersion) {
		secret, ok := writeOnlySecret(ctx, req.Config, "secret_key", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("secret_key_wo"), "Missing S3 secret key",
				"secret_key_wo_version changed, but secret_key_wo is not known.")
		}
		params.Set("secret-key", secret)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if len(params) > 0 {
		err := client.WithConfigLock(pbsclient.ConfigS3Endpoints, func() error { return client.UpdateS3Endpoint(ctx, id, params) })
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS S3 endpoint",
				apiErrorDetail(client, s3EndpointPrivilege(s3EndpointModifyPrivilege, id), err))
			return
		}
	}

	endpoint, err := client.GetS3Endpoint(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS S3 endpoint back after update",
			fmt.Sprintf("PBS updated S3 endpoint %q, and the change was recorded in state, but reading it back "+
				"failed. %s", id, apiErrorDetail(client, s3EndpointPrivilege(s3EndpointReadPrivilege, id), err)))
		return
	}
	plan.fromS3Endpoint(id, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// Delete deletes the endpoint; one already gone is not an error.
func (r *s3EndpointResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state s3EndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigS3Endpoints, func() error { return client.DeleteS3Endpoint(ctx, id) })
	switch {
	case err == nil || pbsclient.IsNotFound(err):
	case pbsclient.IsS3EndpointInUse(err):
		resp.Diagnostics.AddError("Unable to delete PBS S3 endpoint",
			fmt.Sprintf("A datastore still uses S3 endpoint %q, and PBS deletes no endpoint a datastore uses: "+
				"destroy the datastore first. %s", id, err))
	default:
		resp.Diagnostics.AddError("Unable to delete PBS S3 endpoint",
			apiErrorDetail(client, s3EndpointPrivilege(s3EndpointModifyPrivilege, id), err))
	}
}

// ImportState imports an S3 endpoint by ID, given either as the import id
// or, from Terraform 1.12, as the identity of an import block. Read fills in
// the rest, or drops an endpoint that does not exist, which Terraform
// reports. The secret key cannot be imported: PBS never returns it.
func (r *s3EndpointResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := importedSafeID(ctx, req, resp, "id", "S3 endpoint", "backblaze")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}
