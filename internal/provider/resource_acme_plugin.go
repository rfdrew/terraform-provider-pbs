package provider

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &acmePluginResource{}
	_ resource.ResourceWithConfigure      = &acmePluginResource{}
	_ resource.ResourceWithIdentity       = &acmePluginResource{}
	_ resource.ResourceWithImportState    = &acmePluginResource{}
	_ resource.ResourceWithModifyPlan     = &acmePluginResource{}
	_ resource.ResourceWithValidateConfig = &acmePluginResource{}
)

// NewACMEPluginResource returns the pbs_acme_plugin resource.
func NewACMEPluginResource() resource.Resource { return &acmePluginResource{} }

type acmePluginResource struct {
	data *providerData
}

type acmePluginModel struct {
	ID              types.String `tfsdk:"id"`
	Type            types.String `tfsdk:"type"`
	API             types.String `tfsdk:"api"`
	Data            types.Map    `tfsdk:"data"`
	ValidationDelay types.Int64  `tfsdk:"validation_delay"`
	Disable         types.Bool   `tfsdk:"disable"`
}

// acmePluginDeletable are the properties PBS lets a plugin update delete.
var acmePluginDeletable = []string{"disable", "validation-delay"}

// defaultValidationDelay is how many seconds PBS waits after a DNS plugin set
// its record before it has the CA validate, when the plugin does not say.
const defaultValidationDelay = 30

// maxValidationDelay is the longest validation delay PBS accepts: two days.
const maxValidationDelay = 2 * 24 * 60 * 60

// acmeDNSAPIPattern is the name of an acme.sh DNS API, such as cf.
var acmeDNSAPIPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// acmePluginSettingPattern is the name of a DNS plugin setting: the name of
// an environment variable, such as CF_Token.
var acmePluginSettingPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (r *acmePluginResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_plugin"
}

func (r *acmePluginResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server ACME challenge plugin: how PBS proves to the CA that " +
			"it controls a domain of the node's ACME settings (`pbs_node_acme`).\n\n" +
			"A **DNS plugin** solves the DNS-01 challenge: it sets a TXT record through a DNS provider's API, one " +
			"of the [acme.sh DNS APIs](https://github.com/acmesh-official/acme.sh/wiki/dnsapi) PBS ships, such " +
			"as `cf` for Cloudflare, with the settings in `data`. PBS needs no inbound connection, so this works " +
			"for a server the internet cannot reach. For Cloudflare, create an API token with the permission " +
			"`Zone` → `DNS` → `Edit` on the zone alone, and set `CF_Token` and `CF_Zone_ID`; without " +
			"`CF_Zone_ID`, acme.sh looks the zone up, which needs `Zone` → `Zone` → `Read` too.\n\n" +
			"**The built-in `standalone` plugin** solves the HTTP-01 challenge instead: PBS answers the CA on " +
			"port 80 itself. A domain without a plugin uses it. It always exists and has no settings: it cannot " +
			"be created, only imported, and destroying the resource leaves it as it is.\n\n" +
			"PBS returns the settings when it is read, so they are in state — `data` is sensitive — and a change " +
			"made outside Terraform shows as a difference. Managing plugins needs `" + certificatesPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Plugin ID, up to 32 characters: letters, digits, `_`, `.` and `-`, not starting " +
					"with `.` or `-`; `" + pbsclient.StandaloneACMEPlugin + "` for the built-in plugin, which must " +
					"be imported. Domains name their plugin by it. Changing it replaces the plugin.",
				Validators:    safeIDValidators(1),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"type": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Plugin type: `" + pbsclient.DNSACMEPluginType + "`, or `" +
					pbsclient.StandaloneACMEPlugin + "` for the built-in plugin.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"api": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The acme.sh DNS API the plugin uses, such as `cf` for Cloudflare: the name of " +
					"its `dns_<api>.sh` script without `dns_`. Required for a DNS plugin; `GET " +
					"/config/acme/challenge-schema` lists them, with their settings.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					stringvalidator.RegexMatches(acmeDNSAPIPattern, "must be the name of an acme.sh DNS API, such as cf"),
				},
			},
			"data": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Sensitive:   true,
				MarkdownDescription: "Settings of the DNS API, the environment variables its acme.sh script reads, " +
					"such as `{ CF_Token = var.cloudflare_token, CF_Zone_ID = var.cloudflare_zone_id }`. Required " +
					"for a DNS plugin. PBS hands them to the script as `NAME=value` lines, which it splits at white " +
					"space, so a value must not contain any; quotes are kept as they are. Sensitive, and stored in " +
					"state.",
				Validators: []validator.Map{
					mapvalidator.SizeAtLeast(1),
					mapvalidator.NoNullValues(),
					mapvalidator.KeysAre(
						stringvalidator.LengthBetween(1, 128),
						stringvalidator.RegexMatches(acmePluginSettingPattern, "must be the name of an environment variable, such as CF_Token"),
					),
					mapvalidator.ValueStringsAre(stringCheck{
						description: "must not contain white space or control characters, which the plugin script would cut the value at",
						check: func(s string) bool {
							return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
						},
						hideValue: true,
					}),
				},
			},
			"validation_delay": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(defaultValidationDelay),
				MarkdownDescription: fmt.Sprintf("Seconds PBS waits after setting the TXT record before it asks the "+
					"CA to validate, for the record to reach every DNS server of the zone: 0 to %d. Defaults to %d.",
					maxValidationDelay, defaultValidationDelay),
				Validators: []validator.Int64{int64validator.Between(0, maxValidationDelay)},
			},
			"disable": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether the plugin is marked disabled. Defaults to `false`. PBS 4.2 stores the " +
					"flag but does not check it when it orders a certificate: a disabled plugin still validates the " +
					"domains that name it.",
			},
		},
	}
}

func (r *acmePluginResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"id", "Plugin ID, such as `cloudflare` or `standalone`."})
}

func (r *acmePluginResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig requires api and data of a DNS plugin, and nothing of the
// built-in standalone plugin, which has no settings PBS lets anyone change.
func (r *acmePluginResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config acmePluginModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.ID.IsUnknown() {
		return
	}
	if config.ID.ValueString() == pbsclient.StandaloneACMEPlugin {
		for _, a := range []struct {
			name    string
			value   interface{ IsNull() bool }
			changed bool
		}{
			{"api", config.API, true},
			{"data", config.Data, true},
			{"validation_delay", config.ValidationDelay, !config.ValidationDelay.IsUnknown() && config.ValidationDelay.ValueInt64() != defaultValidationDelay},
			{"disable", config.Disable, !config.Disable.IsUnknown() && config.Disable.ValueBool()},
		} {
			if !a.value.IsNull() && a.changed {
				resp.Diagnostics.AddAttributeError(path.Root(a.name), "Setting of the built-in standalone plugin",
					"The built-in "+pbsclient.StandaloneACMEPlugin+" plugin has no "+a.name+" PBS lets anyone change. "+
						"Leave it out.")
			}
		}
		return
	}
	for _, a := range []struct {
		name  string
		value interface{ IsNull() bool }
	}{{"api", config.API}, {"data", config.Data}} {
		if a.value.IsNull() {
			resp.Diagnostics.AddAttributeError(path.Root(a.name), "Missing setting of a DNS plugin",
				"A DNS plugin needs "+a.name+": the acme.sh DNS API, such as cf, and its settings, such as CF_Token.")
		}
	}
}

// ModifyPlan refuses to create the built-in standalone plugin, which exists
// already: it must be imported.
func (r *acmePluginResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan acmePluginModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.ID.ValueString() == pbsclient.StandaloneACMEPlugin && req.State.Raw.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "The standalone plugin must be imported",
			"PBS's built-in "+pbsclient.StandaloneACMEPlugin+" plugin always exists, so it cannot be created. Import "+
				"it to manage it with Terraform, with an import block whose id is \""+pbsclient.StandaloneACMEPlugin+
				"\" or with `terraform import` — or leave it out: domains without a plugin use it anyway.")
		return
	}
	if req.State.Raw.IsNull() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("type"), pbsclient.DNSACMEPluginType)...)
	}
}

// pluginSettings returns the settings in a known data map.
func pluginSettings(data types.Map, diags *diag.Diagnostics) map[string]string {
	settings := map[string]string{}
	if data.IsNull() || data.IsUnknown() {
		return settings
	}
	diags.Append(data.ElementsAs(context.Background(), &settings, false)...)
	return settings
}

// changes records the properties that differ between prior and m. data is
// sent whole whenever a setting differs.
func (m *acmePluginModel) changes(prior acmePluginModel, c *propertyChanges, diags *diag.Diagnostics) map[string]string {
	c.String("api", m.API, prior.API)
	settings := pluginSettings(m.Data, diags)
	if !maps.Equal(settings, pluginSettings(prior.Data, diags)) || (prior.Data.IsNull() && !m.Data.IsNull()) {
		c.String("data", types.StringValue(pbsclient.EncodeACMEPluginData(settings)), types.StringNull())
	}
	c.Int64Default("validation-delay", m.ValidationDelay, prior.ValidationDelay, defaultValidationDelay)
	c.BoolDefault("disable", m.Disable, prior.Disable, false)
	return settings
}

// fromACMEPlugin records a plugin as PBS reports it. The ID is the one it
// was looked up by.
func (m *acmePluginModel) fromACMEPlugin(id string, plugin pbsclient.ACMEPlugin, diags *diag.Diagnostics) {
	m.ID = types.StringValue(id)
	m.Type = stringOrNull(plugin.Type)
	m.API = stringOrNull(plugin.API)
	if plugin.Type == pbsclient.StandaloneACMEPlugin {
		m.Data = types.MapNull(types.StringType)
	} else {
		data, d := types.MapValueFrom(context.Background(), types.StringType, pbsclient.ParseACMEPluginData(plugin.Data))
		diags.Append(d...)
		m.Data = data
	}
	m.ValidationDelay = int64Or(plugin.ValidationDelay, defaultValidationDelay)
	m.Disable = boolOr(plugin.Disable, false)
}

func (r *acmePluginResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan acmePluginModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	settings := plan.changes(acmePluginModel{
		API:             types.StringNull(),
		Data:            types.MapNull(types.StringType),
		ValidationDelay: types.Int64Value(defaultValidationDelay),
		Disable:         types.BoolValue(false),
	}, changes, &resp.Diagnostics)
	params := changes.Values()
	params.Set("id", id)
	params.Set("type", pbsclient.DNSACMEPluginType)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigACMEPlugins, func() error { return client.CreateACMEPlugin(ctx, params, settings) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("id"), "PBS ACME plugin already exists",
				fmt.Sprintf("PBS already has an ACME plugin %q. Import it to manage it with Terraform, with an import "+
					"block whose id is %q or with `terraform import`, or choose another ID. %s", id, id, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS ACME plugin", apiErrorDetail(client, certificatesPrivilege, err))
		return
	}

	plugin, _, err := client.GetACMEPlugin(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS ACME plugin back after creation",
			fmt.Sprintf("PBS created ACME plugin %q, and it was recorded in state, but reading it back failed, so it "+
				"is marked tainted: the next apply replaces it. %s", id, apiErrorDetail(client, certificatesPrivilege, err)))
		return
	}
	plan.fromACMEPlugin(id, plugin, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

func (r *acmePluginResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state acmePluginModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)

	plugin, _, err := r.data.client.GetACMEPlugin(ctx, id)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS ACME plugin", apiErrorDetail(r.data.client, certificatesPrivilege, err))
		return
	}
	state.fromACMEPlugin(id, plugin, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *acmePluginResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state acmePluginModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, acmePluginDeletable...)
	settings := plan.changes(state, changes, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !changes.Empty() {
		// Under the lock, a digest conflict means someone outside this
		// provider wrote plugins.cfg: read the digest again and retry.
		err := client.WithConfigLock(pbsclient.ConfigACMEPlugins, func() error {
			return client.RetryOnDigestConflict(ctx, func() error {
				_, digest, err := client.GetACMEPlugin(ctx, id)
				if err != nil {
					return err
				}
				params := changes.Values()
				params.Set(pbsclient.DigestParam, digest)
				return client.UpdateACMEPlugin(ctx, id, params, settings)
			})
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS ACME plugin", apiErrorDetail(client, certificatesPrivilege, err))
			return
		}
	}

	plugin, _, err := client.GetACMEPlugin(ctx, id)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS ACME plugin back after update",
			fmt.Sprintf("PBS updated ACME plugin %q, and the change was recorded in state, but reading it back failed. %s",
				id, apiErrorDetail(client, certificatesPrivilege, err)))
		return
	}
	plan.fromACMEPlugin(id, plugin, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}

// Delete deletes the plugin. The built-in standalone plugin stays: PBS
// keeps it whatever happens.
func (r *acmePluginResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state acmePluginModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	if id == pbsclient.StandaloneACMEPlugin {
		return
	}
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigACMEPlugins, func() error { return client.DeleteACMEPlugin(ctx, id) })
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS ACME plugin", apiErrorDetail(client, certificatesPrivilege, err))
	}
}

// ImportState imports a plugin, the built-in standalone one included, by ID,
// given either as the import id or, from Terraform 1.12, as the identity of
// an import block. Read fills in the rest, or drops a plugin that does not
// exist, which Terraform reports.
func (r *acmePluginResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := importedSafeID(ctx, req, resp, "id", "ACME plugin", "cloudflare")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	setIdentity(ctx, resp.Identity, "id", id, &resp.Diagnostics)
}
