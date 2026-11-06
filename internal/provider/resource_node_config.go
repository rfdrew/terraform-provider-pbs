package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &nodeConfigResource{}
	_ resource.ResourceWithConfigure   = &nodeConfigResource{}
	_ resource.ResourceWithIdentity    = &nodeConfigResource{}
	_ resource.ResourceWithImportState = &nodeConfigResource{}
	_ resource.ResourceWithModifyPlan  = &nodeConfigResource{}
)

// NewNodeConfigResource returns the pbs_node_config resource.
func NewNodeConfigResource() resource.Resource { return &nodeConfigResource{} }

type nodeConfigResource struct {
	data *providerData
}

// nodeConfigModel is the node's settings. A null attribute is a setting the
// resource does not manage: it is neither read nor changed.
type nodeConfigModel struct {
	ID             types.String `tfsdk:"id"`
	Node           types.String `tfsdk:"node"`
	HTTPProxy      types.String `tfsdk:"http_proxy"`
	EmailFrom      types.String `tfsdk:"email_from"`
	TaskLogMaxDays types.Int64  `tfsdk:"task_log_max_days"`
	DefaultLang    types.String `tfsdk:"default_lang"`
	CiphersTLS12   types.String `tfsdk:"ciphers_tls_1_2"`
	CiphersTLS13   types.String `tfsdk:"ciphers_tls_1_3"`
	ConsentText    types.String `tfsdk:"consent_text"`
	Description    types.String `tfsdk:"description"`
	Location       types.Object `tfsdk:"location"`
}

var nodeLocationTypes = map[string]attr.Type{
	"name":      types.StringType,
	"latitude":  types.Float64Type,
	"longitude": types.Float64Type,
}

// nodeLanguages are the languages of PBS's web interface, the values of
// default-lang.
var nodeLanguages = []string{
	"ar", "ca", "da", "de", "en", "es", "eu", "fa", "fr", "gl", "he", "hu", "it", "ja", "kr", "nb", "nl", "nn",
	"pl", "pt_BR", "ru", "sl", "sv", "tr", "zh_CN", "zh_TW",
}

// maxConsentText is the longest consent text PBS stores: 64 KiB, base64
// encoded.
const maxConsentText = 64 * 1024 / 4 * 3

// maxHTTPProxyLength is the longest HTTP proxy PBS takes.
const maxHTTPProxyLength = 128

// httpProxyPattern is an HTTP proxy as PBS parses it: an optional http
// scheme, optional credentials, a host — a name, an IPv4 address or an IPv6
// one in brackets — and an optional port.
var httpProxyPattern = regexp.MustCompile(`^(http://)?([^\s/@]+@)?([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?/?$`)

// maxTaskLogDays bounds task_log_max_days well below what PBS's seconds
// would overflow at.
const maxTaskLogDays = 1000000

// cipherListValidators check an OpenSSL cipher list as PBS does before it
// asks OpenSSL, and warn about a security level that may keep the proxy
// from loading its certificate.
func cipherListValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthAtLeast(1),
		stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9A-Za-z_:,+!\-@=.]([0-9A-Za-z_:, +!\-@=.]*[0-9A-Za-z_:,+!\-@=.])?$`),
			"must be an OpenSSL cipher list such as ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256, "+
				"without white space at either end"),
		securityLevelWarning{},
	}
}

// securityLevelPattern finds an OpenSSL security level in a cipher list.
var securityLevelPattern = regexp.MustCompile(`@SECLEVEL=([0-9]+)`)

// securityLevelWarning warns about a cipher list that raises OpenSSL's
// security level above its default, 2: the proxy then refuses a certificate
// chain with weaker keys, when it starts, reloads or loads a certificate.
type securityLevelWarning struct{}

func (securityLevelWarning) Description(_ context.Context) string {
	return "warns about @SECLEVEL above 2, which the proxy's certificate chain must meet"
}

func (v securityLevelWarning) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v securityLevelWarning) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	for _, m := range securityLevelPattern.FindAllStringSubmatch(req.ConfigValue.ValueString(), -1) {
		if level, err := strconv.Atoi(m[1]); err == nil && level > 2 {
			resp.Diagnostics.AddAttributeWarning(req.Path, "OpenSSL security level above the default",
				fmt.Sprintf("Attribute %s raises OpenSSL's security level to %d for the proxy's certificate chain too: "+
					"level 3 needs RSA keys of 3072 bits or more and EC keys of 256 bits or more, intermediates "+
					"included, and level 4 refuses even RSA-4096 and P-256. With a chain that falls short, the proxy "+
					"keeps its old certificate when it loads a new one and does not start again — at its next "+
					"restart, reload or package upgrade — until node.cfg is fixed on the host.", req.Path, level))
			return
		}
	}
}

// httpProxyValidators check an HTTP proxy, which may hold a password,
// without showing it.
func httpProxyValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(1, maxHTTPProxyLength),
		noControlOrPadding.secret(),
		stringCheck{
			description: "must be an HTTP proxy such as http://proxy.example.org:3128",
			check:       httpProxyPattern.MatchString,
		}.secret(),
	}
}

func (r *nodeConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node_config"
}

func (r *nodeConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	managed := " Leaving it out leaves the node's setting alone; removing it from the configuration deletes the setting."
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the settings of a Proxmox Backup Server node, which it keeps in `node.cfg`: the HTTP " +
			"proxy, the sender of its mail, how long it keeps task logs, the default language, the TLS ciphers of " +
			"its proxy, the consent banner, its notes and its location. The web interface shows the proxy, the " +
			"sender, the language, the consent text and the location under **Configuration → Other → General**, " +
			"and the notes on the node's **Notes** page; the task logs and the ciphers are set through the API or " +
			"`proxmox-backup-manager node update` only.\n\n" +
			"The node is a singleton, and the resource manages only the settings its configuration sets: one it " +
			"leaves out is neither read nor changed, and keeps whatever the node has. Creating the resource writes " +
			"the settings it sets over the node's; removing a setting from the configuration, or destroying the " +
			"resource, deletes the settings it managed, so that PBS goes back to its defaults for them. The ACME " +
			"settings of the same file belong to `pbs_node_acme`, and this resource never touches them; both " +
			"write with the file's digest, so that neither overwrites the other.\n\n" +
			"Reading the settings needs `" + nodeConfigReadPrivilege + "`, changing them `" +
			nodeConfigModifyPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `node`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": nodeAttribute("settings"),
			"http_proxy": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "HTTP proxy PBS connects through to the internet, `[http://][user:password@]host[:port]`, " +
					"such as `http://proxy.example.org:3128`; without a port, PBS uses 1080. PBS uses it for the " +
					"subscription check, notifications to Gotify and webhooks, and the S3 endpoints and remotes that " +
					"set `use_node_proxy` — from PBS 4.1.7 to 4.2.3, every S3 endpoint, whatever it sets —, and " +
					"writes it to APT's configuration, `/etc/apt/apt.conf.d/76pveproxy` — " +
					"anew whenever the node's settings change, and removing the file when there is no proxy. " +
					"Sensitive, as it may hold a password, which PBS returns." + managed,
				Validators: httpProxyValidators(),
			},
			"email_from": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Address the node's mail comes from: the notifications of sendmail endpoints " +
					"that set no `from_address`, `mail-to-root` included. Without it, PBS sends them from `root`." + managed,
				Validators: textValidators(2, 64),
			},
			"task_log_max_days": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Days PBS keeps the logs of finished tasks, which it rotates every night. Without " +
					"it, PBS keeps the last 20 rotated archives, of about 512 KiB each, however old." + managed,
				Validators: []validator.Int64{int64validator.Between(0, maxTaskLogDays)},
			},
			"default_lang": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Language of the web interface in a browser where no language was chosen in " +
					"the interface — on the login page or with its Language button, which keep the choice in a " +
					"cookie; PBS does not go by the browser's own language. One of `" +
					strings.Join(nodeLanguages, "`, `") + "`; PBS shows English when the language's translation is " +
					"not installed." + managed,
				Validators: []validator.String{stringvalidator.OneOf(nodeLanguages...)},
			},
			"ciphers_tls_1_2": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "OpenSSL cipher list the proxy offers for TLS 1.2, such as " +
					"`ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384`, instead of OpenSSL's defaults for " +
					"Mozilla's intermediate configuration. PBS refuses a list that matches no cipher. The proxy reads " +
					"it only when it starts, reloads (`systemctl reload proxmox-backup-proxy`) or loads a new " +
					"certificate, so a change takes effect then. `@SECLEVEL=N` above 2 applies to the proxy's " +
					"certificate chain too, and a chain with weaker keys then keeps the proxy from starting: the plan " +
					"warns." + managed,
				Validators: cipherListValidators(),
			},
			"ciphers_tls_1_3": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "OpenSSL cipher suites the proxy offers for TLS 1.3, such as " +
					"`TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`. OpenSSL skips names it does not know, " +
					"so check the spelling. Like `ciphers_tls_1_2`, it takes effect when the proxy next starts, " +
					"reloads or loads a certificate." + managed,
				Validators: cipherListValidators(),
			},
			"consent_text": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: fmt.Sprintf("Text of a consent banner that everyone must accept on the login "+
					"page before signing in, in Markdown, up to %d bytes. The provider stores it in PBS "+
					"base64-encoded, as the web interface does.", maxConsentText) + managed,
				Validators: []validator.String{stringvalidator.LengthBetween(1, maxConsentText)},
			},
			"description": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Notes on the node, in Markdown, as the **Notes** page of the web interface " +
					"shows and edits them; lines end in `\\n`, and tabs are allowed, but no other control characters. " +
					"PBS stores each line as a comment line of `node.cfg` and reads the notes back ending in a line " +
					"break, so a line break at the end, or its absence, is no change; the provider sends them with " +
					"one, which older PBS needs for a line with a tab." + managed,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringCheck{
						description: "must not contain control characters other than line breaks (\\n) and tabs",
						check: func(s string) bool {
							return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
						},
					},
				},
			},
			"location": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Where the node is, which PBS shows on a map. PBS 4.2.1 or later." + managed,
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: "Name of the place, such as `Vienna`, without commas: PBS would write " +
							"one into `node.cfg` unquoted, and could not read the file again.",
						Validators: append(textValidators(1, 128), stringCheck{
							description: "must not contain commas",
							check:       func(s string) bool { return !strings.Contains(s, ",") },
						}),
					},
					"latitude": schema.Float64Attribute{
						Required:            true,
						MarkdownDescription: "Latitude in degrees, from -90 to 90.",
						Validators:          []validator.Float64{float64validator.Between(-90, 90)},
					},
					"longitude": schema.Float64Attribute{
						Required:            true,
						MarkdownDescription: "Longitude in degrees, from -180 to 180.",
						Validators:          []validator.Float64{float64validator.Between(-180, 180)},
					},
				},
			},
		},
	}
}

func (r *nodeConfigResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"node", "Node name, such as `localhost`."})
}

func (r *nodeConfigResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *nodeConfigResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planNode(ctx, r.data, req, resp)
	if resp.Diagnostics.HasError() || req.Plan.Raw.IsNull() {
		return
	}
	var location types.Object
	resp.Diagnostics.Append(resp.Plan.GetAttribute(ctx, path.Root("location"), &location)...)
	r.data.requireRelease(&resp.Diagnostics, path.Root("location"), location, pbs421)
}

// nodeSetting is one setting of the node: its property in PBS, how the
// model holds it, and how PBS's value maps to the model's.
type nodeSetting struct {
	property string
	// get returns the setting in m.
	get func(m *nodeConfigModel) attr.Value
	// set records PBS's value in m, keeping the prior value when PBS
	// holds the same in its own form.
	set func(m *nodeConfigModel, s pbsclient.NodeSettings, diags *diag.Diagnostics)
	// pbs returns PBS's value of the setting, "" when unset.
	pbs func(s pbsclient.NodeSettings) string
	// format returns what PBS is sent for the setting in m.
	format func(m *nodeConfigModel) string
}

// nodeSettings are the settings pbs_node_config manages.
var nodeSettings = []nodeSetting{
	stringNodeSetting("http-proxy", func(m *nodeConfigModel) *types.String { return &m.HTTPProxy },
		func(s pbsclient.NodeSettings) string { return s.HTTPProxy }),
	stringNodeSetting("email-from", func(m *nodeConfigModel) *types.String { return &m.EmailFrom },
		func(s pbsclient.NodeSettings) string { return s.EmailFrom }),
	{
		property: "task-log-max-days",
		get:      func(m *nodeConfigModel) attr.Value { return m.TaskLogMaxDays },
		set: func(m *nodeConfigModel, s pbsclient.NodeSettings, _ *diag.Diagnostics) {
			m.TaskLogMaxDays = int64OrNull(s.TaskLogMaxDays)
		},
		pbs: func(s pbsclient.NodeSettings) string {
			if s.TaskLogMaxDays == nil {
				return ""
			}
			return strconv.FormatInt(*s.TaskLogMaxDays, 10)
		},
		format: func(m *nodeConfigModel) string { return strconv.FormatInt(m.TaskLogMaxDays.ValueInt64(), 10) },
	},
	stringNodeSetting("default-lang", func(m *nodeConfigModel) *types.String { return &m.DefaultLang },
		func(s pbsclient.NodeSettings) string { return s.DefaultLang }),
	stringNodeSetting("ciphers-tls-1.2", func(m *nodeConfigModel) *types.String { return &m.CiphersTLS12 },
		func(s pbsclient.NodeSettings) string { return s.CiphersTLS12 }),
	stringNodeSetting("ciphers-tls-1.3", func(m *nodeConfigModel) *types.String { return &m.CiphersTLS13 },
		func(s pbsclient.NodeSettings) string { return s.CiphersTLS13 }),
	{
		property: "consent-text",
		get:      func(m *nodeConfigModel) attr.Value { return m.ConsentText },
		set: func(m *nodeConfigModel, s pbsclient.NodeSettings, diags *diag.Diagnostics) {
			m.ConsentText = decodeConsentText(s.ConsentText, diags)
		},
		pbs: func(s pbsclient.NodeSettings) string { return s.ConsentText },
		format: func(m *nodeConfigModel) string {
			return base64.StdEncoding.EncodeToString([]byte(m.ConsentText.ValueString()))
		},
	},
	{
		property: "description",
		get:      func(m *nodeConfigModel) attr.Value { return m.Description },
		set: func(m *nodeConfigModel, s pbsclient.NodeSettings, _ *diag.Diagnostics) {
			if !m.Description.IsNull() && !m.Description.IsUnknown() && storedDescription(m.Description.ValueString()) == s.Description {
				return
			}
			m.Description = stringOrNull(s.Description)
		},
		pbs: func(s pbsclient.NodeSettings) string { return s.Description },
		// With a line break at the end: PBS built against proxmox-schema
		// before 5.4 refuses notes in which no line is free of control
		// characters, tabs included, and the empty last line is.
		format: func(m *nodeConfigModel) string { return storedDescription(m.Description.ValueString()) },
	},
	{
		property: "location",
		get:      func(m *nodeConfigModel) attr.Value { return m.Location },
		set: func(m *nodeConfigModel, s pbsclient.NodeSettings, diags *diag.Diagnostics) {
			m.Location = nodeLocationObject(m.Location, s.Location, diags)
		},
		pbs:    func(s pbsclient.NodeSettings) string { return s.Location },
		format: func(m *nodeConfigModel) string { return nodeLocationOf(m.Location).Format() },
	},
}

// stringNodeSetting is a setting PBS holds as a plain string.
func stringNodeSetting(property string, field func(m *nodeConfigModel) *types.String, value func(s pbsclient.NodeSettings) string) nodeSetting {
	return nodeSetting{
		property: property,
		get:      func(m *nodeConfigModel) attr.Value { return *field(m) },
		set: func(m *nodeConfigModel, s pbsclient.NodeSettings, _ *diag.Diagnostics) {
			*field(m) = stringOrNull(value(s))
		},
		pbs:    value,
		format: func(m *nodeConfigModel) string { return field(m).ValueString() },
	}
}

// storedDescription is the description as PBS reads it back after writing
// d: each line as a comment line of node.cfg, read back ending in a line
// break. Lines end at "\n" or "\r\n".
func storedDescription(d string) string {
	if d == "" {
		return ""
	}
	lines := strings.Split(strings.TrimSuffix(d, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return strings.Join(lines, "\n") + "\n"
}

// decodeConsentText decodes the consent text PBS stores base64-encoded, as
// UTF-8. A value that is not — written to node.cfg some other way — is
// null, with a warning, so that a plan writes the configured text encoded:
// the login page cannot show it as it is.
func decodeConsentText(stored string, diags *diag.Diagnostics) types.String {
	if stored == "" {
		return types.StringNull()
	}
	decoded, err := base64.StdEncoding.DecodeString(stored)
	if err == nil && !utf8.Valid(decoded) {
		err = errors.New("it does not decode to UTF-8 text")
	}
	if err != nil {
		diags.AddWarning("PBS consent text is not base64",
			"The consent text in node.cfg is not base64-encoded UTF-8, as the web interface writes it, so the "+
				"login page cannot show it: "+err.Error()+". The provider reads it as no text, so that a plan "+
				"writes consent_text encoded.")
		return types.StringNull()
	}
	return types.StringValue(string(decoded))
}

// nodeLocationOf returns the location a known, non-null object holds.
func nodeLocationOf(object types.Object) pbsclient.NodeLocation {
	attributes := object.Attributes()
	location := pbsclient.NodeLocation{}
	if name, ok := attributes["name"].(types.String); ok {
		location.Name = name.ValueString()
	}
	if latitude, ok := attributes["latitude"].(types.Float64); ok {
		location.Latitude = latitude.ValueFloat64()
	}
	if longitude, ok := attributes["longitude"].(types.Float64); ok {
		location.Longitude = longitude.ValueFloat64()
	}
	return location
}

// nodeLocationObject turns the location property PBS holds into the
// attribute, keeping prior when it holds the same location: a number in the
// configuration, such as 48.2, is not exactly the float64 PBS writes back.
func nodeLocationObject(prior types.Object, stored string, diags *diag.Diagnostics) types.Object {
	if stored == "" {
		return types.ObjectNull(nodeLocationTypes)
	}
	location, err := pbsclient.ParseNodeLocation(stored)
	if err != nil {
		diags.AddError("Unexpected PBS node configuration",
			fmt.Sprintf("PBS answered a location property the provider cannot read, %q: %s", stored, err))
		return types.ObjectNull(nodeLocationTypes)
	}
	if !prior.IsNull() && !prior.IsUnknown() && nodeLocationOf(prior) == location {
		return prior
	}
	object, d := types.ObjectValue(nodeLocationTypes, map[string]attr.Value{
		"name":      stringOrNull(location.Name),
		"latitude":  types.Float64Value(location.Latitude),
		"longitude": types.Float64Value(location.Longitude),
	})
	diags.Append(d...)
	return object
}

// managed reports whether the model manages the setting.
func (s nodeSetting) managed(m *nodeConfigModel) bool { return !s.get(m).IsNull() }

// fromNodeSettings records PBS's values of the settings m manages; with all,
// of every setting PBS has, as an import does.
func (m *nodeConfigModel) fromNodeSettings(node string, settings pbsclient.NodeSettings, all bool, diags *diag.Diagnostics) {
	m.ID = types.StringValue(node)
	m.Node = types.StringValue(node)
	for _, s := range nodeSettings {
		if all || s.managed(m) {
			s.set(m, settings, diags)
		}
	}
}

// nodeConfigChanges returns the PUT that makes the node's current settings
// what plan says: the settings plan manages that PBS holds otherwise are
// sent, and those prior managed that plan does not are deleted when PBS has
// them. A nil prior is a create, which deletes nothing.
func nodeConfigChanges(current pbsclient.NodeSettings, plan, prior *nodeConfigModel) url.Values {
	params := url.Values{}
	var deletes []string
	for _, s := range nodeSettings {
		switch {
		case s.managed(plan):
			if want := s.format(plan); !s.same(plan, current, want) {
				params.Set(s.property, want)
			}
		case prior != nil && s.managed(prior) && s.pbs(current) != "":
			deletes = append(deletes, s.property)
		}
	}
	pbsclient.AddDelete(params, deletes...)
	return params
}

// same reports whether PBS's current value of the setting is what plan
// sends, want.
func (s nodeSetting) same(plan *nodeConfigModel, current pbsclient.NodeSettings, want string) bool {
	stored := s.pbs(current)
	switch s.property {
	case "description":
		return stored == storedDescription(want)
	case "consent-text":
		decoded, err := base64.StdEncoding.DecodeString(stored)
		return err == nil && utf8.Valid(decoded) && string(decoded) == plan.ConsentText.ValueString()
	case "location":
		location, err := pbsclient.ParseNodeLocation(stored)
		return err == nil && location == nodeLocationOf(plan.Location)
	}
	return stored == want
}

// write makes the node's settings what plan says, based on what the node
// has now, under the lock of node.cfg and with its digest. prior is nil for
// a create.
func (r *nodeConfigResource) write(ctx context.Context, plan, prior *nodeConfigModel, diags *diag.Diagnostics) {
	client := r.data.client
	node := plan.Node.ValueString()
	err := client.WithConfigLock(pbsclient.ConfigNode, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			current, digest, err := client.GetNodeSettings(ctx, node)
			if err != nil {
				return err
			}
			params := nodeConfigChanges(current, plan, prior)
			if len(params) == 0 {
				return nil
			}
			params.Set(pbsclient.DigestParam, digest)
			return client.UpdateNodeConfig(ctx, node, params)
		})
	})
	if err != nil {
		diags.AddError("Unable to change the settings of the PBS node", apiErrorDetail(client, nodeConfigModifyPrivilege, err))
	}
}

// readBack reads the settings after a write and records them, or the plan
// when reading fails: the write took effect.
func (r *nodeConfigResource) readBack(ctx context.Context, plan nodeConfigModel, state *tfsdk.State, identity *tfsdk.ResourceIdentity, diags *diag.Diagnostics) {
	node := plan.Node.ValueString()
	plan.ID = types.StringValue(node)
	settings, _, err := r.data.client.GetNodeSettings(ctx, node)
	if err != nil {
		diags.AddWarning("Unable to read the settings of the PBS node back",
			fmt.Sprintf("PBS changed the settings of node %s, and they were recorded in state, but reading them "+
				"back failed; the next refresh reads them again. %s", node, apiErrorDetail(r.data.client, nodeConfigReadPrivilege, err)))
	} else {
		plan.fromNodeSettings(node, settings, false, diags)
	}
	diags.Append(state.Set(ctx, &plan)...)
	setIdentity(ctx, identity, "node", node, diags)
}

func (r *nodeConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan nodeConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

func (r *nodeConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state nodeConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := state.Node.ValueString()
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
	settings, _, err := r.data.client.GetNodeSettings(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the settings of the PBS node",
			apiErrorDetail(r.data.client, nodeConfigReadPrivilege, err))
		return
	}
	state.fromNodeSettings(node, settings, false, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *nodeConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior nodeConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &prior, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

// Delete deletes the settings the resource managed, so that PBS goes back to
// its defaults for them, and leaves the node's other settings alone.
func (r *nodeConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state nodeConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Nothing managed: every setting null, as the zero model has them.
	none := nodeConfigModel{Node: state.Node}
	client := r.data.client
	node := state.Node.ValueString()
	err := client.WithConfigLock(pbsclient.ConfigNode, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			current, digest, err := client.GetNodeSettings(ctx, node)
			if err != nil {
				return err
			}
			params := nodeConfigChanges(current, &none, &state)
			if len(params) == 0 {
				return nil
			}
			params.Set(pbsclient.DigestParam, digest)
			return client.UpdateNodeConfig(ctx, node, params)
		})
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete the settings of the PBS node", apiErrorDetail(client, nodeConfigModifyPrivilege, err))
	}
}

// ImportState imports the settings of a node by the node's name, given
// either as the import id or, from Terraform 1.12, as the identity of an
// import block. Every setting the node has becomes managed: a plan then
// shows the ones the configuration leaves out as deleted.
func (r *nodeConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	node, ok := importedNode(ctx, req, resp, "settings")
	if !ok {
		return
	}
	settings, _, err := r.data.client.GetNodeSettings(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the settings of the PBS node",
			apiErrorDetail(r.data.client, nodeConfigReadPrivilege, err))
		return
	}
	var model nodeConfigModel
	model.Location = types.ObjectNull(nodeLocationTypes)
	model.fromNodeSettings(node, settings, true, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
}
