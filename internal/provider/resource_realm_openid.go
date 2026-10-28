package provider

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &openIDRealmResource{}
	_ resource.ResourceWithConfigure   = &openIDRealmResource{}
	_ resource.ResourceWithIdentity    = &openIDRealmResource{}
	_ resource.ResourceWithImportState = &openIDRealmResource{}
	_ resource.ResourceWithModifyPlan  = &openIDRealmResource{}
)

// NewOpenIDRealmResource returns the pbs_realm_openid resource.
func NewOpenIDRealmResource() resource.Resource { return &openIDRealmResource{} }

type openIDRealmResource struct {
	data *providerData
}

type openIDRealmModel struct {
	ID                 types.String `tfsdk:"id"`
	Realm              types.String `tfsdk:"realm"`
	IssuerURL          types.String `tfsdk:"issuer_url"`
	ClientID           types.String `tfsdk:"client_id"`
	ClientKey          types.String `tfsdk:"client_key"`
	ClientKeyWO        types.String `tfsdk:"client_key_wo"`
	ClientKeyWOVersion types.Int64  `tfsdk:"client_key_wo_version"`
	Scopes             types.Set    `tfsdk:"scopes"`
	ACRValues          types.List   `tfsdk:"acr_values"`
	Audiences          types.Set    `tfsdk:"audiences"`
	Prompt             types.String `tfsdk:"prompt"`
	UsernameClaim      types.String `tfsdk:"username_claim"`
	Autocreate         types.Bool   `tfsdk:"autocreate"`
	Default            types.Bool   `tfsdk:"default"`
	Comment            types.String `tfsdk:"comment"`
}

// openIDRealmDeletable are the properties PBS lets an OpenID realm update
// delete. issuer-url and client-id are required, and username-claim cannot
// change at all.
var openIDRealmDeletable = []string{"acr-values", "audiences", "autocreate", "client-key", "comment", "default",
	"prompt", "scopes"}

// Privileges the realm resources need, for error messages.
const (
	realmReadPrivilege   = "Sys.Audit on /access/domains"
	realmModifyPrivilege = "Realm.Allocate on /access/domains"
)

// Lengths PBS allows in an OpenID realm.
const (
	minRealmLength         = 2
	maxUsernameClaimLength = 64
	maxAudienceLength      = 256
)

// openIDListItemPattern is an ACR value or an audience as PBS takes one
// (GENERIC_URI_REGEX), without the commas and semicolons PBS would split it
// at, and without any white space or control character: PBS trims what it
// reads back from its configuration file, and refuses to write control
// characters there.
var openIDListItemPattern = regexp.MustCompile(`^[^\p{Cc}\p{Z}<>#",;]+$`)

// defaultOpenIDScopes are the scopes PBS asks for when a realm sets none,
// pbsclient.DefaultOpenIDScopes as a set.
var defaultOpenIDScopes = types.SetValueMust(types.StringType, []attr.Value{
	types.StringValue("email"), types.StringValue("profile"),
})

// realmValidators check the name of a realm a resource creates: not one of
// the built-in realms, which PBS refuses as existing, so that the plan says
// so already.
func realmValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(minRealmLength, maxSafeIDLength),
		stringvalidator.RegexMatches(realmPattern, "must start with a letter, a digit or an underscore, followed by letters, digits, underscores, dots and hyphens"),
		stringvalidator.NoneOf(pbsclient.RealmTypePAM, pbsclient.RealmTypePBS),
	}
}

// issuerURLValidator accepts an absolute http:// or https:// URL with a
// host, and without credentials, a query, a fragment or white space: an
// OpenID issuer has neither query nor fragment.
func issuerURLValidator() validator.String {
	return stringCheck{
		description: "must be an https:// or http:// URL with a host, and no credentials, query, fragment or white space",
		check: func(s string) bool {
			if strings.ContainsFunc(s, unicode.IsSpace) || strings.ContainsFunc(s, unicode.IsControl) ||
				strings.ContainsAny(s, "?#") {
				return false
			}
			u, err := url.Parse(s)
			return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
		},
	}
}

// clientKeyCheck checks an OpenID client key. PBS trims what it reads back
// from its configuration file, so white space at either end would be lost.
var clientKeyCheck = stringCheck{
	description: "must not be empty, must not contain control characters, and must not begin or end with white space",
	check: func(s string) bool {
		return s != "" && noControlOrPadding.check(s)
	},
}.secret()

func (r *openIDRealmResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_realm_openid"
}

func (r *openIDRealmResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	clientKey, clientKeyVersion := writeOnlySecretAttributes("client_key", "",
		clientKeyCheck,
		stringvalidator.ConflictsWith(path.MatchRoot("client_key")),
	)
	clientKey.MarkdownDescription = "Client secret of a confidential client, instead of `client_key`, with which it " +
		"conflicts. Write-only: Terraform passes it to PBS without storing it in the plan or state. PBS does return " +
		"it, but the provider leaves it out of state, so a change made outside Terraform goes unnoticed. PBS " +
		"receives it when the realm is created and whenever `client_key_wo_version` changes; removing both leaves " +
		"the key PBS has. Requires `client_key_wo_version`, and Terraform or OpenTofu 1.11 or later."

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an OpenID Connect realm of a Proxmox Backup Server: users sign in to PBS " +
			"through an identity provider such as Authentik, Keycloak or Microsoft Entra ID. PBS knows them as " +
			"`<name>@<realm>`, the name being the value of `username_claim`. Only users that exist can sign in — " +
			"create them with `pbs_user`, or let PBS create them at their first sign-in with `autocreate` — and they " +
			"have no privileges until a `pbs_acl` grants them some.\n\n" +
			"PBS contacts nothing when it saves a realm: a wrong issuer URL, client ID or client key shows only when " +
			"someone signs in. The identity provider must accept PBS's address, such as " +
			"`https://pbs.example.com:8007`, as a redirect URI.\n\n" +
			"**The client key** of a confidential client goes either in `client_key`, which Terraform stores in " +
			"state, as sensitive — PBS returns it, so a change made outside Terraform shows in the plan — or in " +
			"`client_key_wo` with `client_key_wo_version`, which keep it out of the plan and state. A realm created " +
			"with neither is a public client, which signs in without a key. Moving from one to the other sends the " +
			"key once. Removing `client_key` deletes the key from PBS; removing `client_key_wo`, or leaving both out " +
			"after an import, keeps the key PBS has. An import reads neither: a configuration with a key sends it " +
			"in the next apply.\n\n" +
			"~> **Only one realm is the default.** `default = true` takes the flag from the realm that had it, the " +
			"built-in `pam` and `pbs` and realms outside Terraform included. Set it on one realm only: two realms " +
			"with `default = true` take it from each other on every apply.\n\n" +
			"Changing `realm` or `username_claim` replaces the realm, which creates it with what the configuration " +
			"holds: a key left to PBS — after an import, or after removing `client_key_wo` — is lost then, and the " +
			"plan warns. PBS keeps the users of a deleted realm, and their ACL entries; after a new " +
			"`username_claim`, users sign in under the names it gives, and users made for the old one no longer " +
			"match.\n\n" +
			"Managing realms needs `Realm.Allocate` on `/access/domains`; reading one `Sys.Audit` there.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `realm`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"realm": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Realm name, 2 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`, and neither `pam` nor `pbs`, the built-in realms. Users of the realm " +
					"are `<name>@<realm>`. Changing it replaces the realm.",
				Validators:    realmValidators(),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"issuer_url": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Issuer of the identity provider, exactly as `issuer` in its discovery " +
					"document, `<issuer_url>/.well-known/openid-configuration`, has it — for Authentik " +
					"`https://authentik.example.com/application/o/<application slug>/`, trailing slash included. An " +
					"`https://` or, for tests, `http://` URL without credentials, query or fragment.",
				Validators: []validator.String{issuerURLValidator()},
			},
			"client_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Client ID of PBS at the identity provider.",
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1), noControlOrPadding},
			},
			"client_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "Client secret of a confidential client, which Terraform stores in state, as " +
					"sensitive. PBS returns it, so a change made outside Terraform shows in the plan. Removing it " +
					"deletes the key from PBS, which then signs in as a public client. Conflicts with `client_key_wo`.",
				Validators: []validator.String{
					clientKeyCheck,
					stringvalidator.ConflictsWith(path.MatchRoot("client_key_wo")),
				},
			},
			"client_key_wo":         clientKey,
			"client_key_wo_version": clientKeyVersion,
			"scopes": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default:     setdefault.StaticValue(defaultOpenIDScopes),
				MarkdownDescription: "Scopes PBS asks the identity provider for, besides `openid`, which it always " +
					"asks for. Defaults to `[\"email\", \"profile\"]`, which have the identity provider include the " +
					"email address and names PBS gives a user it creates. Each is letters, digits, `_`, `.` and `-`, " +
					"not starting with `.` or `-`.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(stringvalidator.RegexMatches(safeIDPattern,
						"must start with a letter, a digit or an underscore, followed by letters, digits, underscores, dots and hyphens")),
				},
			},
			"acr_values": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Authentication context class references PBS asks the identity provider for, " +
					"in order of preference; which it honours is up to the provider. None when left out.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.NoNullValues(),
					listvalidator.UniqueValues(),
					listvalidator.ValueStringsAre(stringvalidator.RegexMatches(openIDListItemPattern,
						"must be non-empty, without white space, control characters or any of <>#\",;")),
				},
			},
			"audiences": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Audiences PBS accepts in ID tokens besides `client_id`, for identity " +
					"providers whose tokens name more than one. When left out, PBS refuses ID tokens with an " +
					"audience other than `client_id`. Each is up to 256 characters. Needs PBS 4.2.1 or newer.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtMost(maxAudienceLength),
						stringvalidator.RegexMatches(openIDListItemPattern,
							"must be non-empty, without white space, control characters or any of <>#\",;"),
					),
				},
			},
			"prompt": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "OpenID `prompt` PBS sends to the identity provider: `login` or `consent` to have " +
					"it ask the user again, `select_account` to let them choose an account, `none` to have it show no " +
					"page at all — signing in then fails without a session there — or another value the provider " +
					"knows. The provider decides when left out.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(safeIDPattern,
						"must start with a letter, a digit or an underscore, followed by letters, digits, underscores, dots and hyphens"),
				},
			},
			"username_claim": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Claim whose value is the user name, `<value>@<realm>`, such as " +
					"`preferred_username`; when left out `sub`, the subject, the only claim the OpenID specification " +
					"guarantees to be unique. Choose one users cannot change themselves. PBS takes it only when it " +
					"creates the realm, so changing it replaces the realm.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, maxUsernameClaimLength),
					stringvalidator.RegexMatches(safeIDPattern,
						"must start with a letter, a digit or an underscore, followed by letters, digits, underscores, dots and hyphens"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"autocreate": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether PBS creates a user who signs in for the first time, with the email " +
					"address and names from their claims, and no privileges. Defaults to `false`: only users that " +
					"exist can sign in.",
			},
			"default": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether the sign-in form preselects this realm. Only one realm is the " +
					"default: `true` takes the flag from the realm that had it. Defaults to `false`.",
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
		},
	}
}

func (r *openIDRealmResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"realm", "Realm name, such as `authentik`."})
}

func (r *openIDRealmResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan refuses audiences on a server older than PBS 4.2.1, and warns
// when a replacement would create the realm without a key the configuration
// leaves to PBS.
func (r *openIDRealmResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan openIDRealmModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.data.requireRelease(&resp.Diagnostics, path.Root("audiences"), plan.Audiences, pbs421)

	if req.State.Raw.IsNull() || !plan.ClientKey.IsNull() || !plan.ClientKeyWOVersion.IsNull() {
		return
	}
	var state openIDRealmModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Realm.Equal(state.Realm) || !plan.UsernameClaim.Equal(state.UsernameClaim) {
		resp.Diagnostics.AddWarning("OpenID realm is replaced without a client key",
			fmt.Sprintf("A new realm or username_claim replaces realm %q, and the configuration has neither client_key "+
				"nor client_key_wo, so PBS creates the realm without a key. If the realm has one now — left to PBS "+
				"after an import, or after removing client_key_wo — it is lost, and a confidential client can no "+
				"longer sign in. Set client_key, or client_key_wo with client_key_wo_version, to keep it.",
				state.Realm.ValueString()))
	}
}

// openIDRealmDefaults is the model of a realm as PBS creates it when a
// property is left out, the prior state of a create.
var openIDRealmDefaults = openIDRealmModel{
	ClientKey:     types.StringNull(),
	Scopes:        defaultOpenIDScopes,
	ACRValues:     types.ListNull(types.StringType),
	Audiences:     types.SetNull(types.StringType),
	Prompt:        types.StringNull(),
	UsernameClaim: types.StringNull(),
	Autocreate:    types.BoolValue(false),
	Default:       types.BoolValue(false),
	Comment:       types.StringNull(),
}

// scopesWithoutDefault maps PBS's default scopes to null, so that resetting
// the scopes deletes them instead of writing the default, and a create does
// not send it.
func scopesWithoutDefault(v types.Set) types.Set {
	if !v.IsUnknown() && v.Equal(defaultOpenIDScopes) {
		return types.SetNull(types.StringType)
	}
	return v
}

// changes records the properties that differ between prior and m. The
// client key is among them only with withClientKey: it is left out when
// client_key_wo sends the key instead.
func (m *openIDRealmModel) changes(prior openIDRealmModel, c *propertyChanges, withClientKey bool) {
	c.String("issuer-url", m.IssuerURL, prior.IssuerURL)
	c.String("client-id", m.ClientID, prior.ClientID)
	if withClientKey {
		c.String("client-key", m.ClientKey, prior.ClientKey)
	}
	c.SpaceSeparated("scopes", scopesWithoutDefault(m.Scopes), scopesWithoutDefault(prior.Scopes))
	c.SpaceSeparated("acr-values", m.ACRValues, prior.ACRValues)
	c.SpaceSeparated("audiences", m.Audiences, prior.Audiences)
	c.String("prompt", m.Prompt, prior.Prompt)
	c.String("username-claim", m.UsernameClaim, prior.UsernameClaim)
	c.BoolDefault("autocreate", m.Autocreate, prior.Autocreate, false)
	c.BoolDefault("default", m.Default, prior.Default, false)
	c.String("comment", m.Comment, prior.Comment)
}

// fromRealm records a realm as PBS reports it. The name is the one it was
// looked up by. The client key is recorded only where m has one: a realm
// whose key is write-only, or left to PBS, keeps it out of state. The
// version of the write-only key exists only in Terraform and keeps its value.
func (m *openIDRealmModel) fromRealm(name string, realm pbsclient.OpenIDRealm, diags *diag.Diagnostics) {
	m.ID = types.StringValue(name)
	m.Realm = types.StringValue(name)
	m.IssuerURL = types.StringValue(realm.IssuerURL)
	m.ClientID = types.StringValue(realm.ClientID)
	if !m.ClientKey.IsNull() {
		m.ClientKey = stringOrNull(realm.ClientKey)
	}
	m.ClientKeyWO = types.StringNull()
	// PBS asks for its default scopes only while the property is absent; an
	// empty list it keeps is none, and the plan then deletes it.
	switch {
	case realm.Scopes == nil:
		m.Scopes = defaultOpenIDScopes
	case len(pbsclient.SplitList(*realm.Scopes)) == 0:
		m.Scopes = types.SetValueMust(types.StringType, []attr.Value{})
	default:
		m.Scopes = stringSetOrNull(uniqueStrings(pbsclient.SplitList(*realm.Scopes)), diags)
	}
	m.ACRValues = stringListOrNull(pbsclient.SplitList(realm.ACRValues), diags)
	m.Audiences = stringSetOrNull(uniqueStrings(pbsclient.SplitList(realm.Audiences)), diags)
	m.Prompt = stringOrNull(realm.Prompt)
	m.UsernameClaim = stringOrNull(realm.UsernameClaim)
	m.Autocreate = boolOr(realm.Autocreate, false)
	m.Default = boolOr(realm.Default, false)
	m.Comment = stringOrNull(realm.Comment)
}

// uniqueStrings returns values sorted and without duplicates, as the
// elements of a set must be.
func uniqueStrings(values []string) []string {
	values = slices.Clone(values)
	slices.Sort(values)
	return slices.Compact(values)
}

// stringListOrNull maps a list PBS answers to a list, the empty list — a
// property PBS leaves out — to null.
func stringListOrNull(values []string, diags *diag.Diagnostics) types.List {
	if len(values) == 0 {
		return types.ListNull(types.StringType)
	}
	elements := make([]attr.Value, len(values))
	for i, v := range values {
		elements[i] = types.StringValue(v)
	}
	list, d := types.ListValue(types.StringType, elements)
	diags.Append(d...)
	return list
}

func (r *openIDRealmResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan openIDRealmModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Realm.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(openIDRealmDefaults, changes, true)
	params := changes.Values()
	params.Set("realm", name)
	if !plan.ClientKeyWOVersion.IsNull() {
		key, ok := writeOnlySecret(ctx, req.Config, "client_key", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("client_key_wo"), "Missing OpenID client key",
				"client_key_wo_version is set, but client_key_wo is not known.")
		}
		params.Set("client-key", key)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// The realm is read back under the same lock, so that no other realm of
	// this provider takes the default flag in between.
	var realm pbsclient.OpenIDRealm
	var readErr error
	err := client.WithConfigLock(pbsclient.ConfigDomains, func() error {
		if err := client.CreateOpenIDRealm(ctx, params); err != nil {
			return err
		}
		realm, _, readErr = client.GetOpenIDRealm(ctx, name)
		return nil
	})
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("realm"), "PBS realm already exists",
				fmt.Sprintf("PBS already has a realm %q; realms of every type share one namespace. If it is an OpenID "+
					"realm, import it to manage it with Terraform, with an import block whose id is %q or with "+
					"`terraform import`; otherwise choose another name. %s", name, name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS OpenID realm", apiErrorDetail(client, realmModifyPrivilege, err))
		return
	}

	// From here on the realm exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	if err := readErr; err != nil {
		plan.ID = types.StringValue(name)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS OpenID realm back after creation",
			fmt.Sprintf("PBS created realm %q, and it was recorded in state, but reading it back failed, so it is "+
				"marked tainted: the next apply replaces it. %s", name, apiErrorDetail(client, realmReadPrivilege, err)))
		return
	}
	plan.fromRealm(name, realm, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
}

func (r *openIDRealmResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state openIDRealmModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Realm.ValueString()
	// Before the lookup, so that a refresh finding the realm gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)

	realm, _, err := r.data.client.GetOpenIDRealm(ctx, name)
	if err != nil {
		switch {
		case pbsclient.IsNotFound(err):
			resp.State.RemoveResource(ctx)
		case pbsclient.IsRealmOfOtherType(err):
			resp.Diagnostics.AddWarning("PBS realm is no OpenID realm",
				fmt.Sprintf("PBS has a realm %q, but not of type openid: it was replaced outside Terraform. It is "+
					"removed from state, and Terraform leaves it alone; creating the OpenID realm again fails while "+
					"it exists. %s", name, err))
			resp.State.RemoveResource(ctx)
		default:
			resp.Diagnostics.AddError("Unable to read PBS OpenID realm", apiErrorDetail(r.data.client, realmReadPrivilege, err))
		}
		return
	}
	state.fromRealm(name, realm, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update sends the properties that changed, and the write-only client key
// when its version did, in one call. PBS clears the default flag of a realm
// on every update that does not set it again, so a default realm's update
// always sends it.
func (r *openIDRealmResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state openIDRealmModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Realm.ValueString()
	client := r.data.client

	sendsKeyWO := writeOnlyChanged(plan.ClientKeyWOVersion, state.ClientKeyWOVersion)
	changes := newPropertyChanges(&resp.Diagnostics, openIDRealmDeletable...)
	plan.changes(state, changes, !sendsKeyWO)
	params := changes.Values()
	if sendsKeyWO {
		key, ok := writeOnlySecret(ctx, req.Config, "client_key", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("client_key_wo"), "Missing OpenID client key",
				"client_key_wo_version changed, but client_key_wo is not known.")
		}
		params.Set("client-key", key)
	}
	if len(params) > 0 && plan.Default.ValueBool() {
		params.Set("default", pbsclient.FormatBool(true))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// As in Create, the realm is read back under the lock of the write.
	var realm pbsclient.OpenIDRealm
	var readErr error
	err := client.WithConfigLock(pbsclient.ConfigDomains, func() error {
		if len(params) > 0 {
			if err := client.UpdateOpenIDRealm(ctx, name, params); err != nil {
				return err
			}
		}
		realm, _, readErr = client.GetOpenIDRealm(ctx, name)
		return nil
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to update PBS OpenID realm", apiErrorDetail(client, realmModifyPrivilege, err))
		return
	}
	if err := readErr; err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS OpenID realm back after update",
			fmt.Sprintf("PBS updated realm %q, and the change was recorded in state, but reading it back failed. %s",
				name, apiErrorDetail(client, realmReadPrivilege, err)))
		return
	}
	plan.fromRealm(name, realm, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
}

// Delete deletes the realm; one already gone is not an error. PBS's delete
// removes a realm of any type, so the realm is read first, and deleted only
// while it is still an OpenID realm — with the digest of that read, so that
// nothing replaces it in between.
func (r *openIDRealmResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state openIDRealmModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Realm.ValueString()
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigDomains, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			_, digest, err := client.GetOpenIDRealm(ctx, name)
			if err != nil {
				return err
			}
			return client.DeleteOpenIDRealm(ctx, name, digest)
		})
	})
	switch {
	case err == nil || pbsclient.IsNotFound(err):
	case pbsclient.IsRealmOfOtherType(err):
		resp.Diagnostics.AddWarning("PBS realm is no OpenID realm",
			fmt.Sprintf("PBS has a realm %q, but not of type openid: it was replaced outside Terraform, so it was not "+
				"deleted. %s", name, err))
	default:
		resp.Diagnostics.AddError("Unable to delete PBS OpenID realm", apiErrorDetail(client, realmModifyPrivilege, err))
	}
}

// ImportState imports an OpenID realm by name, given either as the import id
// or, from Terraform 1.12, as the identity of an import block. Read fills in
// the rest, or drops a realm that does not exist, which Terraform reports.
// The client key is not imported: client_key and client_key_wo_version stay
// null, and a configuration with a key sends it in the next apply.
func (r *openIDRealmResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "realm", "OpenID realm", "authentik")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("realm"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
}
