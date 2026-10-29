package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// pbs_realm_ldap and pbs_realm_ad are one implementation: an Active
// Directory realm is an LDAP realm that looks users up by sAMAccountName
// instead of a user_attr, and can find its base_dn itself. What PBS does with
// them is in internal/pbsclient/realms.go; most notably, it connects to the
// server on every create and update, and refuses to save what does not
// connect.

var (
	_ resource.Resource                = &directoryRealmResource{}
	_ resource.ResourceWithConfigure   = &directoryRealmResource{}
	_ resource.ResourceWithIdentity    = &directoryRealmResource{}
	_ resource.ResourceWithImportState = &directoryRealmResource{}
	_ resource.ResourceWithModifyPlan  = &directoryRealmResource{}
)

// NewLDAPRealmResource returns the pbs_realm_ldap resource.
func NewLDAPRealmResource() resource.Resource { return &directoryRealmResource{kind: ldapRealmKind} }

// NewADRealmResource returns the pbs_realm_ad resource.
func NewADRealmResource() resource.Resource { return &directoryRealmResource{kind: adRealmKind} }

type directoryRealmResource struct {
	data *providerData
	kind realmKind
}

// ad reports whether the resource is pbs_realm_ad.
func (r *directoryRealmResource) ad() bool { return r.kind == adRealmKind }

// directoryRealmModel holds the attributes LDAP and Active Directory realms
// share.
type directoryRealmModel struct {
	ID                types.String `tfsdk:"id"`
	Realm             types.String `tfsdk:"realm"`
	Server1           types.String `tfsdk:"server1"`
	Server2           types.String `tfsdk:"server2"`
	Port              types.Int64  `tfsdk:"port"`
	Mode              types.String `tfsdk:"mode"`
	Verify            types.Bool   `tfsdk:"verify"`
	CAPath            types.String `tfsdk:"capath"`
	BaseDN            types.String `tfsdk:"base_dn"`
	BindDN            types.String `tfsdk:"bind_dn"`
	PasswordWO        types.String `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64  `tfsdk:"password_wo_version"`
	Filter            types.String `tfsdk:"filter"`
	UserClasses       types.Set    `tfsdk:"user_classes"`
	SyncAttributes    types.Object `tfsdk:"sync_attributes"`
	SyncDefaults      types.Object `tfsdk:"sync_defaults"`
	Default           types.Bool   `tfsdk:"default"`
	Comment           types.String `tfsdk:"comment"`
}

type ldapRealmModel struct {
	directoryRealmModel
	UserAttr types.String `tfsdk:"user_attr"`
}

type adRealmModel struct {
	directoryRealmModel
}

// directoryModel is the model of either resource.
type directoryModel interface {
	directory() *directoryRealmModel
	// changes records the properties that differ between prior, of the same
	// kind, and the model.
	changes(prior directoryModel, c *propertyChanges)
	// fromRealm records a realm as PBS reports it.
	fromRealm(name string, realm pbsclient.DirectoryRealm, diags *diag.Diagnostics)
}

func (m *ldapRealmModel) directory() *directoryRealmModel { return &m.directoryRealmModel }
func (m *adRealmModel) directory() *directoryRealmModel   { return &m.directoryRealmModel }

func (m *ldapRealmModel) changes(prior directoryModel, c *propertyChanges) {
	m.directoryRealmModel.changes(*prior.directory(), c)
	c.String("user-attr", m.UserAttr, prior.(*ldapRealmModel).UserAttr)
}

func (m *adRealmModel) changes(prior directoryModel, c *propertyChanges) {
	m.directoryRealmModel.changes(*prior.directory(), c)
}

func (m *ldapRealmModel) fromRealm(name string, realm pbsclient.DirectoryRealm, diags *diag.Diagnostics) {
	m.directoryRealmModel.fromRealm(name, realm, diags)
	m.UserAttr = types.StringValue(realm.UserAttr)
}

func (m *adRealmModel) fromRealm(name string, realm pbsclient.DirectoryRealm, diags *diag.Diagnostics) {
	m.directoryRealmModel.fromRealm(name, realm, diags)
}

// newModel returns an empty model of the resource's kind.
func (r *directoryRealmResource) newModel() directoryModel {
	if r.ad() {
		return &adRealmModel{}
	}
	return &ldapRealmModel{}
}

// defaults returns the model of a realm as PBS creates it when a property is
// left out, the prior state of a create.
func (r *directoryRealmResource) defaults() directoryModel {
	d := directoryRealmModel{
		Server2:        types.StringNull(),
		Port:           types.Int64Null(),
		Mode:           types.StringValue(pbsclient.DefaultLDAPMode),
		Verify:         types.BoolValue(false),
		CAPath:         types.StringNull(),
		BaseDN:         types.StringNull(),
		BindDN:         types.StringNull(),
		Filter:         types.StringNull(),
		UserClasses:    defaultUserClasses,
		SyncAttributes: types.ObjectNull(syncAttributesFormat.attributeTypes()),
		SyncDefaults:   types.ObjectNull(syncDefaultsFormat.attributeTypes()),
		Default:        types.BoolValue(false),
		Comment:        types.StringNull(),
	}
	if r.ad() {
		return &adRealmModel{directoryRealmModel: d}
	}
	return &ldapRealmModel{directoryRealmModel: d, UserAttr: types.StringNull()}
}

// directoryRealmDeletable are the properties PBS lets an LDAP or Active
// Directory realm update delete. password is among them, but the provider
// leaves the bind password alone when password_wo goes.
var directoryRealmDeletable = []string{"bind-dn", "comment", "default", "filter", "mode", "port", "server2",
	"sync-attributes", "sync-defaults-options", "user-classes", "verify"}

// defaultUserClasses are the object classes a sync considers users when a
// realm sets none, pbsclient.DefaultUserClasses as a set.
var defaultUserClasses = types.SetValueMust(types.StringType, []attr.Value{
	types.StringValue("inetorgperson"), types.StringValue("posixaccount"), types.StringValue("person"),
	types.StringValue("user"),
})

// syncAttributesFormat is a realm's sync-attributes: which LDAP attribute a
// sync takes each property of a user from.
var syncAttributesFormat = propertyStringFormat{keys: []propertyStringKey{
	{attribute: "email", key: "email", typ: types.StringType},
	{attribute: "firstname", key: "firstname", typ: types.StringType},
	{attribute: "lastname", key: "lastname", typ: types.StringType},
}}

// syncDefaultsFormat is a realm's sync-defaults-options: what a sync does
// unless told otherwise.
var syncDefaultsFormat = propertyStringFormat{keys: []propertyStringKey{
	{attribute: "enable_new", key: "enable-new", typ: types.BoolType},
	{attribute: "remove_vanished", key: "remove-vanished", typ: propertyStringListType},
}}

// ldapServerPattern is a server as PBS puts it into an LDAP URL,
// ldap://<server>:<port>: a host name or IPv4 address, or an IPv6 address in
// square brackets.
var ldapServerPattern = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?)$`)

// ldapAttributePattern is the name of an LDAP attribute or object class, as
// RFC 4512 has it: a name starting with a letter, or a numeric OID.
var ldapAttributePattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)+)$`)

// ldapAttributeValidator checks the name of an LDAP attribute or object class.
func ldapAttributeValidator() validator.String {
	return stringvalidator.RegexMatches(ldapAttributePattern,
		"must be an LDAP attribute name — a letter, followed by letters, digits and hyphens — or a numeric OID")
}

// ldapFilterCheck accepts what PBS can put into a search filter verbatim:
// one filter in parentheses, on one line.
var ldapFilterCheck = stringCheck{
	description: "must be an LDAP search filter in parentheses, such as (memberOf=cn=pbs,ou=groups,dc=example,dc=com), on one line",
	check: func(s string) bool {
		return strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && !strings.ContainsFunc(s, unicode.IsControl)
	},
}

// caPathCheck accepts an absolute path on the PBS host.
var caPathCheck = stringCheck{
	description: "must be an absolute path on the PBS host, without control characters or white space at either end",
	check: func(s string) bool {
		return strings.HasPrefix(s, "/") && noControlOrPadding.check(s)
	},
}

func (r *directoryRealmResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_realm_" + r.kind.typ
}

func (r *directoryRealmResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	password, passwordVersion := writeOnlySecretAttributes("password", "Password of `bind_dn`, which it requires.",
		stringvalidator.LengthAtLeast(1),
		stringvalidator.AlsoRequires(path.MatchRoot("bind_dn")),
	)
	password.MarkdownDescription += " PBS needs it to create a realm with a `bind_dn`; removing it, with " +
		"`password_wo_version`, keeps the password PBS has."

	attributes := map[string]schema.Attribute{
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
		"server1": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "Server PBS connects to: a host name or IPv4 address, or an IPv6 address in " +
				"square brackets, without a port.",
			Validators: []validator.String{ldapServerValidator()},
		},
		"server2": schema.StringAttribute{
			Optional: true,
			MarkdownDescription: "Server PBS connects to when `server1` does not answer, in the same form. None " +
				"when left out.",
			Validators: []validator.String{ldapServerValidator()},
		},
		"port": schema.Int64Attribute{
			Optional: true,
			MarkdownDescription: "Port of both servers, 1 to 65535. When left out, 636 with `mode = \"ldaps\"` " +
				"and 389 otherwise.",
			Validators: []validator.Int64{int64validator.Between(1, 65535)},
		},
		"mode": schema.StringAttribute{
			Optional: true,
			Computed: true,
			Default:  stringdefault.StaticString(pbsclient.DefaultLDAPMode),
			MarkdownDescription: "How PBS connects: `ldaps`, over TLS; `ldap+starttls`, plain LDAP that " +
				"switches to TLS first; or `ldap`, the default, in plain text, in which the bind password and the " +
				"passwords of users signing in cross the network unencrypted.",
			Validators: []validator.String{stringvalidator.OneOf("ldap", "ldaps", "ldap+starttls")},
		},
		"verify": schema.BoolAttribute{
			Optional: true,
			Computed: true,
			Default:  booldefault.StaticBool(false),
			MarkdownDescription: "Whether PBS checks the server's TLS certificate, against the system's " +
				"certificate authorities or `capath`. Defaults to `false`: with `ldaps` or `ldap+starttls` and " +
				"without `verify`, PBS accepts any certificate, so the connection is encrypted but whoever " +
				"answers in place of the server gets the passwords.",
		},
		"capath": schema.StringAttribute{
			Optional: true,
			MarkdownDescription: "Certificate authority PBS trusts for the server, a path on the PBS host: a " +
				"PEM file, trusted besides the system's certificate authorities, or a directory of PEM " +
				"certificates, all of which are trusted instead of them — any other file in it fails every " +
				"connection. PBS reads it whenever it connects, even with `mode = \"ldap\"`, so it must exist. " +
				"PBS can neither change nor remove it once the realm exists: changing or removing `capath` " +
				"replaces the realm.",
			Validators: []validator.String{caPathCheck},
			// PBS's update accepts capath, but ignores it.
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"bind_dn": schema.StringAttribute{
			Optional: true,
			MarkdownDescription: "Account PBS binds as to look users up, such as " + r.bindDNExample() +
				"; requires a password, `password_wo`, when the realm is created. When left out, PBS searches " +
				"anonymously, which " + r.anonymousSearch() + ".",
			Validators: []validator.String{stringvalidator.LengthAtLeast(1), noControlOrPadding},
		},
		"password_wo":         password,
		"password_wo_version": passwordVersion,
		"filter": schema.StringAttribute{
			Optional: true,
			MarkdownDescription: "LDAP filter that limits which entries a sync turns into users, such as " +
				"`(memberOf=cn=pbs,ou=groups,dc=example,dc=com)`. Signing in does not use it. None when left out.",
			Validators: []validator.String{ldapFilterCheck},
		},
		"user_classes": schema.SetAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Computed:    true,
			Default:     setdefault.StaticValue(defaultUserClasses),
			MarkdownDescription: "Object classes a sync considers users: an entry is one when it has any of " +
				"them. Defaults to `[\"inetorgperson\", \"person\", \"posixaccount\", \"user\"]`.",
			Validators: []validator.Set{
				setvalidator.SizeAtLeast(1),
				setvalidator.NoNullValues(),
				setvalidator.ValueStringsAre(ldapAttributeValidator()),
			},
		},
		"sync_attributes": schema.SingleNestedAttribute{
			Optional: true,
			MarkdownDescription: "LDAP attributes a sync takes users' properties from, at least one. A " +
				"property left out is not synced: users keep theirs, unless `sync_defaults.remove_vanished` has " +
				"`properties`, which removes it from every user a sync finds.",
			Attributes: map[string]schema.Attribute{
				"email":     syncAttribute("email address", "mail"),
				"firstname": syncAttribute("first name", "givenName"),
				"lastname":  syncAttribute("last name", "sn"),
			},
			Validators: []validator.Object{nonEmptyObject{}},
		},
		"sync_defaults": schema.SingleNestedAttribute{
			Optional: true,
			MarkdownDescription: "What a sync does unless it is told otherwise when it is started, at least " +
				"one option.",
			Attributes: map[string]schema.Attribute{
				"enable_new": schema.BoolAttribute{
					Optional: true,
					MarkdownDescription: "Whether a sync enables the users it creates, and the users it updates " +
						"that have no enabled flag stored in PBS; PBS defaults to `true`. PBS stores none for an " +
						"enabled user unless its creation sent `enable = true`: `pbs_user` does not send the " +
						"default, and an update that enables a user removes the flag. So `false` disables the " +
						"enabled users a sync finds, those `pbs_user` manages included, until the next apply " +
						"enables them again. Disabled users stay disabled.",
				},
				"remove_vanished": schema.SetAttribute{
					ElementType: types.StringType,
					Optional:    true,
					MarkdownDescription: "What a sync removes when it no longer finds something in the " +
						"directory: `entry` the users of the realm it does not find, with their API tokens — " +
						"users Terraform manages included; `acl`, together with `entry`, the ACL entries of those " +
						"users and their tokens, and alone nothing; `properties` the email address and names of " +
						"users it finds that the directory has no value for, or that `sync_attributes` does not " +
						"name. PBS removes nothing when left out.",
					Validators: []validator.Set{
						setvalidator.SizeAtLeast(1),
						setvalidator.NoNullValues(),
						setvalidator.ValueStringsAre(stringvalidator.OneOf("acl", "entry", "properties")),
					},
				},
			},
			Validators: []validator.Object{nonEmptyObject{}},
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
	}
	if r.ad() {
		attributes["base_dn"] = schema.StringAttribute{
			Optional: true,
			Computed: true,
			MarkdownDescription: "Entry users are looked up below, such as `dc=example,dc=com`. When left out, " +
				"PBS asks the server for its default naming context, the domain's root, when it creates the " +
				"realm, and keeps that. PBS cannot remove it: removing `base_dn` keeps the one PBS has.",
			Validators: []validator.String{stringvalidator.LengthAtLeast(1), noControlOrPadding},
			// Not UseStateForUnknown: a realm without one — domains.cfg edited
			// by hand — gets one from PBS on its next update.
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseNonNullStateForUnknown()},
		}
	} else {
		attributes["base_dn"] = schema.StringAttribute{
			Required: true,
			MarkdownDescription: "Entry users are looked up below, in its whole subtree, such as " +
				"`ou=people,dc=example,dc=com`.",
			Validators: []validator.String{stringvalidator.LengthAtLeast(1), noControlOrPadding},
		}
		attributes["user_attr"] = schema.StringAttribute{
			Required: true,
			MarkdownDescription: "LDAP attribute whose value is the user name, `<value>@<realm>`, such as " +
				"`uid`.",
			Validators: []validator.String{ldapAttributeValidator()},
		}
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: r.description(),
		Attributes:          attributes,
	}
}

// bindDNExample is an account the realm's directory binds with.
func (r *directoryRealmResource) bindDNExample() string {
	if r.ad() {
		return "`cn=pbs,cn=Users,dc=example,dc=com` or, as a user principal name, `pbs@example.com`"
	}
	return "`uid=pbs,cn=sysaccounts,cn=etc,dc=example,dc=com`"
}

// anonymousSearch is what the realm's directory makes of an anonymous search.
func (r *directoryRealmResource) anonymousSearch() string {
	if r.ad() {
		return "Active Directory refuses by default"
	}
	return "many directories refuse"
}

func ldapServerValidator() validator.String {
	return stringvalidator.RegexMatches(ldapServerPattern,
		"must be a host name or IPv4 address, or an IPv6 address in square brackets, without a port")
}

// syncAttribute is an attribute of sync_attributes.
func syncAttribute(property, example string) schema.StringAttribute {
	return schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: fmt.Sprintf("LDAP attribute holding the user's %s, such as `%s`.", property, example),
		Validators:          []validator.String{ldapAttributeValidator()},
	}
}

// description is the resource's description.
func (r *directoryRealmResource) description() string {
	var intro string
	if r.ad() {
		intro = "Manages an Active Directory realm of a Proxmox Backup Server: users sign in to PBS with the " +
			"name and password of their Active Directory account, as `<sAMAccountName>@<realm>`. PBS looks " +
			"the account up below `base_dn`, by `sAMAccountName`, and checks the password by binding as it.\n\n"
	} else {
		intro = "Manages an LDAP realm of a Proxmox Backup Server: users sign in to PBS with the name and " +
			"password of their entry in an LDAP directory, such as OpenLDAP or FreeIPA, as `<name>@<realm>`, " +
			"the name being the value of `user_attr`. PBS looks the entry up below `base_dn` and checks the " +
			"password by binding as it.\n\n"
	}
	return intro +
		"Only users that exist in PBS can sign in: create them with `pbs_user`, or have a sync create them " +
		"from the directory — in the web interface, or with `proxmox-backup-manager " + r.kind.typ + " sync " +
		"<realm>`; `filter`, `user_classes`, `sync_attributes` and `sync_defaults` shape what it does. They " +
		"have no privileges until a `pbs_acl` grants them some.\n\n" +
		"~> **PBS checks the connection on every change.** Creating the realm, and every update — even of " +
		"`comment` — first connects to the server as the realm would after the change, binds as `bind_dn` " +
		"and reads `base_dn`; PBS saves nothing when that fails, and the apply fails with the reason. PBS " +
		"connects from its own host, so the server must be reachable from there, not from where Terraform " +
		"runs. A bind password changed in the directory but not in PBS blocks every update " +
		"until a new `password_wo_version` sends the new one. Destroying the realm connects to nothing.\n\n" +
		"**The bind password** is write-only, `password_wo` with `password_wo_version`: PBS never returns it, " +
		"so it stays out of the plan and state. PBS needs it to create a realm with a `bind_dn`, so creating " +
		"one — or replacing one, after an import, say — without `password_wo` fails in the plan.\n\n" +
		"~> **Only one realm is the default.** `default = true` takes the flag from the realm that had it, the " +
		"built-in `pam` and `pbs` and realms outside Terraform included. Set it on one realm only: two realms " +
		"with `default = true` take it from each other on every apply.\n\n" +
		"Changing `realm` or `capath` replaces the realm. A new `capath` keeps the name, so such a replacement " +
		"cannot use `create_before_destroy`: PBS refuses the new realm while the old one exists. PBS keeps the " +
		"users of a deleted realm, and their ACL entries.\n\n" +
		"Managing realms needs `Realm.Allocate` on `/access/domains`; reading one `Sys.Audit` there."
}

func (r *directoryRealmResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	example := "Realm name, such as `ipa`."
	if r.ad() {
		example = "Realm name, such as `ad`."
	}
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"realm", example})
}

func (r *directoryRealmResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan refuses to create a realm with a bind_dn but no password: PBS
// binds before it saves the realm, and has no password for a new one. A
// replacement — a new realm name or capath — creates the realm too.
func (r *directoryRealmResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	plan := r.newModel()
	resp.Diagnostics.Append(req.Plan.Get(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := plan.directory()
	what := "creates"
	if !req.State.Raw.IsNull() {
		state := r.newModel()
		resp.Diagnostics.Append(req.State.Get(ctx, state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		s := state.directory()
		what = ""
		if !p.Realm.Equal(s.Realm) || !p.CAPath.Equal(s.CAPath) {
			what = "replaces"
		}
	}
	if what != "" && !p.BindDN.IsNull() && p.PasswordWOVersion.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing bind password",
			fmt.Sprintf("The plan %s %s realm %q, with bind_dn, but without password_wo: PBS binds as bind_dn "+
				"before it saves the realm, and has no password for a new realm. Set password_wo, with "+
				"password_wo_version.", what, r.kind.name, p.Realm.ValueString()))
	}
}

// changes records the properties that differ between prior and m. A base_dn
// still unknown, of an Active Directory realm PBS is to find it for, is not
// sent.
func (m *directoryRealmModel) changes(prior directoryRealmModel, c *propertyChanges) {
	c.String("server1", m.Server1, prior.Server1)
	c.String("server2", m.Server2, prior.Server2)
	c.Int64("port", m.Port, prior.Port)
	c.StringDefault("mode", m.Mode, prior.Mode, pbsclient.DefaultLDAPMode)
	c.BoolDefault("verify", m.Verify, prior.Verify, false)
	c.String("capath", m.CAPath, prior.CAPath)
	if !m.BaseDN.IsUnknown() {
		c.String("base-dn", m.BaseDN, prior.BaseDN)
	}
	c.String("bind-dn", m.BindDN, prior.BindDN)
	c.String("filter", m.Filter, prior.Filter)
	c.CommaSeparated("user-classes", setWithoutDefault(m.UserClasses, defaultUserClasses),
		setWithoutDefault(prior.UserClasses, defaultUserClasses))
	c.PropertyString("sync-attributes", m.SyncAttributes, prior.SyncAttributes, syncAttributesFormat)
	c.PropertyString("sync-defaults-options", m.SyncDefaults, prior.SyncDefaults, syncDefaultsFormat)
	c.BoolDefault("default", m.Default, prior.Default, false)
	c.String("comment", m.Comment, prior.Comment)
}

// fromRealm records a realm as PBS reports it. The name is the one it was
// looked up by. The version of the write-only password exists only in
// Terraform and keeps its value.
func (m *directoryRealmModel) fromRealm(name string, realm pbsclient.DirectoryRealm, diags *diag.Diagnostics) {
	m.ID = types.StringValue(name)
	m.Realm = types.StringValue(name)
	m.Server1 = types.StringValue(realm.Server1)
	m.Server2 = stringOrNull(realm.Server2)
	m.Port = int64OrNull(realm.Port)
	m.Mode = types.StringValue(pbsclient.DefaultLDAPMode)
	if realm.Mode != "" {
		m.Mode = types.StringValue(realm.Mode)
	}
	m.Verify = boolOr(realm.Verify, false)
	m.CAPath = stringOrNull(realm.CAPath)
	m.BaseDN = stringOrNull(realm.BaseDN)
	m.BindDN = stringOrNull(realm.BindDN)
	m.PasswordWO = types.StringNull()
	m.Filter = stringOrNull(realm.Filter)
	m.UserClasses = defaultUserClasses
	if classes := pbsclient.SplitList(realm.UserClasses); len(classes) > 0 {
		m.UserClasses = stringSetOrNull(uniqueStrings(classes), diags)
	}
	m.SyncAttributes = syncAttributesFormat.object("sync-attributes", realm.SyncAttributes, diags)
	m.SyncDefaults = syncDefaultsFormat.object("sync-defaults-options", realm.SyncDefaultsOptions, diags)
	m.Default = boolOr(realm.Default, false)
	m.Comment = stringOrNull(realm.Comment)
}

// setWithoutDefault maps a set equal to def, PBS's default, to null, so that
// resetting it deletes the property instead of writing the default, and a
// create does not send it.
func setWithoutDefault(v, def types.Set) types.Set {
	if !v.IsUnknown() && v.Equal(def) {
		return types.SetNull(types.StringType)
	}
	return v
}

// directoryRealmErrorDetail explains a create or update PBS refused, with
// advice when the check of the connection failed. hasBindDN tells whether
// the realm, as planned, binds as bind_dn or searches anonymously.
func (r *directoryRealmResource) directoryRealmErrorDetail(err error, hasBindDN bool) string {
	detail := apiErrorDetail(r.data.client, realmModifyPrivilege, err)
	var advice string
	switch pbsclient.DirectoryCheckFailureOf(err) {
	case pbsclient.DirectoryCheckPassed:
		return detail
	case pbsclient.DirectoryMissingPassword:
		advice = "PBS has no password for bind_dn: set password_wo, with password_wo_version."
	case pbsclient.DirectoryBindFailed:
		advice = "The server refused bind_dn with the password PBS bound with: the one sent, when " +
			"password_wo_version changed, or else the one PBS has. Check bind_dn, and send the right password " +
			"with password_wo and a new password_wo_version. PBS binds on every change of the realm, so while " +
			"the password it has is wrong, every update fails."
	case pbsclient.DirectoryBindNeedsTLS:
		advice = "The server refuses to bind over a connection that is not protected: use mode = \"ldaps\" " +
			"or \"ldap+starttls\"."
	case pbsclient.DirectoryBaseDNFailed:
		advice = "PBS connected, but could not read base_dn: check that the entry exists, and that bind_dn " +
			"may read it."
		if !hasBindDN {
			advice = "PBS connected, but could not read base_dn: check that the entry exists. Without bind_dn, " +
				"PBS searches anonymously, which " + r.anonymousSearch() + ": set bind_dn, with password_wo " +
				"and password_wo_version."
		}
	case pbsclient.DirectoryNoNamingContext:
		advice = "Without base_dn, PBS asks the server for the default naming context of its domain, and " +
			"the server named none — it may not be an Active Directory domain controller. Set base_dn."
	default:
		advice = "PBS connects to the server before it saves the realm, from its own host, and could not. " +
			"Check server1, server2, port and mode, and that the PBS host reaches the server; capath, when " +
			"set, must exist on the PBS host whatever the mode; with ldaps or ldap+starttls, also check the " +
			"certificate and verify."
	}
	return advice + " " + detail
}

func (r *directoryRealmResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	plan := r.newModel()
	resp.Diagnostics.Append(req.Plan.Get(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := plan.directory()
	name := p.Realm.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(r.defaults(), changes)
	params := changes.Values()
	params.Set("realm", name)
	if !p.PasswordWOVersion.IsNull() {
		password, ok := writeOnlySecret(ctx, req.Config, "password", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing bind password",
				"password_wo_version is set, but password_wo is not known.")
		}
		params.Set("password", password)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	var realm pbsclient.DirectoryRealm
	readErr, err := writeRealm(client,
		func() error { return client.CreateDirectoryRealm(ctx, r.kind.typ, params) },
		func() (err error) { realm, _, err = client.GetDirectoryRealm(ctx, r.kind.typ, name); return err })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			addRealmExistsError(&resp.Diagnostics, r.kind, name, err)
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS "+r.kind.name+" realm",
			r.directoryRealmErrorDetail(err, !p.BindDN.IsNull()))
		return
	}

	// From here on the realm exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it. A base_dn PBS was to find stays unknown, which
	// state cannot hold, so it is recorded as null.
	if err := readErr; err != nil {
		p.ID = types.StringValue(name)
		if p.BaseDN.IsUnknown() {
			p.BaseDN = types.StringNull()
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS "+r.kind.name+" realm back after creation",
			fmt.Sprintf("PBS created realm %q, and it was recorded in state, but reading it back failed, so it is "+
				"marked tainted: the next apply replaces it. %s", name, apiErrorDetail(client, realmReadPrivilege, err)))
		return
	}
	plan.fromRealm(name, realm, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
}

func (r *directoryRealmResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	state := r.newModel()
	resp.Diagnostics.Append(req.State.Get(ctx, state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.directory().Realm.ValueString()
	// Before the lookup, so that a refresh finding the realm gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)

	realm, _, err := r.data.client.GetDirectoryRealm(ctx, r.kind.typ, name)
	if err != nil {
		readRealmFailed(ctx, resp, r.data.client, r.kind, name, err)
		return
	}
	state.fromRealm(name, realm, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update sends the properties that changed, and the bind password when its
// version did, in one call, which PBS checks by connecting. PBS clears the
// default flag of a realm on every update that does not set it again, so a
// default realm's update always sends it.
func (r *directoryRealmResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	plan, state := r.newModel(), r.newModel()
	resp.Diagnostics.Append(req.Plan.Get(ctx, plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := plan.directory()
	name := p.Realm.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, directoryRealmDeletable...)
	plan.changes(state, changes)
	params := changes.Values()
	if writeOnlyChanged(p.PasswordWOVersion, state.directory().PasswordWOVersion) {
		password, ok := writeOnlySecret(ctx, req.Config, "password", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing bind password",
				"password_wo_version changed, but password_wo is not known.")
		}
		params.Set("password", password)
	}
	if len(params) > 0 && p.Default.ValueBool() {
		params.Set("default", pbsclient.FormatBool(true))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	var realm pbsclient.DirectoryRealm
	readErr, err := writeRealm(client,
		func() error {
			if len(params) == 0 {
				return nil
			}
			return client.UpdateDirectoryRealm(ctx, r.kind.typ, name, params)
		},
		func() (err error) { realm, _, err = client.GetDirectoryRealm(ctx, r.kind.typ, name); return err })
	if err != nil {
		resp.Diagnostics.AddError("Unable to update PBS "+r.kind.name+" realm",
			r.directoryRealmErrorDetail(err, !p.BindDN.IsNull()))
		return
	}
	if err := readErr; err != nil {
		// As in Create: a base_dn PBS was to find cannot stay unknown.
		if p.BaseDN.IsUnknown() {
			p.BaseDN = types.StringNull()
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
		setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS "+r.kind.name+" realm back after update",
			fmt.Sprintf("PBS updated realm %q, and the change was recorded in state, but reading it back failed. %s",
				name, apiErrorDetail(client, realmReadPrivilege, err)))
		return
	}
	plan.fromRealm(name, realm, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
}

// Delete deletes the realm, while it still has the resource's type; see
// deleteRealm. PBS removes the stored bind password with it, and connects to
// nothing.
func (r *directoryRealmResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	state := r.newModel()
	resp.Diagnostics.Append(req.State.Get(ctx, state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteRealm(ctx, r.data.client, r.kind, state.directory().Realm.ValueString(), &resp.Diagnostics)
}

// ImportState imports a realm by name, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops a realm that does not exist, which Terraform reports. The
// bind password is not imported: PBS keeps it, and password_wo_version stays
// null until the configuration sets one.
func (r *directoryRealmResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	example := "ipa"
	if r.ad() {
		example = "ad"
	}
	name, ok := importedSafeID(ctx, req, resp, "realm", r.kind.name+" realm", example)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("realm"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "realm", name, &resp.Diagnostics)
}
