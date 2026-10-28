package provider

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	_ resource.Resource                = &remoteResource{}
	_ resource.ResourceWithConfigure   = &remoteResource{}
	_ resource.ResourceWithIdentity    = &remoteResource{}
	_ resource.ResourceWithImportState = &remoteResource{}
	_ resource.ResourceWithModifyPlan  = &remoteResource{}
)

// NewRemoteResource returns the pbs_remote resource.
func NewRemoteResource() resource.Resource { return &remoteResource{} }

type remoteResource struct {
	data *providerData
}

type remoteModel struct {
	ID                types.String     `tfsdk:"id"`
	Name              types.String     `tfsdk:"name"`
	Host              types.String     `tfsdk:"host"`
	Port              types.Int64      `tfsdk:"port"`
	AuthID            types.String     `tfsdk:"auth_id"`
	PasswordWO        types.String     `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64      `tfsdk:"password_wo_version"`
	Fingerprint       fingerprintValue `tfsdk:"fingerprint"`
	UseNodeProxy      types.Bool       `tfsdk:"use_node_proxy"`
	Comment           types.String     `tfsdk:"comment"`
}

// remoteDeletable are the properties PBS lets a remote update delete. host
// and auth-id are not among them; both are required.
var remoteDeletable = []string{"comment", "fingerprint", "port", "use-node-proxy"}

// Privileges the remote resources need, for error messages.
const (
	remoteReadPrivilege   = "Remote.Audit on /remote/<name>"
	remoteModifyPrivilege = "Remote.Modify on /remote/<name>"
	remoteCreatePrivilege = "Remote.Modify on /remote"
)

// maxRemotePasswordBytes bounds a remote's password. PBS takes up to 1024
// characters, but stores the password base64-encoded under the same limit,
// which a password longer than 768 bytes would exceed.
const maxRemotePasswordBytes = 768

// hostNamePattern is a DNS name as PBS accepts one for a remote: labels of
// letters, digits and inner hyphens, separated by dots, without a trailing
// dot.
var hostNamePattern = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

// hostValidators check a remote's host: a DNS name, an IPv4 address or an
// IPv6 address without brackets or zone, and without a port.
func hostValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(1, maxAddressLength),
		stringCheck{
			description: "must be a DNS name, an IPv4 address or an IPv6 address without brackets, and without a port",
			check: func(s string) bool {
				return hostNamePattern.MatchString(s) || (!strings.Contains(s, "%") && net.ParseIP(s) != nil)
			},
		},
	}
}

func (r *remoteResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_remote"
}

func (r *remoteResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	password, passwordVersion := writeOnlySecretAttributes("password",
		"Password of `auth_id` on the remote, or, when `auth_id` is an API token, the token's secret. PBS needs "+
			"it to create the remote, so it is required then; after an import, leave it out to keep the password "+
			"PBS has.",
		stringCheck{
			description: "must be 1 to 768 bytes long, without control characters",
			check: func(s string) bool {
				return s != "" && len(s) <= maxRemotePasswordBytes && !strings.ContainsFunc(s, unicode.IsControl)
			},
		}.secret(),
	)

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server remote: another PBS that sync jobs pull backups from " +
			"or push them to, with the credentials to sign in there. A `pbs_sync_job` names it in `remote`.\n\n" +
			"PBS contacts nothing when it saves a remote: a wrong host, port, fingerprint or password shows only " +
			"when a sync job runs, or when the `pbs_remote_datastores` data source scans the remote, which signs " +
			"in to it.\n\n" +
			"Sign in with an API token on the remote rather than a password, with only the privileges the sync " +
			"jobs need there, on `/datastore/<store>` of the remote — a `pbs_acl` on the remote grants them: to " +
			"pull, the role `DatastoreReader` (or `DatastoreBackup`, which reads the token's own backups only); to " +
			"push, `DatastoreBackup`, or `DatastorePowerUser` for `remove_vanished`, and `Datastore.Modify`, which " +
			"`DatastoreAdmin` has, for a push that creates namespaces there.\n\n" +
			"~> **PBS refuses to delete a remote a sync job uses.** When a change of `name` replaces a remote " +
			"that a `pbs_sync_job` uses, set `lifecycle { create_before_destroy = true }` on the remote, so that " +
			"the job moves to the new remote before the old one goes.\n\n" +
			"Managing remotes needs `Remote.Modify` on `/remote`, or on `/remote/<name>` for an existing one; " +
			"reading them `Remote.Audit`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `name`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Remote name, 3 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`. Sync jobs name it in `remote`, and ACL paths in `/remote/<name>`. " +
					"Changing it replaces the remote.",
				Validators:    safeIDValidators(minSafeIDLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"host": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "DNS name or IP address of the remote, without a port; an IPv6 address goes " +
					"without brackets.",
				Validators: hostValidators(),
			},
			"port": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Port of the remote's API; 8007, PBS's own, when left out.",
				Validators:          []validator.Int64{int64validator.Between(1, 65535)},
			},
			"auth_id": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "User or API token to sign in to the remote as, such as `sync@pbs` or " +
					"`sync@pbs!offsite`.",
				Validators: authIDValidators(),
			},
			"password_wo":         password,
			"password_wo_version": passwordVersion,
			"fingerprint": schema.StringAttribute{
				CustomType: fingerprintType{},
				Optional:   true,
				MarkdownDescription: "SHA-256 fingerprint of the remote's certificate, such as the `fingerprint` " +
					"of the `pbs_fingerprint` data source on the remote: 64 hexadecimal digits, optionally " +
					"separated by colons, in either case. PBS then accepts the certificate with this fingerprint, as " +
					"a self-signed one needs; a certificate its system's CAs validate it accepts either way, so the " +
					"fingerprint is no pin against those. When left out, PBS accepts only certificates its CAs " +
					"validate. The fingerprint changes with the certificate, so update it when the remote's " +
					"certificate is renewed or replaced.",
				Validators: []validator.String{certFingerprintValidator()},
			},
			"use_node_proxy": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether PBS connects to the remote through the HTTP proxy of its node " +
					"configuration. Defaults to `false`, a direct connection. `true` needs PBS 4.2 or newer.",
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
		},
	}
}

func (r *remoteResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Remote name, such as `offsite`."})
}

func (r *remoteResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan requires the password for a create, which PBS cannot do
// without one, and refuses use_node_proxy on a server older than PBS 4.2.
func (r *remoteResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan remoteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if mayBeTrue(plan.UseNodeProxy) {
		r.data.requireRelease(&resp.Diagnostics, path.Root("use_node_proxy"), plan.UseNodeProxy, pbs42)
	}

	creates := req.State.Raw.IsNull()
	if !creates {
		var state remoteModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		creates = !plan.Name.Equal(state.Name)
	}
	if creates && plan.PasswordWOVersion.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing remote password",
			"PBS creates a remote only with the password of auth_id, or the secret of its API token. Set "+
				"password_wo, with password_wo_version.")
	}
}

// mayBeTrue reports whether a planned bool is true or still unknown.
func mayBeTrue(v types.Bool) bool {
	return v.IsUnknown() || v.ValueBool()
}

// remoteDefaults is the model of a remote as PBS creates it when a property
// is left out, the prior state of a create.
var remoteDefaults = remoteModel{
	Port:         types.Int64Null(),
	Fingerprint:  fingerprintOrNull(""),
	UseNodeProxy: types.BoolValue(false),
	Comment:      types.StringNull(),
}

// pbsFingerprint is a fingerprint in the form PBS takes, colon-separated
// lower-case hex pairs, so that one written another way is sent as PBS
// shows it, and a change of spelling alone sends nothing. Null, unknown and
// invalid values stay as they are.
func pbsFingerprint(v fingerprintValue) types.String {
	if v.IsNull() || v.IsUnknown() {
		return v.StringValue
	}
	normalised, err := pbsclient.NormaliseFingerprint(v.ValueString())
	if err != nil {
		return v.StringValue
	}
	return types.StringValue(pbsclient.FormatFingerprint(normalised))
}

// changes records the properties that differ between prior and m. The
// password is not one of them.
func (m *remoteModel) changes(prior remoteModel, c *propertyChanges) {
	c.String("host", m.Host, prior.Host)
	c.Int64("port", m.Port, prior.Port)
	c.String("auth-id", m.AuthID, prior.AuthID)
	c.String("fingerprint", pbsFingerprint(m.Fingerprint), pbsFingerprint(prior.Fingerprint))
	c.BoolDefault("use-node-proxy", m.UseNodeProxy, prior.UseNodeProxy, false)
	c.String("comment", m.Comment, prior.Comment)
}

// fromRemote records a remote as PBS reports it. The name is the one it was
// looked up by. The password's version exists only in Terraform and keeps
// its value; the password itself is never stored.
func (m *remoteModel) fromRemote(name string, remote pbsclient.Remote) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.Host = types.StringValue(remote.Host)
	m.Port = int64OrNull(remote.Port)
	m.AuthID = types.StringValue(remote.AuthID)
	m.PasswordWO = types.StringNull()
	m.Fingerprint = fingerprintOrNull(remote.Fingerprint)
	m.UseNodeProxy = boolOr(remote.UseNodeProxy, false)
	m.Comment = stringOrNull(remote.Comment)
}

// remotePrivilege names a privilege on the remote, for errors.
func remotePrivilege(privilege, name string) string {
	return strings.Replace(privilege, "<name>", name, 1)
}

func (r *remoteResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan remoteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(remoteDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
	password, ok := writeOnlySecret(ctx, req.Config, "password", &resp.Diagnostics)
	if !ok {
		resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing remote password",
			"PBS creates a remote only with a password, but password_wo is not known.")
	}
	params.Set("password", password)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigRemotes, func() error { return client.CreateRemote(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS remote already exists",
				fmt.Sprintf("PBS already has a remote %q. To manage it with Terraform, import it, with an import "+
					"block whose id is %q or with `terraform import`. %s", name, name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS remote", apiErrorDetail(client, remoteCreatePrivilege, err))
		return
	}

	// From here on the remote exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	remote, err := client.GetRemote(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS remote back after creation",
			fmt.Sprintf("PBS created remote %q, and it was recorded in state, but reading it back failed, so it is "+
				"marked tainted: the next apply replaces it. %s", name,
				apiErrorDetail(client, remotePrivilege(remoteReadPrivilege, name), err)))
		return
	}
	plan.fromRemote(name, remote)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

func (r *remoteResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state remoteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the remote gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	remote, err := r.data.client.GetRemote(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS remote",
			apiErrorDetail(r.data.client, remotePrivilege(remoteReadPrivilege, name), err))
		return
	}
	state.fromRemote(name, remote)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update sends the properties that changed, and the password when its
// version did, in one call.
func (r *remoteResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state remoteModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, remoteDeletable...)
	plan.changes(state, changes)
	params := changes.Values()
	if writeOnlyChanged(plan.PasswordWOVersion, state.PasswordWOVersion) {
		password, ok := writeOnlySecret(ctx, req.Config, "password", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing remote password",
				"password_wo_version changed, but password_wo is not known.")
		}
		params.Set("password", password)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if len(params) > 0 {
		err := client.WithConfigLock(pbsclient.ConfigRemotes, func() error { return client.UpdateRemote(ctx, name, params) })
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS remote",
				apiErrorDetail(client, remotePrivilege(remoteModifyPrivilege, name), err))
			return
		}
	}

	remote, err := client.GetRemote(ctx, name)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS remote back after update",
			fmt.Sprintf("PBS updated remote %q, and the change was recorded in state, but reading it back failed. %s",
				name, apiErrorDetail(client, remotePrivilege(remoteReadPrivilege, name), err)))
		return
	}
	plan.fromRemote(name, remote)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// Delete deletes the remote; one already gone is not an error.
func (r *remoteResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state remoteModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigRemotes, func() error { return client.DeleteRemote(ctx, name) })
	switch {
	case err == nil || pbsclient.IsNotFound(err):
	case pbsclient.IsRemoteInUse(err):
		resp.Diagnostics.AddError("Unable to delete PBS remote",
			fmt.Sprintf("A sync job still uses remote %q, and PBS deletes no remote a sync job uses. Delete the job "+
				"or point it at another remote first. When a change of name replaces the remote while a "+
				"pbs_sync_job uses it, set lifecycle { create_before_destroy = true } on the remote, so that the "+
				"job moves to the new remote before the old one goes. %s", name, err))
	default:
		resp.Diagnostics.AddError("Unable to delete PBS remote",
			apiErrorDetail(client, remotePrivilege(remoteModifyPrivilege, name), err))
	}
}

// ImportState imports a remote by name, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops a remote that does not exist, which Terraform reports. The
// password cannot be imported: PBS never returns it.
func (r *remoteResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "remote", "offsite")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
