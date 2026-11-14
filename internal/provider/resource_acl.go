package provider

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &aclResource{}
	_ resource.ResourceWithConfigure   = &aclResource{}
	_ resource.ResourceWithIdentity    = &aclResource{}
	_ resource.ResourceWithImportState = &aclResource{}
	_ resource.ResourceWithModifyPlan  = &aclResource{}
)

// NewACLResource returns the pbs_acl resource.
func NewACLResource() resource.Resource { return &aclResource{} }

type aclResource struct {
	data *providerData
}

type aclModel struct {
	ID        types.String `tfsdk:"id"`
	Path      types.String `tfsdk:"path"`
	AuthID    types.String `tfsdk:"auth_id"`
	Role      types.String `tfsdk:"role"`
	Propagate types.Bool   `tfsdk:"propagate"`
}

// aclIDSeparator joins the three parts of an ACL entry's ID. Neither a path
// nor a role contains it, so an ID splits unambiguously at the first and the
// last one, even though a user name may contain it.
const aclIDSeparator = "|"

// aclID is the ID of an ACL entry: path|auth_id|role.
func aclID(path, authID, role string) string {
	return path + aclIDSeparator + authID + aclIDSeparator + role
}

// splitACLID splits an ACL entry's ID.
func splitACLID(id string) (path, authID, role string, ok bool) {
	first, last := strings.Index(id, aclIDSeparator), strings.LastIndex(id, aclIDSeparator)
	if first < 0 || first == last {
		return "", "", "", false
	}
	return id[:first], id[first+1 : last], id[last+1:], true
}

// aclReadPrivilege is what reading every ACL entry needs. Without it, PBS
// shows a user signed in with its password only the entries of its own API
// tokens, neither its own nor a group's, and an API token none at all, not
// even its own; it answers with what it shows, as a success, never a 403
// (src/api2/access/acl.rs, read_acl and extract_acl_node_data,
// proxmox-backup 7c86c5ad5, after 4.2.11).
const aclReadPrivilege = "Sys.Audit on /access/acl"

// rootUserID is the superuser, which always has every privilege. PBS takes
// an ACL entry for it without an error but leaves it out when it saves
// acl.cfg ("no need to save, because root is always 'Administrator'",
// pbs-config/src/acl.rs, write_node_config, proxmox-backup 7c86c5ad5, after
// 4.2.11); the entries of its API tokens it keeps.
const rootUserID = "root@pam"

// aclAuthIDNotRoot refuses an entry for root@pam itself, which PBS would
// never store: every refresh would find it gone and every apply create it
// again.
var aclAuthIDNotRoot = stringCheck{
	description: "must not be root@pam: it always has every privilege, and PBS stores no ACL entry for it, so " +
		"the entry would be created again on every apply (root@pam's API tokens, such as root@pam!ci, are fine)",
	check: func(s string) bool { return s != rootUserID },
}

func (r *aclResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl"
}

func (r *aclResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Grants a role to a Proxmox Backup Server user or API token on an ACL path: one " +
			"entry of the server's access control list. Several roles on the same path for the same user or " +
			"token are separate entries, and separate resources.\n\n" +
			"An API token acts with the intersection of its user's privileges and its own, so it needs entries " +
			"for its token ID besides those of its user. Deleting a user or token deletes the entries of its " +
			"tokens; the user's own entries are removed by `pbs_user` when it destroys the user.\n\n" +
			"~> **`NoAccess` excludes every other role.** On one path, a user or token has either `NoAccess` or " +
			"other roles: granting `NoAccess` removes its other roles there, and granting another role removes " +
			"`NoAccess`. The provider warns when that happens. Do not manage both kinds for the same path and " +
			"user or token, or each apply removes what the previous one granted.\n\n" +
			"-> Before PBS 4.2.6, PBS caches privileges for up to 5 seconds and does not drop them when an entry " +
			"changes, so a new role may take that long to work after the apply, and a removed one to stop " +
			"working.\n\n" +
			"Creating an entry that already exists fails, so that Terraform does not take over, and later delete, " +
			"an entry it did not create: import it instead.\n\n" +
			"Managing ACL entries needs " + aclModifyPrivilege + ", which only the `Admin` role grants, and " +
			"reading them all " + aclReadPrivilege + ", which `Admin` includes. Without them, PBS lets a user " +
			"signed in with its password see and change only the entries of its own API tokens, and an API " +
			"token none at all. Refreshing an entry the provider cannot see then fails rather than drop it " +
			"from state, and so does importing one.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "`<path>|<auth_id>|<role>`, such as `/datastore/store1|alice@pbs!ci|DatastoreBackup`, " +
					"the ID to import the entry by. Known at plan time.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"path": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "ACL path the role applies to, such as `/` for the whole server, " +
					"`/datastore/store1` for a datastore, `/datastore/store1/ns1` for a namespace in it, " +
					"`/remote/offsite` for a remote or `/system` for the node. PBS refuses a path it does not " +
					"know (\"invalid acl path\"), but not one whose datastore or remote does not exist yet. " +
					"Changing it replaces the entry.",
				Validators:    aclPathValidators(),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"auth_id": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "User ID, such as `alice@pbs`, or API token ID, such as `alice@pbs!ci` — the " +
					"`tokenid` of a `pbs_api_token` — the role is granted to. The user or token must exist. Not " +
					"`root@pam`, which always has every privilege and for which PBS stores no entry; its API " +
					"tokens are fine. Changing it replaces the entry.",
				Validators:    append(authIDValidators(), aclAuthIDNotRoot),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"role": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Role to grant. PBS has a fixed set of roles: " + roleList() + ". The " +
					"`pbs_roles` data source lists the privileges of each. Changing it replaces the entry.",
				Validators:    []validator.String{stringvalidator.OneOf(pbsclient.Roles...)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"propagate": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				MarkdownDescription: "Whether the role also applies below `path` — to the namespaces of a " +
					"datastore, say. Defaults to `true`, as in PBS.",
			},
		},
	}
}

// roleList is the roles for documentation, as code spans.
func roleList() string {
	quoted := make([]string, len(pbsclient.Roles))
	for i, role := range pbsclient.Roles {
		quoted[i] = "`" + role + "`"
	}
	return strings.Join(quoted, ", ")
}

func (r *aclResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(
		identityAttribute{"path", "ACL path, such as `/datastore/store1`."},
		identityAttribute{"auth_id", "User ID or API token ID, such as `alice@pbs!ci`."},
		identityAttribute{"role", "Role, such as `DatastoreBackup`."},
	)
}

func (r *aclResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan fills in the ID at plan time.
func (r *aclResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan aclModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || plan.Path.IsUnknown() || plan.AuthID.IsUnknown() || plan.Role.IsUnknown() {
		return
	}
	id := aclID(plan.Path.ValueString(), plan.AuthID.ValueString(), plan.Role.ValueString())
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), id)...)
}

// findACLEntry looks an entry up among the entries on its path.
func findACLEntry(entries []pbsclient.ACLEntry, path, authID, role string) (pbsclient.ACLEntry, bool) {
	for _, e := range entries {
		if e.Path == path && e.UGID == authID && e.RoleID == role {
			return e, true
		}
	}
	return pbsclient.ACLEntry{}, false
}

func (r *aclResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan aclModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	aclPath, authID, role := plan.Path.ValueString(), plan.AuthID.ValueString(), plan.Role.ValueString()
	id := aclID(aclPath, authID, role)
	client := r.data.client
	propagate := plan.Propagate.ValueBool()

	// PUT /access/acl grants a role that is already granted without a word,
	// so the entry is looked up first, and the digest of what was read makes
	// PBS refuse the write should another client change acl.cfg meanwhile.
	exists := false
	var displaced []string
	err := client.WithConfigLock(pbsclient.ConfigACL, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			entries, digest, err := client.ListACL(ctx, aclPath, true)
			if err != nil {
				return err
			}
			if _, exists = findACLEntry(entries, aclPath, authID, role); exists {
				return nil
			}
			displaced = displacedRoles(entries, aclPath, authID, role)
			return client.UpdateACL(ctx, pbsclient.ACLChange{
				Path: aclPath, AuthID: authID, Role: role, Propagate: &propagate, Digest: digest,
			})
		})
	})
	switch {
	case err != nil:
		resp.Diagnostics.AddError("Unable to create PBS ACL entry", aclErrorDetail(client, authID, err))
		return
	case exists:
		resp.Diagnostics.AddError("PBS ACL entry already exists",
			fmt.Sprintf("%s already has the role %s on %s. To manage the entry with Terraform, import it, with an "+
				"import block whose id is %q or with `terraform import`.", authID, role, aclPath, id))
		return
	}

	plan.ID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	recordACLIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)
	if len(displaced) > 0 {
		resp.Diagnostics.AddWarning("PBS removed other roles",
			fmt.Sprintf("Granting %s to %s on %s removed its roles %s there: PBS lets a user or token have either "+
				"%s or other roles on a path. A pbs_acl resource that manages one of them will plan to grant it "+
				"again, which removes %s in turn.", role, authID, aclPath, strings.Join(displaced, ", "),
				pbsclient.NoAccessRole, role))
	}
}

// displacedRoles returns the roles of authID on path that granting role
// removes: all the others for NoAccess, and NoAccess for any other.
func displacedRoles(entries []pbsclient.ACLEntry, path, authID, role string) []string {
	var displaced []string
	for _, e := range entries {
		if e.Path != path || e.UGID != authID || e.RoleID == role {
			continue
		}
		if role == pbsclient.NoAccessRole || e.RoleID == pbsclient.NoAccessRole {
			displaced = append(displaced, e.RoleID)
		}
	}
	return displaced
}

func (r *aclResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state aclModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	recordACLIdentity(ctx, resp.Identity, state, &resp.Diagnostics)
	aclPath, authID, role := state.Path.ValueString(), state.AuthID.ValueString(), state.Role.ValueString()

	client := r.data.client
	entries, _, err := client.ListACL(ctx, aclPath, true)
	if err != nil {
		// PBS lets everyone read the ACL, so this is not about privileges.
		resp.Diagnostics.AddError("Unable to read PBS ACL entries", err.Error())
		return
	}
	entry, ok := findACLEntry(entries, aclPath, authID, role)
	if !ok {
		// PBS leaves out, as a success, the entries a caller without
		// Sys.Audit on /access/acl may not see, so an entry it does not list
		// is gone only if the provider may see it.
		visible, err := aclEntriesVisible(ctx, client, authID)
		switch {
		case err != nil:
			resp.Diagnostics.AddError("Unable to read PBS ACL entries",
				fmt.Sprintf("PBS did not list the role %s of %s on %s. It does not show every caller every entry, so "+
					"the provider reads its own privileges on /access/acl to tell whether the entry is gone, and that "+
					"failed. %s", role, authID, aclPath, err))
		case !visible:
			resp.Diagnostics.AddError("Unable to read PBS ACL entry", aclHiddenDetail(client, aclPath, authID, role, state.Propagate.IsNull()))
		default:
			resp.State.RemoveResource(ctx)
		}
		return
	}
	state.ID = types.StringValue(aclID(aclPath, authID, role))
	state.Propagate = types.BoolValue(entry.Propagates())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update changes propagate, the only attribute that does not replace the
// entry: granting a role again sets its flag. Should the entry have gone
// meanwhile, this grants it again, which is what the plan says.
func (r *aclResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan aclModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	propagate := plan.Propagate.ValueBool()
	change := pbsclient.ACLChange{
		Path: plan.Path.ValueString(), AuthID: plan.AuthID.ValueString(), Role: plan.Role.ValueString(), Propagate: &propagate,
	}
	err := client.WithConfigLock(pbsclient.ConfigACL, func() error { return client.UpdateACL(ctx, change) })
	if err != nil {
		resp.Diagnostics.AddError("Unable to update PBS ACL entry", aclErrorDetail(client, change.AuthID, err))
		return
	}
	plan.ID = types.StringValue(aclID(change.Path, change.AuthID, change.Role))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	recordACLIdentity(ctx, resp.Identity, plan, &resp.Diagnostics)
}

// Delete removes the role. PBS answers 200 when there is nothing to remove,
// also for a user or token that no longer exists.
func (r *aclResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state aclModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	change := pbsclient.ACLChange{
		Path: state.Path.ValueString(), AuthID: state.AuthID.ValueString(), Role: state.Role.ValueString(), Delete: true,
	}
	err := client.WithConfigLock(pbsclient.ConfigACL, func() error { return client.UpdateACL(ctx, change) })
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete PBS ACL entry", aclModifyErrorDetail(client, err))
	}
}

// aclErrorDetail explains a failed grant, naming the user or token that does
// not exist when PBS says so.
func aclErrorDetail(client *pbsclient.Client, authID string, err error) string {
	// 400 "no such user." or "no such API token.".
	if pbsclient.IsNotFound(err) {
		return fmt.Sprintf("PBS has no user or API token %q to grant the role to. %s", authID, err)
	}
	return aclModifyErrorDetail(client, err)
}

// aclModifyErrorDetail explains a failed change of an ACL entry. PBS refuses
// a caller without Permissions.Modify on /access/acl with a 400 "Unprivileged
// ...", not a 403, which the detail turns into the privilege it lacks.
func aclModifyErrorDetail(client *pbsclient.Client, err error) string {
	if pbsclient.IsUnprivilegedACLChange(err) {
		return fmt.Sprintf("%q lacks %s, which only the Admin role grants: without it, PBS lets a user signed in "+
			"with its password change only the ACL entries of its own API tokens, and an API token none at all. %s",
			client.AuthID(), aclModifyPrivilege, err)
	}
	return apiErrorDetail(client, aclModifyPrivilege, err)
}

// aclEntriesVisible reports whether PBS shows the client the ACL entries of
// authID. With Sys.Audit on /access/acl it shows every entry. Without it, it
// shows a user signed in with its password the entries of its own API
// tokens, which needs no call to know, and an API token none at all
// (src/api2/access/acl.rs, read_acl, proxmox-backup 7c86c5ad5, after
// 4.2.11). GET /access/permissions of the client itself on /access/acl
// answers the very privileges read_acl looks up, and every caller may ask it.
func aclEntriesVisible(ctx context.Context, client *pbsclient.Client, authID string) (bool, error) {
	if !client.UsesAPIToken() {
		if owner, _, ok := pbsclient.SplitTokenID(authID); ok && owner == client.AuthID() {
			return true, nil
		}
	}
	permissions, err := client.Permissions(ctx, "", "/access/acl")
	if err != nil {
		return false, err
	}
	_, ok := permissions["/access/acl"]["Sys.Audit"]
	return ok, nil
}

// aclHiddenDetail explains why the provider cannot tell whether an entry PBS
// did not list still exists: PBS hides it from the client.
func aclHiddenDetail(client *pbsclient.Client, path, authID, role string, importing bool) string {
	outcome := "The entry stays in state as it was, rather than be planned for creation again, which PBS would refuse."
	if importing {
		outcome = "The entry is not imported."
	}
	grantee := strconv.Quote(client.AuthID())
	if client.UsesAPIToken() {
		grantee += " and to its user"
	}
	return fmt.Sprintf("PBS did not list the role %s of %s on %s, but it hides that entry from %q whether it exists "+
		"or not: without %s, PBS shows a user signed in with its password only the ACL entries of its own API "+
		"tokens, and an API token none at all. So the provider cannot tell whether the entry still exists. %s "+
		"Managing ACL entries needs %s, which only the Admin role grants, and %s, which Admin includes: grant "+
		"Admin on /access/acl to %s, or manage the entry with a provider that has it.",
		role, authID, path, client.AuthID(), aclReadPrivilege, outcome, aclModifyPrivilege, aclReadPrivilege, grantee)
}

// recordACLIdentity records the entry's identity.
func recordACLIdentity(ctx context.Context, identity *tfsdk.ResourceIdentity, m aclModel, diags *diag.Diagnostics) {
	setIdentity(ctx, identity, "path", m.Path.ValueString(), diags)
	setIdentity(ctx, identity, "auth_id", m.AuthID.ValueString(), diags)
	setIdentity(ctx, identity, "role", m.Role.ValueString(), diags)
}

// ImportState imports an entry by its ID, path|auth_id|role, or from
// Terraform 1.12 by the identity of an import block. Read drops an entry
// that does not exist, which Terraform reports, and fails for one PBS does
// not show the provider, saying why.
func (r *aclResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, values, byIdentity := importedID(ctx, req, &resp.Diagnostics, "path", "auth_id", "role")
	if resp.Diagnostics.HasError() {
		return
	}
	var aclPath, authID, role string
	ok := true
	if byIdentity {
		aclPath, authID, role = values[0], values[1], values[2]
	} else {
		aclPath, authID, role, ok = splitACLID(id)
	}
	if !ok || !aclPathPattern.MatchString(aclPath) || !authIDPattern.MatchString(authID) || !slices.Contains(pbsclient.Roles, role) {
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import a PBS ACL entry by <path>|<user or token ID>|<role>, such as "+
				"/datastore/store1|alice@pbs!ci|DatastoreBackup, got "+strconv.Quote(id+strings.Join(values, aclIDSeparator))+".")
		return
	}
	m := aclModel{
		ID: types.StringValue(aclID(aclPath, authID, role)), Path: types.StringValue(aclPath),
		AuthID: types.StringValue(authID), Role: types.StringValue(role), Propagate: types.BoolNull(),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
	recordACLIdentity(ctx, resp.Identity, m, &resp.Diagnostics)
}
