package provider

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &userResource{}
	_ resource.ResourceWithConfigure      = &userResource{}
	_ resource.ResourceWithIdentity       = &userResource{}
	_ resource.ResourceWithImportState    = &userResource{}
	_ resource.ResourceWithModifyPlan     = &userResource{}
	_ resource.ResourceWithValidateConfig = &userResource{}
)

// NewUserResource returns the pbs_user resource.
func NewUserResource() resource.Resource { return &userResource{} }

type userResource struct {
	data *providerData
}

type userModel struct {
	ID                types.String `tfsdk:"id"`
	UserID            types.String `tfsdk:"userid"`
	Comment           types.String `tfsdk:"comment"`
	Email             types.String `tfsdk:"email"`
	Firstname         types.String `tfsdk:"firstname"`
	Lastname          types.String `tfsdk:"lastname"`
	Enable            types.Bool   `tfsdk:"enable"`
	Expire            types.Int64  `tfsdk:"expire"`
	PasswordWO        types.String `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64  `tfsdk:"password_wo_version"`
}

// userDeletable are the properties PBS lets a user update delete. expire is
// not among them; 0 resets it.
var userDeletable = []string{"comment", "email", "firstname", "lastname"}

// passwordRealm is the only realm whose passwords PBS stores itself.
const passwordRealm = "pbs"

// Privileges the user resource needs, for error messages.
const (
	userReadPrivilege   = "Sys.Audit on /access/users"
	userModifyPrivilege = "Permissions.Modify on /access/users"
	aclModifyPrivilege  = "Permissions.Modify on /access/acl"
)

func (r *userResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *userResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	password, passwordVersion := writeOnlySecretAttributes("password",
		"Password of the user, 8 to 64 characters, for a user of the `pbs` realm only: users of other realms "+
			"authenticate there.",
		stringvalidator.LengthBetween(8, 64),
		stringCheck{
			description: "must not contain control characters",
			check:       func(s string) bool { return !strings.ContainsFunc(s, unicode.IsControl) },
			hideValue:   true,
		},
	)

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server user: an account of one of the server's realms — " +
			"`pbs`, the server's own user database; `pam`, the accounts of the host; or an LDAP, Active Directory " +
			"or OpenID Connect realm. Only users of the `pbs` realm have a password PBS stores; the others " +
			"authenticate against their realm, and PBS keeps only the settings below.\n\n" +
			"A user has no privileges until ACL entries grant them, with `pbs_acl`. Its API tokens are " +
			"`pbs_api_token` resources, and need ACL entries of their own.\n\n" +
			"~> **Destroying a user removes all its ACL entries.** PBS deletes a user's API tokens, and their ACL " +
			"entries, along with the user, but keeps the user's own entries, which would apply again to a user " +
			"created later under the same ID. Destroying this resource therefore first removes every ACL entry " +
			"of the user, including entries Terraform does not manage; that needs " + aclReadPrivilege + " and " +
			aclModifyPrivilege + ", without which destroying fails. Replacing a user without changing " +
			"`userid`, as `terraform apply -replace` does, also loses its tokens and the entries of `pbs_acl` " +
			"resources: the next plan creates them again, the tokens with new secrets.\n\n" +
			"**Changing the password.** PBS takes `password_wo` when it creates the user, from any caller, API " +
			"tokens included. Later it changes a password only through `PUT /access/password`, which is closed " +
			"to API tokens: a change of `password_wo_version` needs a provider that signs in with `username` and " +
			"`password`, and is a plan-time error with an API token. PBS wants the caller's own password as " +
			"confirmation, which the provider sends, and the caller needs `" + userModifyPrivilege + "` — " +
			"`root@pam` may change any password.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `userid`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"userid": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "User ID: the user name, `@`, and the realm, such as `alice@pbs` or " +
					"`backup@pam`. The realm must exist; a `pam` user also needs an account on the host to sign in. " +
					"Changing it replaces the user.",
				Validators:    userIDValidators(),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
			"email": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Email address, 2 to 64 characters. PBS sends the user's notifications there.",
				Validators:          textValidators(minNameLength, maxNameLength),
			},
			"firstname": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "First name, 2 to 64 characters.",
				Validators:          textValidators(minNameLength, maxNameLength),
			},
			"lastname": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Last name, 2 to 64 characters.",
				Validators:          textValidators(minNameLength, maxNameLength),
			},
			"enable": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				MarkdownDescription: "Whether the user may sign in. Defaults to `true`. The API tokens of a disabled " +
					"user cannot sign in either.",
			},
			"expire": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
				MarkdownDescription: "When the account expires, in seconds since the Unix epoch, such as the " +
					"`unix` attribute of a `time_offset` resource; `0`, the default, means never. Like a disabled " +
					"user, an expired one and its API tokens cannot sign in.",
				Validators: []validator.Int64{int64validator.AtLeast(0)},
			},
			"password_wo":         password,
			"password_wo_version": passwordVersion,
		},
	}
}

func (r *userResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"userid", "User ID, such as `alice@pbs`."})
}

func (r *userResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig refuses a password for a user of any realm but pbs: PBS
// would hand it to the realm, which either refuses it or — for pam, and
// only from root@pam — changes the host account's password.
func (r *userResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var userID types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("userid"), &userID)...)
	var version types.Int64
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("password_wo_version"), &version)...)
	if resp.Diagnostics.HasError() || userID.IsNull() || userID.IsUnknown() || version.IsNull() {
		return
	}
	if realm := pbsclient.Realm(userID.ValueString()); realm != passwordRealm {
		resp.Diagnostics.AddAttributeError(
			path.Root("password_wo"),
			"Password for a user outside the pbs realm",
			fmt.Sprintf("User %q belongs to the %q realm, which authenticates its users itself; PBS stores "+
				"passwords only for users of the %q realm. Remove password_wo and password_wo_version.",
				userID.ValueString(), realm, passwordRealm),
		)
	}
}

// ModifyPlan refuses at plan time a password change that the provider could
// not make, because it signs in with an API token.
func (r *userResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() || r.data == nil {
		return
	}
	var plan, state userModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || plan.PasswordWOVersion.IsUnknown() ||
		!writeOnlyChanged(plan.PasswordWOVersion, state.PasswordWOVersion) {
		return
	}
	// A changed or unknown userid replaces the user, and the new one gets
	// its password at creation, which an API token may do.
	if !plan.UserID.Equal(state.UserID) {
		return
	}

	client := r.data.client
	if client.UsesAPIToken() {
		resp.Diagnostics.AddAttributeError(path.Root("password_wo_version"), "Cannot change the password with an API token",
			passwordChangeWithTokenDetail(client, plan.UserID.ValueString()))
		return
	}
	if client.AuthID() == plan.UserID.ValueString() {
		resp.Diagnostics.AddAttributeWarning(path.Root("password_wo_version"), "Changing the provider's own password",
			fmt.Sprintf("The provider signs in as %q, the user whose password this plan changes. The provider "+
				"uses the new password for the rest of this run, but its `password` setting is wrong from then "+
				"on: update it before the next run.", client.AuthID()))
	}
}

// passwordChangeWithTokenDetail explains why a password change needs a
// password session.
func passwordChangeWithTokenDetail(client *pbsclient.Client, userID string) string {
	return fmt.Sprintf("Changing password_wo_version asks the provider to change the password of %q, but the "+
		"provider signs in with the API token %q. PBS changes an existing user's password only through PUT "+
		"/access/password, which API tokens cannot call. Either configure the provider with `username` and "+
		"`password` (a second provider block with an alias, used by this resource, will do), change the "+
		"password in PBS and leave password_wo_version as it was, or replace the user with `terraform apply "+
		"-replace` and an unchanged password_wo_version — creation sets the password, but deletes the user's "+
		"API tokens and ACL entries.", userID, client.AuthID())
}

// userDefaults is the model of a user as PBS creates it when a property is
// left out, the prior state of a create.
var userDefaults = userModel{
	Comment:   types.StringNull(),
	Email:     types.StringNull(),
	Firstname: types.StringNull(),
	Lastname:  types.StringNull(),
	Enable:    types.BoolValue(true),
	Expire:    types.Int64Value(0),
}

// changes records the properties that differ between prior and m.
func (m *userModel) changes(prior userModel, c *propertyChanges) {
	c.String("comment", m.Comment, prior.Comment)
	c.String("email", m.Email, prior.Email)
	c.String("firstname", m.Firstname, prior.Firstname)
	c.String("lastname", m.Lastname, prior.Lastname)
	c.Bool("enable", m.Enable, prior.Enable)
	c.Int64("expire", m.Expire, prior.Expire)
}

// fromUser records a user as PBS reports it. The user ID is the one it was
// looked up by. The password's version exists only in Terraform and keeps
// its value; the password itself is never stored.
func (m *userModel) fromUser(userID string, u pbsclient.User) {
	m.ID = types.StringValue(userID)
	m.UserID = types.StringValue(userID)
	m.Comment = stringOrNull(u.Comment)
	m.Email = stringOrNull(u.Email)
	m.Firstname = stringOrNull(u.Firstname)
	m.Lastname = stringOrNull(u.Lastname)
	m.Enable = types.BoolValue(u.Enabled())
	m.Expire = types.Int64Value(u.Expiry())
	m.PasswordWO = types.StringNull()
}

func (r *userResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan userModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	userID := plan.UserID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(userDefaults, changes)
	params := changes.Values()
	params.Set("userid", userID)
	if !plan.PasswordWOVersion.IsNull() {
		password, ok := writeOnlySecret(ctx, req.Config, "password", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing password",
				"password_wo_version is set, but password_wo is not known.")
		}
		params.Set("password", password)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigUsers, func() error { return client.CreateUser(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("userid"), "PBS user already exists",
				fmt.Sprintf("PBS already has a user %q. To manage it with Terraform, import it, with an import "+
					"block whose id is %q or with `terraform import`. %s", userID, userID, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS user", apiErrorDetail(client, userModifyPrivilege, err))
		return
	}

	// From here on the user exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	user, err := client.GetUser(ctx, userID)
	if err != nil {
		plan.ID = types.StringValue(userID)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "userid", userID, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS user back after creation",
			fmt.Sprintf("PBS created user %q, and it was recorded in state, but reading it back failed, so it is "+
				"marked tainted: the next apply replaces it. %s", userID, apiErrorDetail(client, userReadPrivilege, err)))
		return
	}
	plan.fromUser(userID, user)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "userid", userID, &resp.Diagnostics)
}

func (r *userResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state userModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	userID := state.UserID.ValueString()
	// Before the lookup, so that a refresh finding the user gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "userid", userID, &resp.Diagnostics)

	user, err := r.data.client.GetUser(ctx, userID)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS user", apiErrorDetail(r.data.client, userReadPrivilege, err))
		return
	}
	state.fromUser(userID, user)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *userResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state userModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	userID := plan.UserID.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, userDeletable...)
	plan.changes(state, changes)
	changePassword := writeOnlyChanged(plan.PasswordWOVersion, state.PasswordWOVersion)
	var password string
	if changePassword {
		var ok bool
		if password, ok = writeOnlySecret(ctx, req.Config, "password", &resp.Diagnostics); !ok {
			resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing password",
				"password_wo_version changed, but password_wo is not known.")
		}
		// ModifyPlan refuses this already; a version unknown at plan time
		// gets here.
		if client.UsesAPIToken() {
			resp.Diagnostics.AddAttributeError(path.Root("password_wo_version"), "Cannot change the password with an API token",
				passwordChangeWithTokenDetail(client, userID))
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	if !changes.Empty() {
		err := client.WithConfigLock(pbsclient.ConfigUsers, func() error {
			return client.UpdateUser(ctx, userID, changes.Values())
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS user", apiErrorDetail(client, userModifyPrivilege, err))
			return
		}
	}

	// The password goes last: should it fail, the state keeps the old
	// version, and the next apply tries again.
	version := plan.PasswordWOVersion
	if changePassword {
		if err := client.ChangePassword(ctx, userID, password); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Unable to change the PBS user's password",
				fmt.Sprintf("The other changes to user %q were applied, but changing its password failed; the next "+
					"apply tries again. PBS confirms a password change with the password of the user the provider "+
					"signs in as, %q, which needs %s unless it is root@pam. %s",
					userID, client.AuthID(), userModifyPrivilege, apiErrorDetail(client, userModifyPrivilege, err)))
			version = state.PasswordWOVersion
		} else {
			tflog.Info(ctx, "changed the password of a PBS user", map[string]any{"userid": userID})
		}
	}

	user, err := client.GetUser(ctx, userID)
	if err != nil {
		// What was applied is recorded, so that a password already changed
		// is not sent again by the next apply.
		plan.PasswordWOVersion = version
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "userid", userID, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS user back after update",
			fmt.Sprintf("PBS updated user %q, and the change was recorded in state, but reading it back failed. %s",
				userID, apiErrorDetail(client, userReadPrivilege, err)))
		return
	}
	plan.fromUser(userID, user)
	plan.PasswordWOVersion = version
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "userid", userID, &resp.Diagnostics)
}

// Delete removes the user's own ACL entries before the user: PBS would keep
// them, and they would apply again to a user created later under the same ID.
// Removing an entry works for a user that no longer exists, so they are
// removed even when the user was deleted outside Terraform.
func (r *userResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state userModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	userID := state.UserID.ValueString()
	client := r.data.client

	removed, err := removeUserACL(ctx, client, userID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to remove the ACL entries of PBS user",
			fmt.Sprintf("Before deleting user %q, the provider removes its ACL entries, which PBS would otherwise "+
				"keep and apply again to a user created later under the same ID, and that failed; the user was "+
				"not deleted. Reading every ACL entry needs %s, removing them %s. %s", userID, aclReadPrivilege,
				aclModifyPrivilege, apiErrorDetail(client, "", err)))
		return
	}
	if removed > 0 {
		tflog.Info(ctx, "removed the ACL entries of a PBS user before deleting it", map[string]any{"userid": userID, "entries": removed})
	}

	err = client.WithConfigLock(pbsclient.ConfigUsers, func() error { return client.DeleteUser(ctx, userID) })
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS user", apiErrorDetail(client, userModifyPrivilege, err))
	}
}

// errACLHidden means the provider may not read every ACL entry: without
// Sys.Audit on /access/acl, PBS answers GET /access/acl with only the entries
// of the caller's own API tokens, as a success.
var errACLHidden = errors.New("the provider lacks " + aclReadPrivilege + ", so PBS would hide the user's entries from it")

// removeUserACL removes every ACL entry of a user, not of its tokens, and
// returns how many there were. It first makes sure PBS shows it every entry,
// rather than delete the user with its entries hidden and left behind.
func removeUserACL(ctx context.Context, client *pbsclient.Client, userID string) (int, error) {
	permissions, err := client.Permissions(ctx, "", "/access/acl")
	if err != nil {
		return 0, err
	}
	if _, ok := permissions["/access/acl"]["Sys.Audit"]; !ok {
		return 0, errACLHidden
	}

	removed := 0
	err = client.WithConfigLock(pbsclient.ConfigACL, func() error {
		entries, _, err := client.ListACL(ctx, "", false)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.UGID != userID {
				continue
			}
			if err := client.UpdateACL(ctx, pbsclient.ACLChange{Path: e.Path, AuthID: userID, Role: e.RoleID, Delete: true}); err != nil {
				return fmt.Errorf("removing role %s on %s: %w", e.RoleID, e.Path, err)
			}
			removed++
		}
		return nil
	})
	return removed, err
}

// ImportState imports a user by user ID, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops a user that does not exist, which Terraform reports. The
// password cannot be imported: PBS never returns it.
func (r *userResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, values, byIdentity := importedID(ctx, req, &resp.Diagnostics, "userid")
	if resp.Diagnostics.HasError() {
		return
	}
	if byIdentity {
		id = values[0]
	}
	if !userIDPattern.MatchString(id) {
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import a PBS user by its user ID, such as alice@pbs, got "+strconv.Quote(id)+".")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("userid"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	setIdentity(ctx, resp.Identity, "userid", id, &resp.Diagnostics)
}
