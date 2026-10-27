package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &apiTokenResource{}
	_ resource.ResourceWithConfigure      = &apiTokenResource{}
	_ resource.ResourceWithIdentity       = &apiTokenResource{}
	_ resource.ResourceWithImportState    = &apiTokenResource{}
	_ resource.ResourceWithModifyPlan     = &apiTokenResource{}
	_ resource.ResourceWithValidateConfig = &apiTokenResource{}
)

// NewAPITokenResource returns the pbs_api_token resource.
func NewAPITokenResource() resource.Resource { return &apiTokenResource{} }

type apiTokenResource struct {
	data *providerData
}

type apiTokenModel struct {
	ID         types.String `tfsdk:"id"`
	UserID     types.String `tfsdk:"userid"`
	TokenName  types.String `tfsdk:"token_name"`
	TokenID    types.String `tfsdk:"tokenid"`
	Comment    types.String `tfsdk:"comment"`
	Enable     types.Bool   `tfsdk:"enable"`
	Expire     types.Int64  `tfsdk:"expire"`
	Regenerate types.String `tfsdk:"regenerate"`
	Value      types.String `tfsdk:"value"`
}

// apiTokenDeletable are the properties PBS lets a token update delete.
var apiTokenDeletable = []string{"comment"}

// apiTokenDefaults is the model of a token as PBS creates it when a property
// is left out, the prior state of a create.
var apiTokenDefaults = apiTokenModel{
	Comment: types.StringNull(),
	Enable:  types.BoolValue(true),
	Expire:  types.Int64Value(0),
}

func (r *apiTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_token"
}

func (r *apiTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an API token of a Proxmox Backup Server user, such as the token a Proxmox VE " +
			"cluster backs up with. Its ID is `<user ID>!<token name>`, and it authenticates with that ID and its " +
			"secret, `value`.\n\n" +
			"~> **A token has no privileges of its own.** It acts with the intersection of its user's privileges " +
			"and those of ACL entries for the token ID itself, so it needs `pbs_acl` entries whose `auth_id` is " +
			"`tokenid`, besides those of its user. Deleting the token deletes its ACL entries.\n\n" +
			"~> **The secret is stored in state.** PBS shows a token's secret only when it creates the token or " +
			"regenerates its secret, so the provider keeps it in Terraform state, marked sensitive, for other " +
			"resources to use — such as the PBS storage of a Proxmox VE cluster. Protect the state accordingly. " +
			"An imported token has no `value`: change `regenerate` to get a new secret.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `tokenid`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"userid": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "User ID of the user the token belongs to, such as `alice@pbs`. Changing it " +
					"replaces the token.",
				Validators:    userIDValidators(),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"token_name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Name of the token, unique for its user: letters, digits, `_`, `-` and `.`, " +
					"starting with a letter, digit or `_`. Changing it replaces the token.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(tokenNamePattern, "must consist of letters, digits, _, - and ., starting with a letter, digit or _"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"tokenid": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Token ID, `<userid>!<token_name>`, such as `alice@pbs!ci`: what an ACL entry for " +
					"the token names, and the user name it signs in with. Known at plan time.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
			"enable": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether the token may sign in. Defaults to `true`.",
			},
			"expire": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
				MarkdownDescription: "When the token expires, in seconds since the Unix epoch, such as the `unix` " +
					"attribute of a `time_offset` resource; `0`, the default, means never. A token also stops " +
					"working when its user is disabled or expires.",
				Validators: []validator.Int64{int64validator.AtLeast(0)},
			},
			"regenerate": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Any value; changing it to another value — from none included — has PBS " +
					"generate a new secret, and the old one stops working at once. A `time_rotating` resource's " +
					"`id` rotates the secret on a schedule. Removing it changes nothing.",
			},
			"value": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				MarkdownDescription: "The token's secret, as PBS shows it when it creates the token or regenerates " +
					"the secret. A client signs in with `tokenid` and this secret, as the HTTP header " +
					"`Authorization: PBSAPIToken=<tokenid>:<value>`; the provider's own `api_token` takes " +
					"`\"<tokenid>:<value>\"`. Null after an import, until `regenerate` changes.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *apiTokenResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"tokenid", "Token ID, such as `alice@pbs!ci`."})
}

func (r *apiTokenResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig checks the length of the whole token ID, which PBS limits.
func (r *apiTokenResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var userID, name types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("userid"), &userID)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("token_name"), &name)...)
	if resp.Diagnostics.HasError() || userID.IsNull() || userID.IsUnknown() || name.IsNull() || name.IsUnknown() {
		return
	}
	if id := pbsclient.TokenID(userID.ValueString(), name.ValueString()); len(id) > maxAuthIDLength {
		resp.Diagnostics.AddAttributeError(path.Root("token_name"), "Token ID too long",
			fmt.Sprintf("The token ID %q is %d characters long; PBS allows at most %d. Choose a shorter token name.",
				id, len(id), maxAuthIDLength))
	}
}

// ModifyPlan fills in the token ID at plan time, so that ACL entries for the
// token can be planned in full, and marks the secret unknown when the plan
// regenerates it. It warns when the plan takes away the token the provider
// itself signs in with.
func (r *apiTokenResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		if !req.State.Raw.IsNull() {
			var state apiTokenModel
			resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
			r.warnAboutOwnToken(state.TokenID, "Destroying", "it is deleted", &resp.Diagnostics)
		}
		return
	}
	var plan apiTokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.UserID.IsUnknown() && !plan.TokenName.IsUnknown() {
		id := pbsclient.TokenID(plan.UserID.ValueString(), plan.TokenName.ValueString())
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tokenid"), id)...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), id)...)
	}

	if req.State.Raw.IsNull() {
		return
	}
	var state apiTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if regenerates(plan.Regenerate, state.Regenerate) {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("value"), types.StringUnknown())...)
		if r.ownToken(state.TokenID) {
			resp.Diagnostics.AddAttributeWarning(path.Root("regenerate"), "Regenerating the provider's own API token",
				fmt.Sprintf("The provider signs in with the API token %q, whose secret this plan regenerates. PBS "+
					"revokes the old secret at once; the provider uses the new one for the rest of this run, but its "+
					"`api_token` setting is wrong from then on: set it to \"<tokenid>:<value>\" before the next run.",
					state.TokenID.ValueString()))
		}
	}
	if plan.Enable.Equal(types.BoolValue(false)) && !state.Enable.Equal(plan.Enable) {
		r.warnAboutOwnToken(state.TokenID, "Disabling", "it is disabled", &resp.Diagnostics)
	}
}

// ownToken reports whether tokenID is the token the provider signs in with.
func (r *apiTokenResource) ownToken(tokenID types.String) bool {
	return r.data != nil && r.data.client.UsesAPIToken() && r.data.client.AuthID() == tokenID.ValueString()
}

// warnAboutOwnToken warns that a plan takes away the token the provider
// signs in with, so that the rest of the run fails.
func (r *apiTokenResource) warnAboutOwnToken(tokenID types.String, doing, done string, diags *diag.Diagnostics) {
	if !r.ownToken(tokenID) {
		return
	}
	diags.AddWarning(doing+" the provider's own API token",
		fmt.Sprintf("The provider signs in with the API token %q, which this plan takes away: once %s, PBS "+
			"refuses it, and everything the provider does after that in this run fails. Sign the provider in "+
			"with another token or a password to do this.", tokenID.ValueString(), done))
}

// regenerates reports whether a plan regenerates the secret: regenerate is
// set and differs from before. An unknown value counts.
func regenerates(plan, prior types.String) bool {
	return !plan.IsNull() && !plan.Equal(prior)
}

// changes records the properties that differ between prior and m.
func (m *apiTokenModel) changes(prior apiTokenModel, c *propertyChanges) {
	c.String("comment", m.Comment, prior.Comment)
	c.Bool("enable", m.Enable, prior.Enable)
	c.Int64("expire", m.Expire, prior.Expire)
}

// fromToken records a token as PBS reports it. The IDs are the ones it was
// looked up by; regenerate and the secret exist only in Terraform and keep
// their values.
func (m *apiTokenModel) fromToken(userID, tokenName string, t pbsclient.APIToken) {
	id := pbsclient.TokenID(userID, tokenName)
	m.ID = types.StringValue(id)
	m.TokenID = types.StringValue(id)
	m.UserID = types.StringValue(userID)
	m.TokenName = types.StringValue(tokenName)
	m.Comment = stringOrNull(t.Comment)
	m.Enable = types.BoolValue(t.Enabled())
	m.Expire = types.Int64Value(t.Expiry())
	if m.Value.IsUnknown() {
		m.Value = types.StringNull()
	}
}

func (r *apiTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiTokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	userID, name := plan.UserID.ValueString(), plan.TokenName.ValueString()
	tokenID := pbsclient.TokenID(userID, name)
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(apiTokenDefaults, changes)
	if resp.Diagnostics.HasError() {
		return
	}

	var secret string
	err := client.WithConfigLock(pbsclient.ConfigUsers, func() error {
		var err error
		_, secret, err = client.CreateAPIToken(ctx, userID, name, changes.Values())
		return err
	})
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("token_name"), "PBS API token already exists",
				fmt.Sprintf("User %q already has an API token %q. To manage it with Terraform, import it, with an "+
					"import block whose id is %q or with `terraform import`; its secret cannot be imported, so "+
					"change regenerate afterwards to get a new one. %s", userID, name, tokenID, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS API token", apiErrorDetail(client, userModifyPrivilege, err))
		return
	}
	plan.Value = types.StringValue(secret)

	// The secret exists only in this answer, so the token is recorded in
	// state even when reading it back fails: Terraform then marks it
	// tainted, and the secret is not lost while it lasts.
	token, err := client.GetAPIToken(ctx, userID, name)
	if err != nil {
		plan.ID = types.StringValue(tokenID)
		plan.TokenID = types.StringValue(tokenID)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "tokenid", tokenID, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS API token back after creation",
			fmt.Sprintf("PBS created API token %q, and it was recorded in state, but reading it back failed, so it "+
				"is marked tainted: the next apply replaces it. %s", tokenID, apiErrorDetail(client, userReadPrivilege, err)))
		return
	}
	plan.fromToken(userID, name, token)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "tokenid", tokenID, &resp.Diagnostics)
}

func (r *apiTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	userID, name := state.UserID.ValueString(), state.TokenName.ValueString()
	setIdentity(ctx, resp.Identity, "tokenid", pbsclient.TokenID(userID, name), &resp.Diagnostics)

	token, err := r.data.client.GetAPIToken(ctx, userID, name)
	if err != nil {
		// A token whose user is gone is gone too.
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS API token", apiErrorDetail(r.data.client, userReadPrivilege, err))
		return
	}
	state.fromToken(userID, name, token)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *apiTokenResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state apiTokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	userID, name := plan.UserID.ValueString(), plan.TokenName.ValueString()
	tokenID := pbsclient.TokenID(userID, name)
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, apiTokenDeletable...)
	plan.changes(state, changes)
	if resp.Diagnostics.HasError() {
		return
	}
	regenerate := regenerates(plan.Regenerate, state.Regenerate)

	plan.Value = state.Value
	if !changes.Empty() || regenerate {
		var secret string
		err := client.WithConfigLock(pbsclient.ConfigUsers, func() error {
			var err error
			secret, err = client.UpdateAPIToken(ctx, userID, name, changes.Values(), regenerate)
			return err
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS API token", apiErrorDetail(client, userModifyPrivilege, err))
			return
		}
		if regenerate {
			plan.Value = types.StringValue(secret)
			tflog.Info(ctx, "regenerated the secret of a PBS API token", map[string]any{"tokenid": tokenID})
			// PBS revoked the old secret: should it be the provider's own,
			// the provider goes on with the new one.
			if client.UsesAPIToken() && client.AuthID() == tokenID {
				client.UseAPITokenSecret(secret)
			}
		}
	}

	token, err := client.GetAPIToken(ctx, userID, name)
	if err != nil {
		// What was applied is recorded — above all a new secret, which is in
		// no other answer.
		plan.ID = types.StringValue(tokenID)
		plan.TokenID = types.StringValue(tokenID)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "tokenid", tokenID, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS API token back after update",
			fmt.Sprintf("PBS updated API token %q, and the change was recorded in state, but reading it back "+
				"failed. %s", tokenID, apiErrorDetail(client, userReadPrivilege, err)))
		return
	}
	plan.fromToken(userID, name, token)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "tokenid", tokenID, &resp.Diagnostics)
}

// Delete deletes the token, and with it its ACL entries. A token that is
// already gone — with its user, say — is fine.
func (r *apiTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigUsers, func() error {
		return client.DeleteAPIToken(ctx, state.UserID.ValueString(), state.TokenName.ValueString())
	})
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS API token", apiErrorDetail(client, userModifyPrivilege, err))
	}
}

// ImportState imports a token by token ID, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Its secret cannot
// be imported: PBS never shows it again.
func (r *apiTokenResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, values, byIdentity := importedID(ctx, req, &resp.Diagnostics, "tokenid")
	if resp.Diagnostics.HasError() {
		return
	}
	if byIdentity {
		id = values[0]
	}
	userID, name, ok := pbsclient.SplitTokenID(id)
	if !ok || !userIDPattern.MatchString(userID) || !tokenNamePattern.MatchString(name) {
		resp.Diagnostics.AddError("Unexpected import identifier",
			"Import a PBS API token by its token ID, <user ID>!<token name> such as alice@pbs!ci, got "+strconv.Quote(id)+".")
		return
	}
	for attribute, value := range map[string]string{"id": id, "tokenid": id, "userid": userID, "token_name": name} {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(attribute), value)...)
	}
	setIdentity(ctx, resp.Identity, "tokenid", id, &resp.Diagnostics)
}
