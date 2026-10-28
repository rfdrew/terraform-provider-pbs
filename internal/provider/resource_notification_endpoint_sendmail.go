package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                     = &sendmailEndpointResource{}
	_ resource.ResourceWithConfigure        = &sendmailEndpointResource{}
	_ resource.ResourceWithConfigValidators = &sendmailEndpointResource{}
	_ resource.ResourceWithIdentity         = &sendmailEndpointResource{}
	_ resource.ResourceWithImportState      = &sendmailEndpointResource{}
)

// NewSendmailEndpointResource returns the
// pbs_notification_endpoint_sendmail resource.
func NewSendmailEndpointResource() resource.Resource { return &sendmailEndpointResource{} }

type sendmailEndpointResource struct {
	data *providerData
}

type sendmailEndpointModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Mailto          types.Set    `tfsdk:"mailto"`
	MailtoUser      types.Set    `tfsdk:"mailto_user"`
	FromAddress     types.String `tfsdk:"from_address"`
	Author          types.String `tfsdk:"author"`
	Comment         types.String `tfsdk:"comment"`
	Disable         types.Bool   `tfsdk:"disable"`
	Origin          types.String `tfsdk:"origin"`
	SendTestOnApply types.Bool   `tfsdk:"send_test_on_apply"`
}

// sendmailEndpointDeletable are the properties PBS lets a sendmail endpoint
// update delete: all of them.
var sendmailEndpointDeletable = []string{"author", "comment", "disable", "from-address", "mailto", "mailto-user"}

func (r *sendmailEndpointResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_endpoint_sendmail"
}

func (r *sendmailEndpointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server sendmail notification endpoint: notifications PBS " +
			"hands, as mail, to the mail transport agent of its host — Postfix on a standard installation — which " +
			"delivers them, or relays them as it is configured to. A notification reaches an endpoint only " +
			"through a matcher: route notifications to this one with a `pbs_notification_matcher` whose `target` " +
			"names it.\n\n" +
			"**The built-in `" + mailToRoot + "`** mails `root@pam` at the email address PBS has for it, and is " +
			"where the built-in `default-matcher` sends notifications. It cannot be created or deleted, only " +
			"changed: manage it by importing it, and destroying the resource resets it to its built-in " +
			"settings.\n\n" +
			"~> **PBS refuses to delete an endpoint a matcher targets.** When a change of `name` replaces an " +
			"endpoint that a `pbs_notification_matcher` targets, set `lifecycle { create_before_destroy = true }` " +
			"on the endpoint, so that the matcher moves to the new endpoint before the old one goes.\n\n" +
			"Endpoint and matcher names share one namespace. Managing notification endpoints needs `" +
			notificationsModifyPrivilege + "`, reading them `" + notificationsReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `name`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Endpoint name, 2 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`; `" + mailToRoot + "` for the built-in endpoint, which must be " +
					"imported. Matchers name it in `target`. Changing it replaces the endpoint.",
				Validators:    safeIDValidators(minNotificationNameLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"mailto": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Mail addresses to send notifications to. At least one of `mailto` and " +
					"`mailto_user` is required.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(textValidators(minRecipientLength, maxRecipientLength)...),
				},
			},
			"mailto_user": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Users, such as `root@pam`, to send notifications to, at the email address PBS " +
					"has for each; a user without one gets nothing.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(userIDValidators()...),
				},
			},
			"from_address": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Sender address of the mails; when left out, the email sender address in the " +
					"node's settings, or `root` at the host when that is not set either.",
				Validators: textValidators(1, maxAddressLength),
			},
			"author": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Sender name of the mails, which appear from `<author> <from_address>`; " +
					"`Proxmox Backup Server - <host name>` when left out.",
				Validators: textValidators(1, maxAddressLength),
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Free-form comment, up to 128 characters on one line.",
				Validators:          textValidators(1, maxCommentLength),
			},
			"disable": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the endpoint is disabled: matchers that target it send nothing through it. Defaults to `false`.",
			},
			"origin": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Where the endpoint comes from: `user-created`; `builtin` for `" + mailToRoot +
					"` with its built-in settings; `modified-builtin` once it is changed.",
				PlanModifiers: []planmodifier.String{userCreatedOrigin{builtin: []string{mailToRoot}}},
			},
			"send_test_on_apply": sendTestOnApplyAttribute("A successful test means that the host's mail " +
				"transport agent accepted the mail, not that it delivered it."),
		},
	}
}

func (r *sendmailEndpointResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.AtLeastOneOf(path.MatchRoot("mailto"), path.MatchRoot("mailto_user")),
	}
}

func (r *sendmailEndpointResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Endpoint name, such as `" + mailToRoot + "`."})
}

func (r *sendmailEndpointResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// sendmailEndpointDefaults is the model of a sendmail endpoint as PBS
// creates it when a property is left out, the prior state of a create.
var sendmailEndpointDefaults = sendmailEndpointModel{
	Mailto:      types.SetNull(types.StringType),
	MailtoUser:  types.SetNull(types.StringType),
	FromAddress: types.StringNull(),
	Author:      types.StringNull(),
	Comment:     types.StringNull(),
	Disable:     types.BoolValue(false),
}

// changes records the properties that differ between prior and m.
func (m *sendmailEndpointModel) changes(prior sendmailEndpointModel, c *propertyChanges) {
	c.StringSet("mailto", m.Mailto, prior.Mailto)
	c.StringSet("mailto-user", m.MailtoUser, prior.MailtoUser)
	c.String("from-address", m.FromAddress, prior.FromAddress)
	c.String("author", m.Author, prior.Author)
	c.String("comment", m.Comment, prior.Comment)
	c.BoolDefault("disable", m.Disable, prior.Disable, false)
}

// fromSendmailEndpoint records a sendmail endpoint as PBS reports it. The
// name is the one it was looked up by; send_test_on_apply exists only in
// Terraform and keeps its value.
func (m *sendmailEndpointModel) fromSendmailEndpoint(name string, e pbsclient.SendmailEndpoint, diags *diag.Diagnostics) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.Mailto = stringSetOrNull(e.Mailto, diags)
	m.MailtoUser = stringSetOrNull(e.MailtoUser, diags)
	m.FromAddress = stringOrNull(e.FromAddress)
	m.Author = stringOrNull(e.Author)
	m.Comment = stringOrNull(e.Comment)
	m.Disable = boolOr(e.Disable, false)
	m.Origin = stringOr(e.Origin, pbsclient.OriginUserCreated)
	m.SendTestOnApply = sendTestOnApplyOrDefault(m.SendTestOnApply)
}

func (m *sendmailEndpointModel) testPlan() notificationTestPlan {
	return notificationTestPlan{SendTestOnApply: m.SendTestOnApply, Disable: m.Disable}
}

func (r *sendmailEndpointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan sendmailEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(sendmailEndpointDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.CreateSendmailEndpoint(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS notification endpoint or matcher already exists",
				endpointExistsDetail("sendmail", name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS sendmail notification endpoint",
			apiErrorDetail(client, notificationsModifyPrivilege, err))
		return
	}

	// From here on the endpoint exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	endpoint, err := client.GetSendmailEndpoint(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		plan.Origin = types.StringValue(pbsclient.OriginUserCreated)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS sendmail notification endpoint back after creation",
			fmt.Sprintf("PBS created sendmail endpoint %q, and it was recorded in state, but reading it back failed, "+
				"so it is marked tainted: the next apply replaces it. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromSendmailEndpoint(name, endpoint, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() && !testCreatedEndpoint(ctx, client, name, plan.testPlan(), client.DeleteSendmailEndpoint, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

func (r *sendmailEndpointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state sendmailEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the endpoint gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	endpoint, err := r.data.client.GetSendmailEndpoint(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS sendmail notification endpoint",
			apiErrorDetail(r.data.client, notificationsReadPrivilege, err))
		return
	}
	state.fromSendmailEndpoint(name, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *sendmailEndpointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state sendmailEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, sendmailEndpointDeletable...)
	plan.changes(state, changes)
	if resp.Diagnostics.HasError() {
		return
	}
	changed := !changes.Empty()
	if changed {
		err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error {
			return client.UpdateSendmailEndpoint(ctx, name, changes.Values())
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS sendmail notification endpoint",
				apiErrorDetail(client, notificationsModifyPrivilege, err))
			return
		}
	}

	endpoint, err := client.GetSendmailEndpoint(ctx, name)
	if err != nil {
		// origin may be unknown in the plan, and state must not be.
		if plan.Origin.IsUnknown() {
			plan.Origin = state.Origin
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS sendmail notification endpoint back after update",
			fmt.Sprintf("PBS updated sendmail endpoint %q, and the change was recorded in state, but reading it back "+
				"failed. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromSendmailEndpoint(name, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
	if resp.Diagnostics.HasError() || !changed {
		return
	}
	testChangedEndpoint(ctx, client, name, plan.testPlan(), &resp.Diagnostics)
}

// Delete deletes the endpoint. PBS answers the same for mail-to-root, which
// it resets to its built-in settings instead: it stays, as PBS keeps it.
func (r *sendmailEndpointResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state sendmailEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.DeleteSendmailEndpoint(ctx, name) })
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS sendmail notification endpoint",
			notificationDeleteErrorDetail(client, name, err))
		return
	}
	if name == mailToRoot {
		tflog.Info(ctx, "reset the built-in PBS notification endpoint to its built-in settings", map[string]any{"name": name})
	}
}

// ImportState imports a sendmail endpoint, mail-to-root included, by name,
// given either as the import id or, from Terraform 1.12, as the identity of
// an import block. Read fills in the rest, or drops an endpoint that does not
// exist, which Terraform reports.
func (r *sendmailEndpointResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "sendmail notification endpoint", mailToRoot)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	// The default, so that importing plans no change for a configuration
	// that leaves it out.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("send_test_on_apply"), false)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
