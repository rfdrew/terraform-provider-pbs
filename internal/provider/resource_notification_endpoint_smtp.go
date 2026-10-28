package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                     = &smtpEndpointResource{}
	_ resource.ResourceWithConfigure        = &smtpEndpointResource{}
	_ resource.ResourceWithConfigValidators = &smtpEndpointResource{}
	_ resource.ResourceWithIdentity         = &smtpEndpointResource{}
	_ resource.ResourceWithImportState      = &smtpEndpointResource{}
)

// NewSMTPEndpointResource returns the pbs_notification_endpoint_smtp
// resource.
func NewSMTPEndpointResource() resource.Resource { return &smtpEndpointResource{} }

type smtpEndpointResource struct {
	data *providerData
}

type smtpEndpointModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Server            types.String `tfsdk:"server"`
	Port              types.Int64  `tfsdk:"port"`
	Mode              types.String `tfsdk:"mode"`
	Username          types.String `tfsdk:"username"`
	PasswordWO        types.String `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64  `tfsdk:"password_wo_version"`
	FromAddress       types.String `tfsdk:"from_address"`
	Author            types.String `tfsdk:"author"`
	Mailto            types.Set    `tfsdk:"mailto"`
	MailtoUser        types.Set    `tfsdk:"mailto_user"`
	Comment           types.String `tfsdk:"comment"`
	Disable           types.Bool   `tfsdk:"disable"`
	Origin            types.String `tfsdk:"origin"`
	SendTestOnApply   types.Bool   `tfsdk:"send_test_on_apply"`
}

// smtpEndpointDeletable are the properties PBS lets an SMTP endpoint update
// delete. mode, server and from-address are not among them.
var smtpEndpointDeletable = []string{"author", "comment", "disable", "mailto", "mailto-user", "password", "port", "username"}

// SMTP connection security; tls is PBS's default.
const (
	smtpModeInsecure = "insecure"
	smtpModeStartTLS = "starttls"
	smtpModeTLS      = "tls"
)

// Privileges the notification resources need, for error messages.
const (
	notificationsReadPrivilege   = "Sys.Audit on /system/notifications"
	notificationsModifyPrivilege = "Sys.Modify on /system/notifications"
)

// maxAddressLength bounds host names and mail addresses; PBS sets no limit,
// but no valid one is longer.
const maxAddressLength = 255

// The lengths PBS allows for a recipient's mail address or user ID.
const (
	minRecipientLength = 2
	maxRecipientLength = 64
)

func (r *smtpEndpointResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_endpoint_smtp"
}

func (r *smtpEndpointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	password, passwordVersion := writeOnlySecretAttributes("password",
		"Password to authenticate to the SMTP server with, along with `username`, without white space at either "+
			"end, which PBS would drop when it reads the password back.",
		stringvalidator.LengthAtLeast(1),
		stringvalidator.AlsoRequires(path.MatchRoot("username")),
		noControlOrPadding.secret(),
	)

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server SMTP notification endpoint: a mail server PBS " +
			"delivers notifications through — about garbage collection, prune, verify and sync jobs, tape backups, " +
			"package updates and certificates; mails about backups come from Proxmox VE. A notification reaches an " +
			"endpoint only through a matcher: route notifications to " +
			"this one with a `pbs_notification_matcher` whose `target` names it, such as the built-in " +
			"`default-matcher`, imported.\n\n" +
			"PBS does not contact the server when it saves the endpoint; a wrong setting shows when PBS sends the " +
			"first notification, or at once with `send_test_on_apply`. Endpoint and matcher names share one " +
			"namespace.\n\n" +
			"~> **PBS refuses to delete an endpoint a matcher targets.** When a change of `name` replaces an " +
			"endpoint that a `pbs_notification_matcher` targets, set `lifecycle { create_before_destroy = true }` " +
			"on the endpoint, so that the matcher moves to the new endpoint before the old one goes.\n\n" +
			"Managing notification endpoints needs `" + notificationsModifyPrivilege + "`, reading them `" +
			notificationsReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `name`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Endpoint name, 2 to 32 characters: letters, digits, `_`, `.` and `-`, not " +
					"starting with `.` or `-`. Matchers name it in `target`. Changing it replaces the endpoint.",
				Validators:    safeIDValidators(minNotificationNameLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"server": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Host name or IP address of the SMTP server or relay.",
				Validators:          textValidators(1, maxAddressLength),
			},
			"port": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Port of the SMTP server; when left out, the one `mode` implies: 465 for `tls`, " +
					"587 for `starttls`, 25 for `insecure`.",
				Validators: []validator.Int64{int64validator.Between(1, 65535)},
			},
			"mode": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(smtpModeTLS),
				MarkdownDescription: "Connection security: `tls`, the default, for TLS from the start; `starttls`, " +
					"to upgrade a plain connection; `insecure`, for none.",
				Validators: []validator.String{stringvalidator.OneOf(smtpModeTLS, smtpModeStartTLS, smtpModeInsecure)},
			},
			"username": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "User name to authenticate with, by PLAIN or LOGIN; no authentication when left " +
					"out. Requires `password_wo`: PBS fails to send with a user name but no password.",
				Validators: append(textValidators(1, maxAddressLength),
					stringvalidator.AlsoRequires(path.MatchRoot("password_wo"))),
			},
			"password_wo":         password,
			"password_wo_version": passwordVersion,
			"from_address": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Sender address of the mails. A relay may insist that it belongs to " +
					"`username`.",
				Validators: textValidators(1, maxAddressLength),
			},
			"author": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Sender name of the mails, which appear from `<author> <from_address>`; " +
					"`Proxmox Backup Server - <host name>` when left out.",
				Validators: textValidators(1, maxAddressLength),
			},
			"mailto": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Mail addresses to send notifications to. At least one of `mailto` and " +
					"`mailto_user` is required.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(textValidators(minRecipientLength, maxRecipientLength)...),
				},
			},
			"mailto_user": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Users, such as `root@pam`, to send notifications to, at the email address PBS " +
					"has for each.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.NoNullValues(),
					setvalidator.ValueStringsAre(userIDValidators()...),
				},
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
				Computed:            true,
				MarkdownDescription: "Where the endpoint comes from: `user-created` for every SMTP endpoint, as PBS has no built-in one.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"send_test_on_apply": sendTestOnApplyAttribute("PBS waits for the SMTP server to accept the mail, " +
				"which it then delivers or bounces on its own."),
		},
	}
}

func (r *smtpEndpointResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.AtLeastOneOf(path.MatchRoot("mailto"), path.MatchRoot("mailto_user")),
	}
}

func (r *smtpEndpointResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Endpoint name, such as `smtp`."})
}

func (r *smtpEndpointResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// smtpEndpointDefaults is the model of an SMTP endpoint as PBS creates it
// when a property is left out, the prior state of a create.
var smtpEndpointDefaults = smtpEndpointModel{
	Port:       types.Int64Null(),
	Mode:       types.StringValue(smtpModeTLS),
	Username:   types.StringNull(),
	Author:     types.StringNull(),
	Mailto:     types.SetNull(types.StringType),
	MailtoUser: types.SetNull(types.StringType),
	Comment:    types.StringNull(),
	Disable:    types.BoolValue(false),
}

// changes records the properties that differ between prior and m. The
// password is not one of them.
func (m *smtpEndpointModel) changes(prior smtpEndpointModel, c *propertyChanges) {
	c.String("server", m.Server, prior.Server)
	c.Int64("port", m.Port, prior.Port)
	c.String("mode", m.Mode, prior.Mode)
	c.String("username", m.Username, prior.Username)
	c.String("from-address", m.FromAddress, prior.FromAddress)
	c.String("author", m.Author, prior.Author)
	c.StringSet("mailto", m.Mailto, prior.Mailto)
	c.StringSet("mailto-user", m.MailtoUser, prior.MailtoUser)
	c.String("comment", m.Comment, prior.Comment)
	c.BoolDefault("disable", m.Disable, prior.Disable, false)
}

// fromSMTPEndpoint records an SMTP endpoint as PBS reports it. The name is the
// one it was looked up by. The password's version and send_test_on_apply
// exist only in Terraform and keep their values; the password itself is never
// stored.
func (m *smtpEndpointModel) fromSMTPEndpoint(name string, e pbsclient.SMTPEndpoint, diags *diag.Diagnostics) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.Server = types.StringValue(e.Server)
	m.Port = int64OrNull(e.Port)
	m.Mode = stringOr(e.Mode, smtpModeTLS)
	m.Username = stringOrNull(e.Username)
	m.PasswordWO = types.StringNull()
	m.FromAddress = types.StringValue(e.FromAddress)
	m.Author = stringOrNull(e.Author)
	m.Mailto = stringSetOrNull(e.Mailto, diags)
	m.MailtoUser = stringSetOrNull(e.MailtoUser, diags)
	m.Comment = stringOrNull(e.Comment)
	m.Disable = boolOr(e.Disable, false)
	m.Origin = stringOr(e.Origin, pbsclient.OriginUserCreated)
	m.SendTestOnApply = sendTestOnApplyOrDefault(m.SendTestOnApply)
}

func (m *smtpEndpointModel) testPlan() notificationTestPlan {
	return notificationTestPlan{SendTestOnApply: m.SendTestOnApply, Disable: m.Disable}
}

func (r *smtpEndpointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan smtpEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(smtpEndpointDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
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

	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.CreateSMTPEndpoint(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS notification endpoint or matcher already exists",
				fmt.Sprintf("PBS already has a notification endpoint or matcher named %q; endpoints and matchers share "+
					"one namespace. If it is an SMTP endpoint, import it to manage it with Terraform, with an import "+
					"block whose id is %q or with `terraform import`; otherwise choose another name. %s", name, name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS SMTP notification endpoint",
			apiErrorDetail(client, notificationsModifyPrivilege, err))
		return
	}

	// From here on the endpoint exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	endpoint, err := client.GetSMTPEndpoint(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		plan.Origin = types.StringValue(pbsclient.OriginUserCreated)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS SMTP notification endpoint back after creation",
			fmt.Sprintf("PBS created SMTP endpoint %q, and it was recorded in state, but reading it back failed, so it "+
				"is marked tainted: the next apply replaces it. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromSMTPEndpoint(name, endpoint, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() && !testCreatedEndpoint(ctx, client, name, plan.testPlan(), client.DeleteSMTPEndpoint, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

func (r *smtpEndpointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state smtpEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the endpoint gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	endpoint, err := r.data.client.GetSMTPEndpoint(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS SMTP notification endpoint",
			apiErrorDetail(r.data.client, notificationsReadPrivilege, err))
		return
	}
	state.fromSMTPEndpoint(name, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update sends the properties that changed, and the password when its
// version did, in one call.
func (r *smtpEndpointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state smtpEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, smtpEndpointDeletable...)
	plan.changes(state, changes)
	params := changes.Values()
	if writeOnlyChanged(plan.PasswordWOVersion, state.PasswordWOVersion) {
		password, ok := writeOnlySecret(ctx, req.Config, "password", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Missing password",
				"password_wo_version changed, but password_wo is not known.")
		}
		params.Set("password", password)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	changed := len(params) > 0
	if changed {
		err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error {
			return client.UpdateSMTPEndpoint(ctx, name, params)
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS SMTP notification endpoint",
				apiErrorDetail(client, notificationsModifyPrivilege, err))
			return
		}
	}

	endpoint, err := client.GetSMTPEndpoint(ctx, name)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS SMTP notification endpoint back after update",
			fmt.Sprintf("PBS updated SMTP endpoint %q, and the change was recorded in state, but reading it back "+
				"failed. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromSMTPEndpoint(name, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
	if resp.Diagnostics.HasError() || !changed {
		return
	}
	testChangedEndpoint(ctx, client, name, plan.testPlan(), &resp.Diagnostics)
}

func (r *smtpEndpointResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state smtpEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.DeleteSMTPEndpoint(ctx, name) })
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS SMTP notification endpoint",
			notificationDeleteErrorDetail(client, name, err))
	}
}

// notificationDeleteErrorDetail explains why deleting an endpoint failed,
// naming the matchers that still target it when PBS says so.
func notificationDeleteErrorDetail(client *pbsclient.Client, name string, err error) string {
	// 400 "cannot delete 'x', referenced by: matcher1, matcher2".
	var apiErr *pbsclient.Error
	if errors.As(err, &apiErr) && strings.Contains(apiErr.Message, "referenced by") {
		return fmt.Sprintf("Matchers still target endpoint %q, and PBS deletes no endpoint a matcher targets. Remove it "+
			"from their target first. When a change of name replaces the endpoint while a pbs_notification_matcher "+
			"targets it, set lifecycle { create_before_destroy = true } on the endpoint, so that the matcher moves to "+
			"the new endpoint before the old one goes. %s", name, err)
	}
	return apiErrorDetail(client, notificationsModifyPrivilege, err)
}

// ImportState imports an SMTP endpoint by name, given either as the import
// id or, from Terraform 1.12, as the identity of an import block. Read fills
// in the rest, or drops an endpoint that does not exist, which Terraform
// reports. The password cannot be imported: PBS never returns it.
func (r *smtpEndpointResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "SMTP notification endpoint", "smtp")
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
