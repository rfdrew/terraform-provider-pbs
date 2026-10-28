package provider

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"unicode"

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
	_ resource.Resource                = &gotifyEndpointResource{}
	_ resource.ResourceWithConfigure   = &gotifyEndpointResource{}
	_ resource.ResourceWithIdentity    = &gotifyEndpointResource{}
	_ resource.ResourceWithImportState = &gotifyEndpointResource{}
)

// NewGotifyEndpointResource returns the pbs_notification_endpoint_gotify
// resource.
func NewGotifyEndpointResource() resource.Resource { return &gotifyEndpointResource{} }

type gotifyEndpointResource struct {
	data *providerData
}

type gotifyEndpointModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Server          types.String `tfsdk:"server"`
	TokenWO         types.String `tfsdk:"token_wo"`
	TokenWOVersion  types.Int64  `tfsdk:"token_wo_version"`
	Comment         types.String `tfsdk:"comment"`
	Disable         types.Bool   `tfsdk:"disable"`
	Origin          types.String `tfsdk:"origin"`
	SendTestOnApply types.Bool   `tfsdk:"send_test_on_apply"`
}

// gotifyEndpointDeletable are the properties PBS lets a Gotify endpoint
// update delete. server and the token are not among them.
var gotifyEndpointDeletable = []string{"comment", "disable"}

func (r *gotifyEndpointResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_endpoint_gotify"
}

func (r *gotifyEndpointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	token, tokenVersion := writeOnlySecretAttributes("token",
		"Application token PBS sends the messages with, created in Gotify under Apps.",
		stringvalidator.LengthAtLeast(1),
		noControlOrPadding.secret(),
	)
	// PBS needs a token to create the endpoint, and an endpoint without the
	// right one delivers nothing, so neither can be removed.
	token.Optional, token.Required = false, true
	tokenVersion.Optional, tokenVersion.Required = false, true
	tokenVersion.MarkdownDescription = "Version of `token_wo`, which Terraform stores in its place. Change it — " +
		"increment it, say — to send a new `token_wo`."

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server Gotify notification endpoint: a " +
			"[Gotify](https://gotify.net) server PBS pushes notifications to, as messages of one application. A " +
			"notification reaches an endpoint only through a matcher: route notifications to this one with a " +
			"`pbs_notification_matcher` whose `target` names it.\n\n" +
			"PBS does not contact the server when it saves the endpoint; a wrong setting shows when PBS sends the " +
			"first notification, or at once with `send_test_on_apply`. PBS reaches the server through the HTTP " +
			"proxy in the node's settings, when one is set.\n\n" +
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
					"starting with `.` or `-`. Matchers name it in `target`. Changing it replaces the endpoint.",
				Validators:    safeIDValidators(minNotificationNameLength),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"server": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Base URL of the Gotify server, such as `https://gotify.example.com`, without " +
					"a trailing slash: PBS posts the messages to `<server>/message`.",
				Validators: []validator.String{gotifyServerValidator()},
			},
			"token_wo":         token,
			"token_wo_version": tokenVersion,
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
				MarkdownDescription: "Where the endpoint comes from: `user-created` for every Gotify endpoint, as PBS has no built-in one.",
				PlanModifiers:       []planmodifier.String{userCreatedOrigin{}},
			},
			"send_test_on_apply": sendTestOnApplyAttribute("PBS waits up to 10 seconds for the Gotify server to " +
				"take the message."),
		},
	}
}

// gotifyServerValidator accepts an http:// or https:// URL with a host and
// without a trailing slash, query or fragment, to which PBS appends
// /message.
func gotifyServerValidator() validator.String {
	return stringCheck{
		description: "must be an http:// or https:// URL with a host, without a trailing slash, query or fragment",
		check: func(s string) bool {
			if strings.ContainsFunc(s, unicode.IsSpace) || strings.ContainsAny(s, "?#") || strings.HasSuffix(s, "/") {
				return false
			}
			u, err := url.Parse(s)
			return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil &&
				!strings.ContainsFunc(s, unicode.IsControl)
		},
	}
}

func (r *gotifyEndpointResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Endpoint name, such as `gotify`."})
}

func (r *gotifyEndpointResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// gotifyEndpointDefaults is the model of a Gotify endpoint as PBS creates it
// when a property is left out, the prior state of a create.
var gotifyEndpointDefaults = gotifyEndpointModel{
	Server:  types.StringNull(),
	Comment: types.StringNull(),
	Disable: types.BoolValue(false),
}

// changes records the properties that differ between prior and m. The token
// is not one of them.
func (m *gotifyEndpointModel) changes(prior gotifyEndpointModel, c *propertyChanges) {
	c.String("server", m.Server, prior.Server)
	c.String("comment", m.Comment, prior.Comment)
	c.BoolDefault("disable", m.Disable, prior.Disable, false)
}

// fromGotifyEndpoint records a Gotify endpoint as PBS reports it. The name is
// the one it was looked up by. The token's version and send_test_on_apply
// exist only in Terraform and keep their values; the token itself is never
// stored.
func (m *gotifyEndpointModel) fromGotifyEndpoint(name string, e pbsclient.GotifyEndpoint) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.Server = types.StringValue(e.Server)
	m.TokenWO = types.StringNull()
	m.Comment = stringOrNull(e.Comment)
	m.Disable = boolOr(e.Disable, false)
	m.Origin = stringOr(e.Origin, pbsclient.OriginUserCreated)
	m.SendTestOnApply = sendTestOnApplyOrDefault(m.SendTestOnApply)
}

func (m *gotifyEndpointModel) testPlan() notificationTestPlan {
	return notificationTestPlan{SendTestOnApply: m.SendTestOnApply, Disable: m.Disable}
}

func (r *gotifyEndpointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan gotifyEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(gotifyEndpointDefaults, changes)
	params := changes.Values()
	params.Set("name", name)
	token, ok := writeOnlySecret(ctx, req.Config, "token", &resp.Diagnostics)
	if !ok {
		resp.Diagnostics.AddAttributeError(path.Root("token_wo"), "Missing token", "token_wo is not known.")
	}
	params.Set("token", token)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.CreateGotifyEndpoint(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS notification endpoint or matcher already exists",
				endpointExistsDetail("Gotify", name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS Gotify notification endpoint",
			apiErrorDetail(client, notificationsModifyPrivilege, err))
		return
	}

	// From here on the endpoint exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	endpoint, err := client.GetGotifyEndpoint(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS Gotify notification endpoint back after creation",
			fmt.Sprintf("PBS created Gotify endpoint %q, and it was recorded in state, but reading it back failed, so "+
				"it is marked tainted: the next apply replaces it. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromGotifyEndpoint(name, endpoint)
	if !testCreatedEndpoint(ctx, client, name, plan.testPlan(), client.DeleteGotifyEndpoint, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

func (r *gotifyEndpointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state gotifyEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the endpoint gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	endpoint, err := r.data.client.GetGotifyEndpoint(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS Gotify notification endpoint",
			apiErrorDetail(r.data.client, notificationsReadPrivilege, err))
		return
	}
	state.fromGotifyEndpoint(name, endpoint)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update sends the properties that changed, and the token when its version
// did, in one call.
func (r *gotifyEndpointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state gotifyEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, gotifyEndpointDeletable...)
	plan.changes(state, changes)
	params := changes.Values()
	if writeOnlyChanged(plan.TokenWOVersion, state.TokenWOVersion) {
		token, ok := writeOnlySecret(ctx, req.Config, "token", &resp.Diagnostics)
		if !ok {
			resp.Diagnostics.AddAttributeError(path.Root("token_wo"), "Missing token",
				"token_wo_version changed, but token_wo is not known.")
		}
		params.Set("token", token)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	changed := len(params) > 0
	if changed {
		err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error {
			return client.UpdateGotifyEndpoint(ctx, name, params)
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS Gotify notification endpoint",
				apiErrorDetail(client, notificationsModifyPrivilege, err))
			return
		}
	}

	endpoint, err := client.GetGotifyEndpoint(ctx, name)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS Gotify notification endpoint back after update",
			fmt.Sprintf("PBS updated Gotify endpoint %q, and the change was recorded in state, but reading it back "+
				"failed. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromGotifyEndpoint(name, endpoint)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
	if resp.Diagnostics.HasError() || !changed {
		return
	}
	testChangedEndpoint(ctx, client, name, plan.testPlan(), &resp.Diagnostics)
}

func (r *gotifyEndpointResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state gotifyEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.DeleteGotifyEndpoint(ctx, name) })
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS Gotify notification endpoint",
			notificationDeleteErrorDetail(client, name, err))
	}
}

// ImportState imports a Gotify endpoint by name, given either as the import
// id or, from Terraform 1.12, as the identity of an import block. Read fills
// in the rest, or drops an endpoint that does not exist, which Terraform
// reports. The token cannot be imported: PBS never returns it.
func (r *gotifyEndpointResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "Gotify notification endpoint", "gotify")
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
