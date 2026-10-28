package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &webhookEndpointResource{}
	_ resource.ResourceWithConfigure   = &webhookEndpointResource{}
	_ resource.ResourceWithIdentity    = &webhookEndpointResource{}
	_ resource.ResourceWithImportState = &webhookEndpointResource{}
)

// NewWebhookEndpointResource returns the pbs_notification_endpoint_webhook
// resource.
func NewWebhookEndpointResource() resource.Resource { return &webhookEndpointResource{} }

type webhookEndpointResource struct {
	data *providerData
}

// A webhook endpoint keeps its headers in its section of notifications.cfg
// and its secrets apart, in notifications-priv.cfg, both as property strings
// whose values are base64 (pbsclient.FormatNotificationKeyValue); its body is
// base64 too. The schema shows all of them as text, which the provider
// encodes and decodes.
//
// PBS never returns a secret's value, and a PUT that carries secrets
// replaces them all, keeping the value PBS has for each one sent by name
// alone. So the secrets are a list of objects whose value is write-only and
// whose name and value version are in state: a change of the list sends
// every secret, with its value only when it is new or its version changed.

type webhookEndpointModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	URL             types.String `tfsdk:"url"`
	Method          types.String `tfsdk:"method"`
	Body            types.String `tfsdk:"body"`
	Header          types.List   `tfsdk:"header"`
	Secret          types.List   `tfsdk:"secret"`
	Comment         types.String `tfsdk:"comment"`
	Disable         types.Bool   `tfsdk:"disable"`
	Origin          types.String `tfsdk:"origin"`
	SendTestOnApply types.Bool   `tfsdk:"send_test_on_apply"`
}

// The objects of header and secret.
var (
	webhookHeaderAttrTypes = map[string]attr.Type{"name": types.StringType, "value": types.StringType}
	webhookSecretAttrTypes = map[string]attr.Type{
		"name": types.StringType, "value_wo": types.StringType, "value_wo_version": types.Int64Type,
	}
	webhookHeaderType = types.ObjectType{AttrTypes: webhookHeaderAttrTypes}
	webhookSecretType = types.ObjectType{AttrTypes: webhookSecretAttrTypes}
)

// webhookEndpointDeletable are the properties PBS lets a webhook endpoint
// update delete. url and method are not among them.
var webhookEndpointDeletable = []string{"body", "comment", "disable", "header", "secret"}

// HTTP methods a webhook can use; post is PBS's default.
const (
	webhookMethodPost = "post"
	webhookMethodPut  = "put"
	webhookMethodGet  = "get"
)

var (
	// headerNamePattern is an HTTP header name, a token of RFC 9110.
	headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	// secretNamePattern is a secret name a template can use as
	// {{ secrets.<name> }}.
	secretNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

func (r *webhookEndpointResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_endpoint_webhook"
}

func (r *webhookEndpointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server webhook notification endpoint: an HTTP request PBS " +
			"makes for every notification, to any service that takes one — a chat, a push service, an incident " +
			"tool. A notification reaches an endpoint only through a matcher: route notifications to this one " +
			"with a `pbs_notification_matcher` whose `target` names it.\n\n" +
			"`url`, the header values and `body` are [Handlebars](https://handlebarsjs.com) templates, rendered " +
			"for each notification with `{{ title }}`, `{{ message }}`, `{{ severity }}`, `{{ timestamp }}`, the " +
			"notification's metadata fields as `{{ fields.<name> }}` and the endpoint's secrets as " +
			"`{{ secrets.<name> }}`, and the helpers `{{ url-encode … }}`, `{{ escape … }}` (for a JSON string) " +
			"and `{{ json … }}`. In Terraform strings, write `{{` as is, but `${` as `$${`.\n\n" +
			"PBS does not contact the URL when it saves the endpoint; a wrong setting shows when PBS sends the " +
			"first notification, or at once with `send_test_on_apply`. PBS goes through the HTTP proxy in the " +
			"node's settings, when one is set, and treats any answer but a 2xx as a failure.\n\n" +
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
			"url": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "URL to send the request to, `http://` or `https://`, with an optional port; " +
					"its path and query may use templates, such as `https://ntfy.example.com/{{ secrets.topic }}`. " +
					"PBS checks the host and port.",
				Validators: []validator.String{webhookURLValidator()},
			},
			"method": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(webhookMethodPost),
				MarkdownDescription: "HTTP method: `post`, the default, `put` or `get`.",
				Validators:          []validator.String{stringvalidator.OneOf(webhookMethodPost, webhookMethodPut, webhookMethodGet)},
			},
			"body": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Body of the request, a template, such as a JSON document; none when left " +
					"out. Send it with a `Content-Type` header that says what it is. PBS stores it base64-encoded; " +
					"the provider encodes and decodes it.",
				Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"header": schema.ListNestedAttribute{
				Optional: true,
				MarkdownDescription: "HTTP headers of the request, in order, such as `{ name = \"Content-Type\", " +
					"value = \"application/json\" }`. A name may appear more than once. PBS stores the values " +
					"base64-encoded; the provider encodes and decodes them. A header that holds a credential should " +
					"take it from a secret, as `{{ secrets.<name> }}`: header values are stored as they are given " +
					"and readable through the API.",
				Validators: []validator.List{listvalidator.SizeAtLeast(1), listvalidator.NoNullValues()},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Header name, such as `Authorization`.",
						Validators: []validator.String{
							stringvalidator.LengthBetween(1, 256),
							stringvalidator.RegexMatches(headerNamePattern, "must be an HTTP header name: letters, digits and !#$%&'*+-.^_`|~"),
						},
					},
					"value": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Header value, a template, such as `Bearer {{ secrets.token }}`.",
						Validators:          []validator.String{stringvalidator.LengthAtLeast(1), noControlOrPadding},
					},
				}},
			},
			"secret": schema.ListNestedAttribute{
				Optional: true,
				MarkdownDescription: "Secrets the templates of `url`, the headers and `body` can use as " +
					"`{{ secrets.<name> }}`. PBS keeps them in a file only root reads, never returns their values, " +
					"and masks the values in its logs and error messages — but only as they are: a value a helper " +
					"such as `url-encode` changed is not masked, which the provider makes up for in the errors it " +
					"shows. The values are write-only: Terraform passes " +
					"them to PBS without storing them in the plan or state, so a change made outside Terraform goes " +
					"unnoticed. PBS receives a secret's value when the secret is created — with the endpoint, or " +
					"when it is added to the list — and whenever its `value_wo_version` changes; every other secret " +
					"keeps the value PBS has. Removing a secret from the list removes it from PBS, and PBS's " +
					"secrets that the list does not name show as a change that removes them. Needs Terraform or " +
					"OpenTofu 1.11 or later.",
				Validators: []validator.List{listvalidator.SizeAtLeast(1), listvalidator.NoNullValues(), uniqueSecretNames{}},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Secret name, unique in the list: letters, digits, `_` and `-`.",
						Validators: []validator.String{
							stringvalidator.LengthBetween(1, 64),
							stringvalidator.RegexMatches(secretNamePattern, "must be letters, digits, _ and -"),
						},
					},
					"value_wo": schema.StringAttribute{
						Required:            true,
						WriteOnly:           true,
						Sensitive:           true,
						MarkdownDescription: "Value of the secret. Write-only: PBS receives it as `value_wo_version` says.",
						Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
					},
					"value_wo_version": schema.Int64Attribute{
						Required: true,
						MarkdownDescription: "Version of `value_wo`, which Terraform stores in its place. Change it — " +
							"increment it, say — to send a new `value_wo`.",
					},
				}},
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
				MarkdownDescription: "Where the endpoint comes from: `user-created` for every webhook endpoint, as PBS has no built-in one.",
				PlanModifiers:       []planmodifier.String{userCreatedOrigin{}},
			},
			"send_test_on_apply": sendTestOnApplyAttribute("PBS waits up to 10 seconds for an answer. The test " +
				"notification has severity `info` and no metadata fields: `{{ fields.<name> }}` renders empty, " +
				"`{{ json fields.<name> }}` renders `null`, and `escape` or `url-encode` given one, such as " +
				"`{{ escape fields.datastore }}`, fails the test."),
		},
	}
}

// webhookURLValidator accepts an http:// or https:// URL on one line, which
// may hold templates; PBS checks the host and port.
func webhookURLValidator() validator.String {
	return stringCheck{
		description: "must be an http:// or https:// URL without white space at either end or control characters",
		check: func(s string) bool {
			rest, ok := strings.CutPrefix(s, "https://")
			if !ok {
				rest, ok = strings.CutPrefix(s, "http://")
			}
			return ok && rest != "" && !strings.ContainsFunc(s, unicode.IsControl) && strings.TrimSpace(s) == s
		},
	}
}

// uniqueSecretNames refuses a secret list that names one secret twice, which
// PBS refuses on update but not on create.
type uniqueSecretNames struct{}

func (uniqueSecretNames) Description(_ context.Context) string {
	return "secret names must be unique"
}

func (v uniqueSecretNames) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (uniqueSecretNames) ValidateList(_ context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	seen := map[string]bool{}
	for i, element := range req.ConfigValue.Elements() {
		object, ok := element.(types.Object)
		if !ok || object.IsNull() || object.IsUnknown() {
			continue
		}
		name, ok := object.Attributes()["name"].(types.String)
		if !ok || name.IsNull() || name.IsUnknown() {
			continue
		}
		if seen[name.ValueString()] {
			resp.Diagnostics.AddAttributeError(req.Path.AtListIndex(i).AtName("name"), "Duplicate secret name",
				fmt.Sprintf("The secret %q is in the list more than once; secret names must be unique.", name.ValueString()))
		}
		seen[name.ValueString()] = true
	}
}

func (r *webhookEndpointResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "Endpoint name, such as `webhook`."})
}

func (r *webhookEndpointResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// webhookEndpointDefaults is the model of a webhook endpoint as PBS creates
// it when a property is left out, the prior state of a create. PBS requires
// url and method, so they are always sent.
var webhookEndpointDefaults = webhookEndpointModel{
	URL:     types.StringNull(),
	Method:  types.StringNull(),
	Body:    types.StringNull(),
	Header:  types.ListNull(webhookHeaderType),
	Secret:  types.ListNull(webhookSecretType),
	Comment: types.StringNull(),
	Disable: types.BoolValue(false),
}

// changes records the properties that differ between prior and m, the
// secrets included, whose values come from config.
func (m *webhookEndpointModel) changes(ctx context.Context, prior webhookEndpointModel, config tfsdk.Config, c *propertyChanges, diags *diag.Diagnostics) {
	c.String("url", m.URL, prior.URL)
	c.String("method", m.Method, prior.Method)
	c.change("body", m.Body, prior.Body, func() string {
		return base64.StdEncoding.EncodeToString([]byte(m.Body.ValueString()))
	})
	c.changeValues("header", m.Header, prior.Header, func() []string {
		var headers []string
		for _, h := range listObjects(m.Header) {
			value := stringAttr(h, "value").ValueString()
			headers = append(headers, pbsclient.FormatNotificationKeyValue(stringAttr(h, "name").ValueString(), &value))
		}
		return headers
	})
	c.changeValues("secret", m.Secret, prior.Secret, func() []string {
		return webhookSecrets(ctx, m.Secret, prior.Secret, config, diags)
	})
	c.String("comment", m.Comment, prior.Comment)
	c.BoolDefault("disable", m.Disable, prior.Disable, false)
}

// webhookSecrets returns the secret parameter of a change from prior to
// planned: every planned secret, with its value from config when it is new
// or its version differs from the prior one, by name alone otherwise, which
// keeps the value PBS has.
func webhookSecrets(ctx context.Context, planned, prior types.List, config tfsdk.Config, diags *diag.Diagnostics) []string {
	priorVersions := map[string]types.Int64{}
	for _, s := range listObjects(prior) {
		priorVersions[stringAttr(s, "name").ValueString()] = int64Attr(s, "value_wo_version")
	}
	var configured types.List
	diags.Append(config.GetAttribute(ctx, path.Root("secret"), &configured)...)
	values := map[string]types.String{}
	for _, s := range listObjects(configured) {
		values[stringAttr(s, "name").ValueString()] = stringAttr(s, "value_wo")
	}

	var secrets []string
	for i, s := range listObjects(planned) {
		name, version := stringAttr(s, "name").ValueString(), int64Attr(s, "value_wo_version")
		if prior, ok := priorVersions[name]; ok && !prior.IsNull() && prior.Equal(version) {
			secrets = append(secrets, pbsclient.FormatNotificationKeyValue(name, nil))
			continue
		}
		value, ok := values[name]
		if !ok || value.IsNull() || value.IsUnknown() {
			diags.AddAttributeError(path.Root("secret").AtListIndex(i).AtName("value_wo"), "Missing secret value",
				fmt.Sprintf("The secret %q is new or its value_wo_version changed, but its value_wo is not known.", name))
			continue
		}
		v := value.ValueString()
		secrets = append(secrets, pbsclient.FormatNotificationKeyValue(name, &v))
	}
	return secrets
}

// listObjects returns the objects of a known list of objects; none for a null
// or unknown one.
func listObjects(list types.List) []types.Object {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var objects []types.Object
	for _, element := range list.Elements() {
		if object, ok := element.(types.Object); ok && !object.IsNull() && !object.IsUnknown() {
			objects = append(objects, object)
		}
	}
	return objects
}

func stringAttr(object types.Object, name string) types.String {
	if v, ok := object.Attributes()[name].(types.String); ok {
		return v
	}
	return types.StringNull()
}

func int64Attr(object types.Object, name string) types.Int64 {
	if v, ok := object.Attributes()[name].(types.Int64); ok {
		return v
	}
	return types.Int64Null()
}

// fromWebhookEndpoint records a webhook endpoint as PBS reports it. The name
// is the one it was looked up by. The secrets are those PBS has, each with
// the version m has for its name, or none; send_test_on_apply exists only in
// Terraform and keeps its value.
func (m *webhookEndpointModel) fromWebhookEndpoint(name string, e pbsclient.WebhookEndpoint, diags *diag.Diagnostics) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	m.URL = types.StringValue(e.URL)
	m.Method = stringOr(e.Method, webhookMethodPost)
	m.Body = types.StringNull()
	if e.Body != "" {
		body, err := pbsclient.DecodeNotificationBase64(e.Body)
		if err != nil {
			diags.AddWarning("PBS webhook body is not base64",
				fmt.Sprintf("PBS has a body for webhook endpoint %q that is not base64-encoded text, as PBS expects: %s. It is "+
					"shown as stored, and the next apply that changes it writes body encoded.", name, err))
			body = e.Body
		}
		m.Body = types.StringValue(body)
	}

	var headers []attr.Value
	for _, h := range e.Header {
		p, err := pbsclient.ParsePropertyString(h, "")
		if err != nil || p["name"] == "" {
			diags.AddWarning("Unexpected PBS webhook header",
				fmt.Sprintf("PBS has a header for webhook endpoint %q the provider cannot read, %q; it is left out, and the "+
					"next apply that changes the headers replaces it.", name, h))
			continue
		}
		value := types.StringNull()
		if raw, ok := p["value"]; ok {
			decoded, err := pbsclient.DecodeNotificationBase64(raw)
			if err != nil {
				diags.AddWarning("PBS webhook header is not base64",
					fmt.Sprintf("PBS has a value for header %q of webhook endpoint %q that is not base64-encoded text, as "+
						"PBS expects: %s. It is shown as stored.", p["name"], name, err))
				decoded = raw
			}
			value = types.StringValue(decoded)
		}
		headers = append(headers, types.ObjectValueMust(webhookHeaderAttrTypes, map[string]attr.Value{
			"name": types.StringValue(p["name"]), "value": value,
		}))
	}
	m.Header = objectListOrNull(webhookHeaderType, headers, diags)

	versions := map[string]types.Int64{}
	for _, s := range listObjects(m.Secret) {
		versions[stringAttr(s, "name").ValueString()] = int64Attr(s, "value_wo_version")
	}
	var secrets []attr.Value
	for _, s := range e.Secret {
		secretName, _, err := pbsclient.ParseNotificationKeyValue(s)
		if err != nil {
			diags.AddWarning("Unexpected PBS webhook secret",
				fmt.Sprintf("PBS has a secret for webhook endpoint %q the provider cannot read: %s. It is left out, and the "+
					"next apply that changes the secrets removes it.", name, err))
			continue
		}
		version, ok := versions[secretName]
		if !ok {
			version = types.Int64Null()
		}
		secrets = append(secrets, types.ObjectValueMust(webhookSecretAttrTypes, map[string]attr.Value{
			"name": types.StringValue(secretName), "value_wo": types.StringNull(), "value_wo_version": version,
		}))
	}
	m.Secret = objectListOrNull(webhookSecretType, secrets, diags)

	m.Comment = stringOrNull(e.Comment)
	m.Disable = boolOr(e.Disable, false)
	m.Origin = stringOr(e.Origin, pbsclient.OriginUserCreated)
	m.SendTestOnApply = sendTestOnApplyOrDefault(m.SendTestOnApply)
}

// objectListOrNull is a list of objects, or null for none.
func objectListOrNull(typ types.ObjectType, elements []attr.Value, diags *diag.Diagnostics) types.List {
	if len(elements) == 0 {
		return types.ListNull(typ)
	}
	list, d := types.ListValue(typ, elements)
	diags.Append(d...)
	return list
}

func (m *webhookEndpointModel) testPlan() notificationTestPlan {
	return notificationTestPlan{SendTestOnApply: m.SendTestOnApply, Disable: m.Disable}
}

func (r *webhookEndpointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan webhookEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics)
	plan.changes(ctx, webhookEndpointDefaults, req.Config, changes, &resp.Diagnostics)
	params := changes.Values()
	params.Set("name", name)
	if resp.Diagnostics.HasError() {
		return
	}

	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.CreateWebhookEndpoint(ctx, params) })
	if err != nil {
		if pbsclient.IsAlreadyExists(err) {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS notification endpoint or matcher already exists",
				endpointExistsDetail("webhook", name, err))
			return
		}
		resp.Diagnostics.AddError("Unable to create PBS webhook notification endpoint",
			apiErrorDetail(client, notificationsModifyPrivilege, err))
		return
	}

	// From here on the endpoint exists, so it is recorded in state even when
	// reading it back fails: Terraform then marks it tainted instead of
	// losing track of it.
	endpoint, err := client.GetWebhookEndpoint(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS webhook notification endpoint back after creation",
			fmt.Sprintf("PBS created webhook endpoint %q, and it was recorded in state, but reading it back failed, so "+
				"it is marked tainted: the next apply replaces it. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromWebhookEndpoint(name, endpoint, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() && !testCreatedEndpoint(ctx, client, name, plan.testPlan(), client.DeleteWebhookEndpoint,
		&resp.Diagnostics, configuredSecretValues(ctx, req.Config, &resp.Diagnostics)...) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// configuredSecretValues returns the values of the secrets config sets, to
// keep out of errors.
func configuredSecretValues(ctx context.Context, config tfsdk.Config, diags *diag.Diagnostics) []string {
	var configured types.List
	diags.Append(config.GetAttribute(ctx, path.Root("secret"), &configured)...)
	var values []string
	for _, s := range listObjects(configured) {
		if v := stringAttr(s, "value_wo"); !v.IsNull() && !v.IsUnknown() {
			values = append(values, v.ValueString())
		}
	}
	return values
}

func (r *webhookEndpointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state webhookEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	// Before the lookup, so that a refresh finding the endpoint gone still
	// reports one; see setIdentity.
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	endpoint, err := r.data.client.GetWebhookEndpoint(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS webhook notification endpoint",
			apiErrorDetail(r.data.client, notificationsReadPrivilege, err))
		return
	}
	state.fromWebhookEndpoint(name, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update sends the properties that changed in one call, the secrets as
// webhookSecrets says.
func (r *webhookEndpointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state webhookEndpointModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	changes := newPropertyChanges(&resp.Diagnostics, webhookEndpointDeletable...)
	plan.changes(ctx, state, req.Config, changes, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	changed := !changes.Empty()
	if changed {
		err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error {
			return client.UpdateWebhookEndpoint(ctx, name, changes.Values())
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update PBS webhook notification endpoint",
				apiErrorDetail(client, notificationsModifyPrivilege, err))
			return
		}
	}

	endpoint, err := client.GetWebhookEndpoint(ctx, name)
	if err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS webhook notification endpoint back after update",
			fmt.Sprintf("PBS updated webhook endpoint %q, and the change was recorded in state, but reading it back "+
				"failed. %s", name, apiErrorDetail(client, notificationsReadPrivilege, err)))
		return
	}
	plan.fromWebhookEndpoint(name, endpoint, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
	if resp.Diagnostics.HasError() || !changed {
		return
	}
	testChangedEndpoint(ctx, client, name, plan.testPlan(), &resp.Diagnostics, configuredSecretValues(ctx, req.Config, &resp.Diagnostics)...)
}

func (r *webhookEndpointResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state webhookEndpointModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	err := client.WithConfigLock(pbsclient.ConfigNotifications, func() error { return client.DeleteWebhookEndpoint(ctx, name) })
	if err != nil && !pbsclient.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete PBS webhook notification endpoint",
			notificationDeleteErrorDetail(client, name, err))
	}
}

// ImportState imports a webhook endpoint by name, given either as the import
// id or, from Terraform 1.12, as the identity of an import block. Read fills
// in the rest, or drops an endpoint that does not exist, which Terraform
// reports. The secrets' values cannot be imported: PBS never returns them,
// so their versions are null and the first apply sends every value.
func (r *webhookEndpointResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "webhook notification endpoint", "webhook")
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
