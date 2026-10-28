package provider

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &acmeAccountResource{}
	_ resource.ResourceWithConfigure   = &acmeAccountResource{}
	_ resource.ResourceWithIdentity    = &acmeAccountResource{}
	_ resource.ResourceWithImportState = &acmeAccountResource{}
	_ resource.ResourceWithModifyPlan  = &acmeAccountResource{}
)

// NewACMEAccountResource returns the pbs_acme_account resource.
func NewACMEAccountResource() resource.Resource { return &acmeAccountResource{} }

type acmeAccountResource struct {
	data *providerData
}

type acmeAccountModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Contact   types.String `tfsdk:"contact"`
	Directory types.String `tfsdk:"directory"`
	ToSURL    types.String `tfsdk:"tos_url"`
	Location  types.String `tfsdk:"location"`
	Status    types.String `tfsdk:"status"`
}

// certificatesPrivilege is what managing ACME accounts, plugins and the
// node's certificate needs.
const certificatesPrivilege = "Sys.Modify on /system/certificates"

// acmeAccountNamePattern is the name of an ACME account: a safe ID, which
// PBS also uses as the account's file name.
var acmeAccountNamePattern = safeIDPattern

func (r *acmeAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_account"
}

func (r *acmeAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server ACME account: an account at a certificate authority " +
			"such as Let's Encrypt, which the node uses to order the certificate of its web interface and API " +
			"(`pbs_node_certificate`), named in its ACME settings (`pbs_node_acme`).\n\n" +
			"Creating the resource has PBS register the account at the CA; PBS keeps the account's key. A new " +
			"`contact` is sent to the CA in place, and a new `tos_url` only recorded; a new `name` or `directory` " +
			"registers a new account.\n\n" +
			"~> **Destroying the resource deactivates the account at the CA, which cannot be undone.** The CA " +
			"refuses every later request of the account; certificates it issued stay valid until they expire, " +
			"but PBS can no longer renew them with this account. Replacing the resource — a new `name` or " +
			"`directory` — deactivates the old account the same way.\n\n" +
			"Let's Encrypt stopped storing contact addresses in June 2025: it takes the address at registration " +
			"but neither keeps nor returns it, and ignores changes. The provider therefore keeps `contact` as " +
			"configured, and reports a change made outside Terraform only for a CA that returns its contacts.\n\n" +
			"Managing ACME accounts needs `" + certificatesPrivilege + "`. Registering, updating and deactivating " +
			"an account runs as a PBS task; the provider waits for it, up to `task_timeout`, and reports the CA's " +
			"error when it fails.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `name`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Account name in PBS, such as `default` — the account PBS uses when the node's " +
					"ACME settings name none. Letters, digits, `_`, `.` and `-`, not starting with `.` or `-`. " +
					"Changing it registers a new account and deactivates the old one.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, maxSafeIDLength),
					stringvalidator.RegexMatches(acmeAccountNamePattern, "must start with a letter, a digit or an underscore, followed by letters, digits, underscores, dots and hyphens"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"contact": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Email address to register with the CA, or several separated by commas, such as " +
					"`ops@example.org`. Changes in place: PBS sends the new addresses to the CA. Let's Encrypt " +
					"refuses addresses at `example.com`, `example.net` and `example.org`.",
				Validators: []validator.String{contactValidator()},
			},
			"directory": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(pbsclient.DefaultACMEDirectory),
				MarkdownDescription: "URL of the CA's ACME directory. Defaults to Let's Encrypt's production directory, " +
					"`" + pbsclient.DefaultACMEDirectory + "`; set `" + pbsclient.ACMEStagingDirectory + "` to try " +
					"things out with Let's Encrypt's staging directory, whose certificates browsers do not trust " +
					"and whose rate limits are far higher. PBS itself must reach the directory, and trust its TLS " +
					"certificate. CAs that require External Account Binding, such as ZeroSSL or Google Trust Services, " +
					"are not supported yet. Changing it registers a new account and deactivates the old one.",
				Validators:    []validator.String{httpsURLValidator()},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"tos_url": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "URL of the CA's terms of service; setting it agrees to them, which Let's " +
					"Encrypt requires. The `pbs_acme_tos` data source reads the current URL from the directory. " +
					"PBS records the agreement at registration only: a new URL later — Let's Encrypt publishes a " +
					"new one with each version of its subscriber agreement, and applies it to existing accounts — " +
					"is recorded in state without contacting the CA, and does not register a new account.",
				Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"location": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "URL of the account at the CA.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseNonNullStateForUnknown()},
			},
			"status": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Status of the account, as the CA last reported it to PBS: `valid`, or " +
					"`deactivated` or `revoked`. PBS does not ask the CA again when it is read.",
			},
		},
	}
}

// contactValidator checks the email addresses of contact: one or more,
// separated by commas, each one an address without a display name.
func contactValidator() validator.String {
	return stringCheck{
		description: "must be one or more email addresses separated by commas, such as ops@example.org",
		check: func(s string) bool {
			addresses := splitContact(s)
			if len(addresses) == 0 {
				return false
			}
			for _, address := range addresses {
				parsed, err := mail.ParseAddress(address)
				if err != nil || parsed.Address != address || parsed.Name != "" {
					return false
				}
			}
			return true
		},
	}
}

// splitContact splits contact addresses at commas, semicolons and white
// space, leaving out empty parts. PBS splits at commas, semicolons and spaces
// too, but keeps empty parts, which it sends to the CA as empty addresses
// the CA refuses, so the provider sends normalContact instead of the
// configured text.
func splitContact(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == 0
	})
}

// normalContact is contact as the provider sends it: the addresses separated
// by single commas.
func normalContact(contact types.String) string {
	return strings.Join(splitContact(contact.ValueString()), ",")
}

// sameContacts reports whether two lists of addresses hold the same
// addresses, in any order and case.
func sameContacts(a, b []string) bool {
	normalise := func(addresses []string) []string {
		out := make([]string, 0, len(addresses))
		for _, address := range addresses {
			out = append(out, strings.ToLower(address))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(normalise(a), normalise(b))
}

func (r *acmeAccountResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"name", "ACME account name, such as `default`."})
}

func (r *acmeAccountResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan warns that destroying the account, also to replace it,
// deactivates it at the CA for good.
func (r *acmeAccountResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() {
		return
	}
	var state acmeAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	replaced := req.Plan.Raw.IsNull()
	if !replaced {
		var plan acmeAccountModel
		resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
		if resp.Diagnostics.HasError() {
			return
		}
		replaced = !plan.Name.Equal(state.Name) || !plan.Directory.Equal(state.Directory)
	}
	if replaced {
		resp.Diagnostics.AddWarning("Destroying the ACME account deactivates it at the CA",
			fmt.Sprintf("This plan destroys ACME account %q, which deactivates it at %s for good: the CA refuses "+
				"every later request of the account. PBS cannot renew certificates with it any more.",
				state.Name.ValueString(), state.Directory.ValueString()))
	}
}

// fromACMEAccount records an account as PBS reports it. The name is the one
// it was looked up by. contact keeps the value in m, which a CA need not
// return, unless refresh is set and the CA reports other addresses: after a
// write, m is the plan, which the result must match. tos_url, which PBS
// records at registration only, always keeps the value in m.
func (m *acmeAccountModel) fromACMEAccount(name string, account pbsclient.ACMEAccount, refresh bool) {
	m.ID = types.StringValue(name)
	m.Name = types.StringValue(name)
	emails := account.Emails()
	switch {
	case len(emails) == 0:
	case m.Contact.IsNull() || m.Contact.IsUnknown():
		m.Contact = types.StringValue(strings.Join(emails, ","))
	case refresh && !sameContacts(emails, splitContact(m.Contact.ValueString())):
		m.Contact = types.StringValue(strings.Join(emails, ","))
	}
	m.Directory = types.StringValue(account.Directory)
	if m.Location.IsNull() || m.Location.IsUnknown() || refresh {
		m.Location = stringOrNull(account.Location)
	}
	m.Status = stringOrNull(account.Account.Status)
}

func (r *acmeAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan acmeAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	params := url.Values{
		"name":      {name},
		"contact":   {normalContact(plan.Contact)},
		"directory": {plan.Directory.ValueString()},
	}
	if !plan.ToSURL.IsNull() {
		params.Set("tos_url", plan.ToSURL.ValueString())
	}
	if err := client.RegisterACMEAccount(ctx, params); err != nil {
		switch {
		case pbsclient.IsAlreadyExists(err):
			resp.Diagnostics.AddAttributeError(path.Root("name"), "PBS ACME account already exists",
				fmt.Sprintf("PBS already has an ACME account named %q. Import it to manage it with Terraform, with an "+
					"import block whose id is %q or with `terraform import`, or choose another name. %s", name, name, err))
		default:
			resp.Diagnostics.AddError("Unable to register PBS ACME account", acmeAccountErrorDetail(client, plan, true, err))
		}
		return
	}

	// From here on the account exists, so it is recorded in state even when
	// reading it back fails, with a warning: replacing it would deactivate
	// it at the CA.
	account, err := client.GetACMEAccount(ctx, name)
	if err != nil {
		plan.ID = types.StringValue(name)
		plan.Location = types.StringNull()
		plan.Status = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddWarning("Unable to read PBS ACME account back after registration",
			fmt.Sprintf("PBS registered ACME account %q, and it was recorded in state, but reading it back failed; "+
				"the next refresh reads it again. %s", name, apiErrorDetail(client, certificatesPrivilege, err)))
		return
	}
	plan.fromACMEAccount(name, account, false)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// acmeAccountErrorDetail explains a failed registration or update, with
// advice when the CA turned it down.
func acmeAccountErrorDetail(client *pbsclient.Client, plan acmeAccountModel, registering bool, err error) string {
	var taskErr *pbsclient.TaskError
	if !errors.As(err, &taskErr) {
		return apiErrorDetail(client, certificatesPrivilege, err)
	}
	if !registering {
		return "PBS could not update the account at " + plan.Directory.ValueString() + ". Check that PBS can reach " +
			"the directory and trusts its TLS certificate. " + err.Error()
	}
	detail := "PBS could not register the account at " + plan.Directory.ValueString() + ". Check that PBS can " +
		"reach the directory and trusts its TLS certificate"
	if plan.ToSURL.IsNull() {
		detail += ", and set tos_url: most CAs, Let's Encrypt among them, require agreeing to their terms of " +
			"service (the pbs_acme_tos data source reads the URL)"
	}
	if strings.Contains(taskErr.ExitStatus, "externalAccountRequired") {
		detail += ". This CA requires External Account Binding, which the provider does not support yet"
	}
	return detail + ". " + err.Error()
}

func (r *acmeAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state acmeAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)

	account, err := r.data.client.GetACMEAccount(ctx, name)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS ACME account", apiErrorDetail(r.data.client, certificatesPrivilege, err))
		return
	}
	// An import sets the name alone; directory always has a value
	// otherwise. Only then does tos_url come from PBS, which keeps the URL
	// agreed to at registration: later, the configured one is kept.
	imported := state.Directory.IsNull()
	state.fromACMEAccount(name, account, true)
	if imported {
		state.ToSURL = stringOrNull(account.ToS)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update changes the contact addresses at the CA; a new tos_url, or the same
// addresses written another way, is only recorded.
func (r *acmeAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state acmeAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	client := r.data.client

	// The same addresses written another way change nothing at the CA.
	if !sameContacts(splitContact(plan.Contact.ValueString()), splitContact(state.Contact.ValueString())) {
		if err := client.UpdateACMEAccountContact(ctx, name, normalContact(plan.Contact)); err != nil {
			resp.Diagnostics.AddError("Unable to update PBS ACME account", acmeAccountErrorDetail(client, plan, false, err))
			return
		}
	}

	account, err := client.GetACMEAccount(ctx, name)
	if err != nil {
		plan.Location, plan.Status = state.Location, state.Status
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
		resp.Diagnostics.AddError("Unable to read PBS ACME account back after update",
			fmt.Sprintf("PBS updated ACME account %q, and the change was recorded in state, but reading it back "+
				"failed. %s", name, apiErrorDetail(client, certificatesPrivilege, err)))
		return
	}
	plan.fromACMEAccount(name, account, false)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}

// Delete deactivates the account at the CA, for good. An account PBS no
// longer has is gone already.
func (r *acmeAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state acmeAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	err := client.DeactivateACMEAccount(ctx, name, false)
	var taskErr *pbsclient.TaskError
	switch {
	case err == nil:
	case errors.As(err, &taskErr) && strings.Contains(taskErr.ExitStatus, "does not exist"):
	default:
		detail := apiErrorDetail(client, certificatesPrivilege, err)
		if errors.As(err, &taskErr) {
			detail = "PBS could not deactivate the account at " + state.Directory.ValueString() + "; it keeps " +
				"the account. When the CA cannot be reached, or no longer knows the account, remove it from " +
				"state with `terraform state rm` and delete it in PBS with `proxmox-backup-manager acme account " +
				"deactivate " + name + " --force`. " + err.Error()
		}
		resp.Diagnostics.AddError("Unable to deactivate PBS ACME account", detail)
	}
}

// ImportState imports an account by name, given either as the import id or,
// from Terraform 1.12, as the identity of an import block. Read fills in the
// rest, or drops an account that does not exist, which Terraform reports.
func (r *acmeAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name, ok := importedSafeID(ctx, req, resp, "name", "ACME account", "default")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	setIdentity(ctx, resp.Identity, "name", name, &resp.Diagnostics)
}
