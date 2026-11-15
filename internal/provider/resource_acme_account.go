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
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
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
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Contact             types.String `tfsdk:"contact"`
	Directory           types.String `tfsdk:"directory"`
	ToSURL              types.String `tfsdk:"tos_url"`
	EABKid              types.String `tfsdk:"eab_kid"`
	EABHMACKeyWO        types.String `tfsdk:"eab_hmac_key_wo"`
	EABHMACKeyWOVersion types.Int64  `tfsdk:"eab_hmac_key_wo_version"`
	ForceDestroy        types.Bool   `tfsdk:"force_destroy"`
	Location            types.String `tfsdk:"location"`
	Status              types.String `tfsdk:"status"`
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
	eabKey, eabKeyVersion := writeOnlySecretAttributes("eab_hmac_key", "",
		stringCheck{
			description: "must be the HMAC key as the CA gave it: base64url, or base64 holding + or /, with or without = padding",
			check:       pbsclient.ValidEABHMACKey,
		}.secret(),
	)
	// The helper's texts say PBS receives the secret whenever its version
	// changes; here, PBS uses it only when it registers the account.
	eabKey.MarkdownDescription = "HMAC key of the External Account Binding, as the CA gave it: base64url, or " +
		"base64, with or without `=` padding; white space around it is ignored. PBS uses it once, to sign the " +
		"binding when it registers the account, and keeps no copy. Write-only: Terraform passes it to PBS without " +
		"storing it in the plan or state. Needed with `eab_kid` when the account is registered — when the " +
		"resource is created or replaced — and only then: it may be left out afterwards, with its version, as a " +
		"CA may accept a key only once. Requires `eab_hmac_key_wo_version`, and Terraform or OpenTofu 1.11 or later."
	eabKeyVersion.MarkdownDescription = "Version of `eab_hmac_key_wo`, which Terraform stores in its place. " +
		"Changing it from one version to another registers a new account with the key in `eab_hmac_key_wo`, after " +
		"deactivating the old one; setting it where state has none, as after an import, or removing it with " +
		"`eab_hmac_key_wo`, is only recorded. Requires `eab_hmac_key_wo`."
	eabKeyVersion.PlanModifiers = []planmodifier.Int64{int64planmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.Int64Request, resp *int64planmodifier.RequiresReplaceIfFuncResponse) {
			resp.RequiresReplace = eabBindingReplaced(req.StateValue, req.PlanValue)
		},
		"Changing the version from one value to another registers a new account.",
		"Changing the version from one value to another registers a new account.",
	)}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Proxmox Backup Server ACME account: an account at a certificate authority " +
			"such as Let's Encrypt, which the node uses to order the certificate of its web interface and API " +
			"(`pbs_node_certificate`), named in its ACME settings (`pbs_node_acme`).\n\n" +
			"Creating the resource has PBS register the account at the CA; PBS keeps the account's key. A new " +
			"`contact` is sent to the CA in place, and a new `tos_url` only recorded; a new `name` or `directory` " +
			"registers a new account.\n\n" +
			"For a CA that requires External Account Binding (EAB), such as ZeroSSL or Google Trust Services, set " +
			"`eab_kid` and `eab_hmac_key_wo` to the key identifier and HMAC key the CA gave you. PBS sends the " +
			"binding once, when it registers the account, and a new binding registers a new account. PBS cannot " +
			"tell whether a CA requires one, so without it such a registration fails at apply with the CA's " +
			"`externalAccountRequired` error.\n\n" +
			"~> **Destroying the resource deactivates the account at the CA, which cannot be undone.** The CA " +
			"refuses every later request of the account; certificates it issued stay valid until they expire, " +
			"but PBS can no longer renew them with this account. Replacing the resource — a new `name`, " +
			"`directory` or binding — deactivates the old account the same way, before the new one is " +
			"registered. When the CA refuses to deactivate the account, or cannot be reached, destroying fails " +
			"unless `force_destroy` is set.\n\n" +
			"Let's Encrypt stopped storing contact addresses in June 2025: it takes the address at registration " +
			"but neither keeps nor returns it, and ignores changes. The provider therefore keeps `contact` as " +
			"configured, and reports a change made outside Terraform only for a CA that returns its contacts.\n\n" +
			"Managing ACME accounts needs `" + certificatesPrivilege + "`. Registering, updating and deactivating " +
			"an account runs as a PBS task; the provider waits for it, up to `task_timeout`, and reports the CA's " +
			"error when it fails.\n\n" +
			"PBS writes about one account key in 128 in a form that CAs such as Let's Encrypt refuse as malformed " +
			"(Pebble says \"invalid EC public key, wrong length for x\" or \"for y\", Let's Encrypt \"Parse error " +
			"reading JWS\"); the provider then tries up to " + fmt.Sprint(pbsclient.ACMERegisterAttempts) + " keys in " +
			"all, registering the account again with a new key.",
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
					"certificate. A CA that requires External Account Binding, such as ZeroSSL or Google Trust " +
					"Services, needs `eab_kid` and `eab_hmac_key_wo`. Changing it registers a new account and " +
					"deactivates the old one.",
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
			"eab_kid": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Key identifier of the External Account Binding the CA gave you, for a CA that " +
					"requires one; set with `eab_hmac_key_wo`. PBS sends the binding to the CA when it registers the " +
					"account, and only then. A new `eab_kid` registers a new account and deactivates the old one, " +
					"before the new one is registered: should the CA refuse the new binding, no account remains. " +
					"Setting it where state has none, as after an import, or removing it is only recorded. An import " +
					"fills it in when the CA returned the binding at registration and PBS still holds it; updating " +
					"`contact` replaces what PBS holds with the CA's answer, which may leave the binding out.",
				Validators: []validator.String{stringvalidator.LengthAtLeast(1), noControlOrPadding},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIf(
					func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
						resp.RequiresReplace = eabBindingReplaced(req.StateValue, req.PlanValue)
					},
					"Changing the key identifier from one value to another registers a new account.",
					"Changing the key identifier from one value to another registers a new account.",
				)},
			},
			"eab_hmac_key_wo":         eabKey,
			"eab_hmac_key_wo_version": eabKeyVersion,
			"force_destroy": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Whether destroying the account removes it from PBS even when the CA refuses to " +
					"deactivate it or cannot be reached, as `proxmox-backup-manager acme account deactivate --force` " +
					"does: PBS then keeps the account's key as `/etc/proxmox-backup/acme/accounts/_deactivated_<name>_<n>`, " +
					"the account may stay active at the CA, and the provider warns with the CA's answer. Defaults to " +
					"`false`: destroying fails, and leaves the account in PBS and in state. Destroying uses the value " +
					"in state: set it in an apply before the one that destroys or replaces the account.",
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

// eabBindingReplaced reports whether a new eab_kid or eab_hmac_key_wo_version
// replaces the account: only a value that changes into another one does. A
// value set where state has none — after an import, or on an account
// registered without a binding — or one removed is only recorded: replacing
// the account then would deactivate it at the CA, and could not register a
// new one without the key, which a CA may accept only once. An unknown plan
// value counts as another value.
func eabBindingReplaced(state, plan attr.Value) bool {
	return !state.IsNull() && !plan.IsNull() && !state.Equal(plan)
}

// ModifyPlan warns that destroying the account, also to replace it,
// deactivates it at the CA for good, and that a binding added to an
// existing account is only recorded. When the plan registers an account, it
// requires the External Account Binding's key identifier and key together.
func (r *acmeAccountResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		if req.State.Raw.IsNull() {
			return
		}
		var state acmeAccountModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		acmeDeactivationWarning(&resp.Diagnostics, state, false)
		return
	}
	var plan acmeAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Terraform and OpenTofu plan a replacement twice, the second time with
	// a null prior state, as for a create: either way PBS is to register an
	// account.
	if req.State.Raw.IsNull() {
		requireEABPair(plan, &resp.Diagnostics)
		return
	}
	var state acmeAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The attributes' own RequiresReplace are not visible here, so the
	// replacement is worked out again.
	newBinding := eabBindingReplaced(state.EABKid, plan.EABKid) ||
		eabBindingReplaced(state.EABHMACKeyWOVersion, plan.EABHMACKeyWOVersion)
	if newBinding || !plan.Name.Equal(state.Name) || !plan.Directory.Equal(state.Directory) {
		acmeDeactivationWarning(&resp.Diagnostics, state, newBinding)
		return
	}
	if state.EABKid.IsNull() && !plan.EABKid.IsNull() && !plan.EABKid.IsUnknown() {
		resp.Diagnostics.AddAttributeWarning(path.Root("eab_kid"), "External Account Binding only recorded",
			fmt.Sprintf("eab_kid is recorded in state, and nothing changes at the CA: PBS sends an External Account "+
				"Binding only when it registers an account, so ACME account %q keeps the binding it was registered "+
				"with, if any. To register a new account with this binding, replace the resource, with terraform "+
				"apply -replace and eab_hmac_key_wo set, which deactivates the current account at the CA.",
				state.Name.ValueString()))
	}
}

// acmeDeactivationWarning warns that a plan destroys an account, which
// deactivates it at the CA, and, when a new binding replaces it, that the
// old account goes before the new one is registered.
func acmeDeactivationWarning(diags *diag.Diagnostics, state acmeAccountModel, newBinding bool) {
	detail := fmt.Sprintf("This plan destroys ACME account %q, which deactivates it at %s for good: the CA refuses "+
		"every later request of the account. PBS cannot renew certificates with it any more.",
		state.Name.ValueString(), state.Directory.ValueString())
	if newBinding {
		detail += " The account is deactivated before PBS registers the new one with the new External Account " +
			"Binding: should the CA refuse the binding, as for a wrong key or one it accepts only once, no " +
			"account remains."
	}
	if state.ForceDestroy.ValueBool() {
		detail += " force_destroy is set in state: should the CA refuse to deactivate the account, PBS removes " +
			"it all the same, and it may stay active at the CA."
	}
	diags.AddWarning("Destroying the ACME account deactivates it at the CA", detail)
}

// requireEABPair refuses an External Account Binding given half for an
// account PBS is to register, which PBS refuses before it contacts the CA.
// Write-only values are null in a plan, so the key's version stands for
// the key, which requires it.
func requireEABPair(plan acmeAccountModel, diags *diag.Diagnostics) {
	switch {
	case !plan.EABKid.IsNull() && !plan.EABKid.IsUnknown() && plan.EABHMACKeyWOVersion.IsNull():
		diags.AddAttributeError(path.Root("eab_hmac_key_wo"), "Missing External Account Binding key",
			"PBS registers an account with External Account Binding only with both its key identifier and its HMAC "+
				"key. Set eab_hmac_key_wo, with eab_hmac_key_wo_version, or remove eab_kid.")
	case plan.EABKid.IsNull() && !plan.EABHMACKeyWOVersion.IsNull() && !plan.EABHMACKeyWOVersion.IsUnknown():
		diags.AddAttributeError(path.Root("eab_kid"), "Missing External Account Binding key identifier",
			"eab_hmac_key_wo is set, but PBS sends it only with eab_kid. Set eab_kid, or remove eab_hmac_key_wo and "+
				"eab_hmac_key_wo_version.")
	}
}

// fromACMEAccount records an account as PBS reports it. The name is the one
// it was looked up by. contact keeps the value in m, which a CA need not
// return, unless refresh is set and the CA reports other addresses: after a
// write, m is the plan, which the result must match. tos_url, which PBS
// records at registration only, always keeps the value in m, and so do
// eab_kid, which PBS holds only as long as the CA's echo of the binding
// lasts, and the binding key's version; force_destroy lives in Terraform
// only, and is false unless set.
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
	if m.ForceDestroy.IsNull() || m.ForceDestroy.IsUnknown() {
		m.ForceDestroy = types.BoolValue(false)
	}
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
	if !plan.EABKid.IsNull() || !plan.EABHMACKeyWOVersion.IsNull() {
		// ModifyPlan checked the pair, unless eab_kid was unknown then.
		key, ok := writeOnlySecret(ctx, req.Config, "eab_hmac_key", &resp.Diagnostics)
		switch {
		case plan.EABKid.IsNull():
			resp.Diagnostics.AddAttributeError(path.Root("eab_kid"), "Missing External Account Binding key identifier",
				"eab_hmac_key_wo is set, but PBS sends it only with eab_kid.")
		case !ok:
			resp.Diagnostics.AddAttributeError(path.Root("eab_hmac_key_wo"), "Missing External Account Binding key",
				"eab_kid is set, but eab_hmac_key_wo is not known. PBS registers an account with External Account "+
					"Binding only with both.")
		default:
			params.Set("eab_kid", plan.EABKid.ValueString())
			params.Set("eab_hmac_key", pbsclient.NormalizeEABHMACKey(key))
		}
		if resp.Diagnostics.HasError() {
			return
		}
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
	if pbsclient.IsACMEKeyRefused(err) {
		return fmt.Sprintf("PBS could not register the account at %s: the CA refused the request as malformed. "+
			"PBS writes about one account key in 128 in a form that CAs such as Let's Encrypt refuse, so the "+
			"provider tried up to %d keys; applying again tries more. %s", plan.Directory.ValueString(),
			pbsclient.ACMERegisterAttempts, err)
	}
	detail := "PBS could not register the account at " + plan.Directory.ValueString() + ". Check that PBS can " +
		"reach the directory and trusts its TLS certificate"
	if plan.ToSURL.IsNull() {
		detail += ", and set tos_url: most CAs, Let's Encrypt among them, require agreeing to their terms of " +
			"service (the pbs_acme_tos data source reads the URL)"
	}
	exit := taskErr.ExitStatus
	binding := !plan.EABKid.IsNull()
	switch {
	case strings.Contains(exit, "externalAccountRequired") && !binding:
		detail += ". This CA requires External Account Binding: set eab_kid and eab_hmac_key_wo, with " +
			"eab_hmac_key_wo_version, to the key identifier and HMAC key the CA gave you"
	case binding && eabBindingRefused(exit):
		detail += ". The CA refused the External Account Binding: check eab_kid and eab_hmac_key_wo against what " +
			"the CA gave you; a CA may accept a binding key only once, or only for a limited time"
	case binding && base64Refused(exit):
		detail += ". PBS could not decode eab_hmac_key_wo as base64"
	}
	return detail + ". " + err.Error()
}

// eabBindingRefused reports whether a registration that carried an External
// Account Binding failed on it: the CA answers unauthorized, as Pebble does
// for an unknown key identifier ("the field 'kid' references a key that is
// not known to the ACME server") or a wrong key ("external account binding
// JWS verification error"), or malformed, naming the binding or its kid.
func eabBindingRefused(exit string) bool {
	if strings.Contains(exit, "urn:ietf:params:acme:error:unauthorized") {
		return true
	}
	lower := strings.ToLower(exit)
	return strings.Contains(exit, "urn:ietf:params:acme:error:malformed") &&
		(strings.Contains(lower, "external account") || strings.Contains(lower, "externalaccountbinding") ||
			strings.Contains(lower, "'kid'") || strings.Contains(lower, `"kid"`))
}

// base64Refused reports whether PBS failed to decode the binding's key. PBS
// decodes it with proxmox-base64 (proxmox-acme's set_eab_credentials) and
// fails the task with its DecodeError, which hides the base64 crate's
// message: "invalid padding in base64 encoded data", as for a base64url key
// with "=" padding, or "error decoding base64 data" for any other fault. Only
// these texts count: a CA's own answer may mention base64. The provider's
// validation refuses such keys first.
func base64Refused(exit string) bool {
	return strings.Contains(exit, "invalid padding in base64 encoded data") ||
		strings.Contains(exit, "error decoding base64 data")
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
	// agreed to at registration: later, the configured one is kept. eab_kid
	// too, from the binding the CA echoed, which PBS loses on the next
	// update of the account at a CA such as Pebble: reading it later would
	// take away a configured eab_kid.
	imported := state.Directory.IsNull()
	state.fromACMEAccount(name, account, true)
	if imported {
		state.ToSURL = stringOrNull(account.ToS)
		state.EABKid = stringOrNull(account.EABKeyID())
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

// Delete deactivates the account at the CA, for good, and with
// force_destroy, as in state, has PBS remove it also when the CA refuses. An
// account PBS no longer has is gone already: PBS fails the task with "acme
// account '<name>' does not exist", also with force.
func (r *acmeAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state acmeAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	client := r.data.client
	refusal, err := client.DeactivateACMEAccount(ctx, name, state.ForceDestroy.ValueBool())
	var taskErr *pbsclient.TaskError
	switch {
	case err == nil:
		if refusal != "" {
			resp.Diagnostics.AddWarning("ACME account removed although the CA refused to deactivate it",
				fmt.Sprintf("Deactivating ACME account %q at %s failed: %s. With force_destroy, PBS removed the "+
					"account all the same, keeping its key as /etc/proxmox-backup/acme/accounts/_deactivated_%s_<n>; "+
					"the account may still be active at the CA.", name, state.Directory.ValueString(), refusal, name))
		}
	case errors.As(err, &taskErr) && strings.Contains(taskErr.ExitStatus, fmt.Sprintf("acme account '%s' does not exist", name)):
	default:
		resp.Diagnostics.AddError("Unable to deactivate PBS ACME account", acmeDeactivationErrorDetail(client, state, err))
	}
}

// acmeAccountDir is where PBS keeps its ACME accounts, a file each: the
// "accounts" directory of configdir!("/acme"), which PBS's daemons hand to
// proxmox_acme_api::init (ACME_ACCOUNT_DIR in src/config/acme/mod.rs before
// 4.1.2).
const acmeAccountDir = "/etc/proxmox-backup/acme/accounts"

// acmeAccountReadFailures are the errors of a deactivation task that failed
// on PBS's own file of the account before PBS asked the CA: reading or
// parsing it (load_account_config in proxmox-acme-api's account_config.rs;
// AcmeClient::load in src/acme/client.rs before 4.1.2).
var acmeAccountReadFailures = []string{
	"failed to load acme account from ",
	"failed to parse acme account from ",
}

// acmeAccountWriteFailure reports whether a deactivation task failed on
// PBS's own file of the account after the CA's answer, which, without
// force, means that the CA has deactivated the account. PBS saves the CA's
// answer, serializing it and writing it with proxmox-sys's replace_file
// (save_account_config in proxmox-acme-api's account_config.rs, from PBS
// 4.1.2; AcmeClient::update_account in src/acme/client.rs before), and
// renames the file to _deactivated_<name>_<n>, which PBS tries for n up to
// 99 only (mark_account_deactivated). Every error of these names the file
// or its directory — "failed to serialize acme account to ...", "mkstemp
// ... failed", "fchmod ...", "Atomic rename failed for file ...", "fsync of
// directory ...", "No free slot to rename deactivated account ...", "failed
// to move account path ..." — except replace_file's "write failed: " and
// "fsync failed: ", which start the task's exit status, as PBS fails the
// task with the error itself. Nothing that fails at the CA names the
// directory or starts so.
func acmeAccountWriteFailure(exit string) bool {
	return strings.Contains(exit, acmeAccountDir) || strings.HasPrefix(exit, "write failed: ") ||
		strings.HasPrefix(exit, "fsync failed: ")
}

// acmeAccountFileStep says what to fix on PBS after a deactivation failed
// on its own file of the account, as a sentence without its full stop.
func acmeAccountFileStep(name, exit string) string {
	switch {
	case strings.Contains(exit, "No free slot to rename deactivated account "):
		return "Remove old _deactivated_" + name + "_<n> files in " + acmeAccountDir + " on PBS, which " +
			"renames the file of a deactivated account to the first free n below 100"
	case strings.Contains(exit, "No space left on device"):
		return "Free space on the file system of " + acmeAccountDir + " on PBS"
	case strings.Contains(exit, "Read-only file system"):
		return "Make the file system of " + acmeAccountDir + " on PBS writable again"
	}
	return "Fix on PBS what the error names"
}

// acmeDeactivationErrorDetail explains a failed deactivation by where it
// failed. Reading PBS's own file of the account fails before PBS asks the
// CA, and force_destroy does not get past it. Saving the CA's answer or
// renaming the file fails after the CA's answer: without force, the CA has
// deactivated the account then, and refuses every later request of it, so
// destroying again needs force_destroy, which has PBS pass over that
// refusal; with force_destroy in state, a failure on the file is the only
// way the task fails, and advising force_destroy would be wrong. Anything
// else failed at the CA.
func acmeDeactivationErrorDetail(client *pbsclient.Client, state acmeAccountModel, err error) string {
	var taskErr *pbsclient.TaskError
	if !errors.As(err, &taskErr) {
		return apiErrorDetail(client, certificatesPrivilege, err)
	}
	name := state.Name.ValueString()
	exit := taskErr.ExitStatus
	for _, text := range acmeAccountReadFailures {
		if strings.Contains(exit, text) {
			return "PBS could not read its own copy of the account, " + acmeAccountDir + "/" + name + ", so it " +
				"did not ask the CA, and keeps the account. force_destroy does not get past this: it makes PBS " +
				"pass over the CA's refusal only. Repair the file on PBS, or remove it, which leaves the account " +
				"active at the CA; then destroy again. " + err.Error()
		}
	}
	switch {
	case state.ForceDestroy.ValueBool():
		return "PBS failed on its own copy of the account, in " + acmeAccountDir + ", and keeps the account; the " +
			"CA may have deactivated it already. force_destroy does not get past this: it makes PBS pass over " +
			"the CA's refusal only. " + acmeAccountFileStep(name, exit) + "; then destroy again. " + err.Error()
	case acmeAccountWriteFailure(exit):
		return "The CA has deactivated the account, but PBS could not record that in " + acmeAccountDir + ", and " +
			"keeps the account. " + acmeAccountFileStep(name, exit) + "; then set force_destroy = true, apply " +
			"that, and destroy again: the CA refuses every request of the deactivated account, and with " +
			"force_destroy PBS passes over that refusal, which the provider reports as a warning. " + err.Error()
	}
	detail := "PBS could not deactivate the account at " + state.Directory.ValueString() + "; it keeps the account."
	if strings.Contains(taskErr.ExitStatus, "urn:ietf:params:acme:error:accountDoesNotExist") {
		detail += " The CA does not know the account any more, so nothing is left behind at the CA."
	}
	return detail + " When the CA cannot be reached, or no longer knows the account, set force_destroy = true " +
		"and apply that first: PBS then removes the account although the CA refuses, and destroying or " +
		"replacing it succeeds. Without Terraform, `proxmox-backup-manager acme account deactivate " + name +
		" --force` does the same; then remove the account from state with `terraform state rm`. " + err.Error()
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
