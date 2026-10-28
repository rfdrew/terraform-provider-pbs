package provider

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &nodeACMEResource{}
	_ resource.ResourceWithConfigure   = &nodeACMEResource{}
	_ resource.ResourceWithIdentity    = &nodeACMEResource{}
	_ resource.ResourceWithImportState = &nodeACMEResource{}
	_ resource.ResourceWithModifyPlan  = &nodeACMEResource{}
)

// NewNodeACMEResource returns the pbs_node_acme resource.
func NewNodeACMEResource() resource.Resource { return &nodeACMEResource{} }

type nodeACMEResource struct {
	data *providerData
}

type nodeACMEModel struct {
	ID      types.String `tfsdk:"id"`
	Node    types.String `tfsdk:"node"`
	Account types.String `tfsdk:"account"`
	Domains types.Set    `tfsdk:"domains"`
}

// nodeACMEDomain is one element of domains.
type nodeACMEDomain struct {
	Domain types.String `tfsdk:"domain"`
	Alias  types.String `tfsdk:"alias"`
	Plugin types.String `tfsdk:"plugin"`
}

var nodeACMEDomainTypes = map[string]attr.Type{
	"domain": types.StringType,
	"alias":  types.StringType,
	"plugin": types.StringType,
}

// The node's ACME settings are read with Sys.Audit on /system and changed
// with Sys.Modify.
const (
	nodeConfigReadPrivilege   = "Sys.Audit on /system"
	nodeConfigModifyPrivilege = "Sys.Modify on /system"
)

// dnsNamePattern is a domain PBS orders a certificate for; dnsAliasPattern
// is a challenge alias, whose labels may also start with an underscore.
var (
	dnsNamePattern  = regexp.MustCompile(`^(([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)
	dnsAliasPattern = regexp.MustCompile(`^(([a-zA-Z0-9_]([a-zA-Z0-9-]*[a-zA-Z0-9])?)\.)*[a-zA-Z0-9_]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)
)

func (r *nodeACMEResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node_acme"
}

func (r *nodeACMEResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the ACME settings of a Proxmox Backup Server node: which ACME account " +
			"(`pbs_acme_account`) orders the certificate of its web interface and API, and for which domains, " +
			"each validated by a challenge plugin (`pbs_acme_plugin`). `pbs_node_certificate` orders the " +
			"certificate; PBS renews it with these settings.\n\n" +
			"The node is a singleton: creating the resource takes over the node's ACME settings, replacing " +
			"domains configured before, and destroying it removes them. It manages only these settings — " +
			"`acme` and `acmedomain0` to `acmedomain4` in the node's configuration — and leaves the node's other " +
			"settings alone.\n\n" +
			"Reading the settings needs `" + nodeConfigReadPrivilege + "`, changing them `" +
			nodeConfigModifyPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `node`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": nodeAttribute("ACME settings"),
			"account": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Name of the ACME account that orders the node's certificate, such as the `name` " +
					"of a `pbs_acme_account`. PBS checks it when it orders.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, maxSafeIDLength),
					stringvalidator.RegexMatches(acmeAccountNamePattern, "must be an ACME account name such as default"),
				},
			},
			"domains": schema.SetNestedAttribute{
				Required: true,
				MarkdownDescription: fmt.Sprintf("Domains of the certificate, 1 to %d, each in a slot of its own in PBS "+
					"(`acmedomain0` to `acmedomain4`). The certificate covers all of them; the CA picks which one "+
					"becomes its subject — Let's Encrypt the alphabetically first. A domain keeps its slot while it "+
					"stays, so reordering them changes nothing.", pbsclient.MaxACMEDomains),
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"domain": schema.StringAttribute{
							Required: true,
							MarkdownDescription: "Domain to certify, such as `pbs.example.org`. Each domain may appear " +
								"once, in any case. PBS does not support wildcard domains.",
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 253),
								stringvalidator.RegexMatches(dnsNamePattern, "must be a domain name such as pbs.example.org"),
							},
						},
						"alias": schema.StringAttribute{
							Optional: true,
							MarkdownDescription: "Domain whose `_acme-challenge` TXT record a DNS plugin sets instead of " +
								"the domain's own, for a domain whose `_acme-challenge` record is a CNAME delegating the " +
								"challenge to another zone: with an alias of `validation.example.net`, the CNAME points " +
								"at `_acme-challenge.validation.example.net`.",
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 253),
								stringvalidator.RegexMatches(dnsAliasPattern, "must be a domain name such as validation.example.net"),
							},
						},
						"plugin": schema.StringAttribute{
							Optional: true,
							MarkdownDescription: "ID of the plugin that validates the domain, such as the `id` of a " +
								"`pbs_acme_plugin`. Without one, the built-in `standalone` plugin validates it by HTTP " +
								"on port 80, which the CA must reach.",
							Validators: safeIDValidators(1),
						},
					},
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, pbsclient.MaxACMEDomains),
					setvalidator.NoNullValues(),
					uniqueDomainsValidator{},
				},
			},
		},
	}
}

// uniqueDomainsValidator refuses the same domain twice, in any case, which
// PBS refuses too.
type uniqueDomainsValidator struct{}

func (uniqueDomainsValidator) Description(_ context.Context) string {
	return "each domain must appear once, in any case"
}

func (v uniqueDomainsValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v uniqueDomainsValidator) ValidateSet(ctx context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	seen := map[string]bool{}
	for _, element := range req.ConfigValue.Elements() {
		object, ok := element.(types.Object)
		if !ok || object.IsNull() || object.IsUnknown() {
			continue
		}
		domain, ok := object.Attributes()["domain"].(types.String)
		if !ok || domain.IsNull() || domain.IsUnknown() {
			continue
		}
		key := strings.ToLower(domain.ValueString())
		if seen[key] {
			resp.Diagnostics.AddAttributeError(req.Path, "Duplicate ACME domain",
				fmt.Sprintf("Attribute %s lists %s more than once; %s.", req.Path, domain.ValueString(), v.Description(ctx)))
			return
		}
		seen[key] = true
	}
}

func (r *nodeACMEResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"node", "Node name, such as `localhost`."})
}

func (r *nodeACMEResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *nodeACMEResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planNode(ctx, r.data, req, resp)
}

// domains returns the planned domains, keyed by their lower-case name.
func (m nodeACMEModel) domains(ctx context.Context, diags *diag.Diagnostics) map[string]pbsclient.ACMEDomain {
	var elements []nodeACMEDomain
	diags.Append(m.Domains.ElementsAs(ctx, &elements, false)...)
	out := make(map[string]pbsclient.ACMEDomain, len(elements))
	for _, e := range elements {
		out[strings.ToLower(e.Domain.ValueString())] = pbsclient.ACMEDomain{
			Domain: e.Domain.ValueString(),
			Alias:  e.Alias.ValueString(),
			Plugin: e.Plugin.ValueString(),
		}
	}
	return out
}

// fromNodeConfig records the node's ACME settings. account is null when
// the node names none, and domains when it has none.
func (m *nodeACMEModel) fromNodeConfig(node string, config pbsclient.NodeConfig, diags *diag.Diagnostics) {
	m.ID = types.StringValue(node)
	m.Node = types.StringValue(node)
	m.Account = types.StringNull()
	if strings.TrimSpace(config.ACME) != "" {
		account, err := config.ACMEAccountName()
		if err != nil {
			diags.AddError("Unexpected PBS node configuration",
				fmt.Sprintf("PBS answered an acme property the provider cannot read, %q: %s", config.ACME, err))
			return
		}
		m.Account = stringOrNull(account)
	}

	var elements []attr.Value
	for i, raw := range config.ACMEDomains {
		if raw == "" {
			continue
		}
		domain, err := pbsclient.ParseACMEDomain(raw)
		if err != nil {
			diags.AddError("Unexpected PBS node configuration",
				fmt.Sprintf("PBS answered an %s property the provider cannot read, %q: %s", pbsclient.ACMEDomainProperty(i), raw, err))
			return
		}
		object, d := types.ObjectValue(nodeACMEDomainTypes, map[string]attr.Value{
			"domain": types.StringValue(domain.Domain),
			"alias":  stringOrNull(domain.Alias),
			"plugin": stringOrNull(domain.Plugin),
		})
		diags.Append(d...)
		elements = append(elements, object)
	}
	if len(elements) == 0 {
		m.Domains = types.SetNull(types.ObjectType{AttrTypes: nodeACMEDomainTypes})
		return
	}
	set, d := types.SetValue(types.ObjectType{AttrTypes: nodeACMEDomainTypes}, elements)
	diags.Append(d...)
	m.Domains = set
}

// nodeACMEChanges turns the node's current settings into the planned ones:
// the account, and the domains, each kept in the slot it has, new ones in
// the free slots from the lowest. replaced lists the domains of the node the
// plan does not have.
func nodeACMEChanges(current pbsclient.NodeConfig, account string, planned map[string]pbsclient.ACMEDomain) (params url.Values, replaced []string, err error) {
	params = url.Values{}
	var deletes []string
	if want := "account=" + account; current.ACME != want {
		params.Set("acme", want)
	}

	placed := map[string]bool{}
	var free []int
	for i, raw := range current.ACMEDomains {
		if raw == "" {
			free = append(free, i)
			continue
		}
		existing, parseErr := pbsclient.ParseACMEDomain(raw)
		key := strings.ToLower(existing.Domain)
		want, keep := planned[key]
		if parseErr != nil || !keep || placed[key] {
			// A slot PBS has but the plan does not, or one the provider
			// cannot read, is emptied for a planned domain.
			deletes = append(deletes, pbsclient.ACMEDomainProperty(i))
			free = append(free, i)
			if parseErr == nil && !keep {
				replaced = append(replaced, existing.Domain)
			}
			continue
		}
		placed[key] = true
		if formatted := want.Format(); formatted != raw && existing != want {
			params.Set(pbsclient.ACMEDomainProperty(i), formatted)
		}
	}

	var unplaced []string
	for key := range planned {
		if !placed[key] {
			unplaced = append(unplaced, key)
		}
	}
	sort.Strings(unplaced)
	sort.Ints(free)
	if len(unplaced) > len(free) {
		return nil, nil, fmt.Errorf("%d domains do not fit into the %d free ACME domain slots", len(unplaced), len(free))
	}
	for i, key := range unplaced {
		slot := free[i]
		params.Set(pbsclient.ACMEDomainProperty(slot), planned[key].Format())
		deletes = removeString(deletes, pbsclient.ACMEDomainProperty(slot))
	}
	pbsclient.AddDelete(params, deletes...)
	return params, replaced, nil
}

// removeString returns list without s.
func removeString(list []string, s string) []string {
	out := list[:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// apply writes the planned settings to the node, based on what it has now,
// under the lock of node.cfg and with its digest, and returns the domains
// the node had that the plan replaced.
func (r *nodeACMEResource) apply(ctx context.Context, plan nodeACMEModel, diags *diag.Diagnostics) []string {
	client := r.data.client
	node := plan.Node.ValueString()
	planned := plan.domains(ctx, diags)
	if diags.HasError() {
		return nil
	}
	var replaced []string
	err := client.WithConfigLock(pbsclient.ConfigNode, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			current, digest, err := client.GetNodeConfig(ctx, node)
			if err != nil {
				return err
			}
			params, removed, err := nodeACMEChanges(current, plan.Account.ValueString(), planned)
			if err != nil || (len(params) == 0) {
				replaced = removed
				return err
			}
			params.Set(pbsclient.DigestParam, digest)
			if err := client.UpdateNodeConfig(ctx, node, params); err != nil {
				return err
			}
			replaced = removed
			return nil
		})
	})
	if err != nil {
		diags.AddError("Unable to change the ACME settings of the PBS node", apiErrorDetail(client, nodeConfigModifyPrivilege, err))
	}
	return replaced
}

func (r *nodeACMEResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan nodeACMEModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	replaced := r.apply(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	node := plan.Node.ValueString()
	if len(replaced) > 0 {
		resp.Diagnostics.AddWarning("Replaced ACME domains of the PBS node",
			fmt.Sprintf("Node %s had ACME domains this resource does not list, which it removed: %s. PBS orders and "+
				"renews its certificate for the domains of this resource only.", node, strings.Join(replaced, ", ")))
	}
	r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

// readBack reads the settings after a write and records them, or the plan
// when reading fails: the write took effect.
func (r *nodeACMEResource) readBack(ctx context.Context, plan nodeACMEModel, state *tfsdk.State, identity *tfsdk.ResourceIdentity, diags *diag.Diagnostics) {
	node := plan.Node.ValueString()
	config, _, err := r.data.client.GetNodeConfig(ctx, node)
	if err != nil {
		plan.ID = types.StringValue(node)
		diags.Append(state.Set(ctx, &plan)...)
		setIdentity(ctx, identity, "node", node, diags)
		diags.AddWarning("Unable to read the ACME settings of the PBS node back",
			fmt.Sprintf("PBS changed the ACME settings of node %s, and they were recorded in state, but reading them "+
				"back failed; the next refresh reads them again. %s", node, apiErrorDetail(r.data.client, nodeConfigReadPrivilege, err)))
		return
	}
	plan.fromNodeConfig(node, config, diags)
	diags.Append(state.Set(ctx, &plan)...)
	setIdentity(ctx, identity, "node", node, diags)
}

func (r *nodeACMEResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state nodeACMEModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := state.Node.ValueString()
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)

	config, _, err := r.data.client.GetNodeConfig(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the ACME settings of the PBS node",
			apiErrorDetail(r.data.client, nodeConfigReadPrivilege, err))
		return
	}
	state.fromNodeConfig(node, config, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *nodeACMEResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan nodeACMEModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

// Delete removes the node's ACME settings: the account, which PBS then takes
// to be the one named default, and every domain.
func (r *nodeACMEResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state nodeACMEModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	node := state.Node.ValueString()
	err := client.WithConfigLock(pbsclient.ConfigNode, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			current, digest, err := client.GetNodeConfig(ctx, node)
			if err != nil {
				return err
			}
			var deletes []string
			if current.ACME != "" {
				deletes = append(deletes, "acme")
			}
			for i, raw := range current.ACMEDomains {
				if raw != "" {
					deletes = append(deletes, pbsclient.ACMEDomainProperty(i))
				}
			}
			if len(deletes) == 0 {
				return nil
			}
			params := url.Values{pbsclient.DigestParam: {digest}}
			pbsclient.AddDelete(params, deletes...)
			return client.UpdateNodeConfig(ctx, node, params)
		})
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to remove the ACME settings of the PBS node", apiErrorDetail(client, nodeConfigModifyPrivilege, err))
	}
}

// ImportState imports the ACME settings of a node by its name, given either
// as the import id or, from Terraform 1.12, as the identity of an import
// block.
func (r *nodeACMEResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	node, ok := importedNode(ctx, req, resp, "ACME settings")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node"), node)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), node)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
}
