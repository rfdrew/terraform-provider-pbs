package provider

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	_ resource.Resource                = &dnsResource{}
	_ resource.ResourceWithConfigure   = &dnsResource{}
	_ resource.ResourceWithIdentity    = &dnsResource{}
	_ resource.ResourceWithImportState = &dnsResource{}
	_ resource.ResourceWithModifyPlan  = &dnsResource{}
)

// NewDNSResource returns the pbs_dns resource.
func NewDNSResource() resource.Resource { return &dnsResource{} }

type dnsResource struct {
	data *providerData
}

type dnsModel struct {
	ID     types.String `tfsdk:"id"`
	Node   types.String `tfsdk:"node"`
	Search types.String `tfsdk:"search"`
	DNS1   types.String `tfsdk:"dns1"`
	DNS2   types.String `tfsdk:"dns2"`
	DNS3   types.String `tfsdk:"dns3"`
}

// The node's DNS settings are read with Sys.Audit on /system/network/dns
// and changed with Sys.Modify.
const (
	dnsReadPrivilege   = "Sys.Audit on /system/network/dns"
	dnsModifyPrivilege = "Sys.Modify on /system/network/dns"
)

func (r *dnsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns"
}

func (r *dnsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nameserver := func(which string) string {
		return "IP address of the node's " + which + " nameserver, IPv4 or IPv6."
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the DNS settings of a Proxmox Backup Server node — its search domain and up to " +
			"three nameservers —, which PBS keeps in `/etc/resolv.conf`.\n\n" +
			"The node is a singleton: creating the resource takes over the node's nameservers, removing those it " +
			"does not list, with a warning. Every change has PBS write the file anew: the search domain, the " +
			"nameservers in order, then the file's other lines — `options`, comments — as they were. PBS keeps " +
			"only what it reads, so the first change also drops a `domain` line (in favour of `search`), search " +
			"domains after the first, nameservers after the third, comments at the end of a `nameserver` line " +
			"and the zone of a link-local nameserver — `%eth0` of `fe80::1%eth0`, which leaves that nameserver " +
			"unusable —, and replaces a symbolic link — such as systemd-resolved's — with a file.\n\n" +
			"**Destroying the resource leaves the node's DNS settings as they are.** PBS cannot remove the search " +
			"domain, and a node without nameservers would resolve no name — not its ACME CA, S3 endpoints, " +
			"remotes or APT mirrors —, so there is nothing safe to go back to. To remove a nameserver, remove it " +
			"from the configuration and apply.\n\n" +
			"PBS replaces `/etc/resolv.conf` by renaming a new file over it, which fails where the file is a mount " +
			"point, as Docker and Kubernetes make it in a container: there, set DNS through the container instead " +
			"(`--dns` and `--dns-search` of `docker run`). On a host where another program manages the file, such " +
			"as systemd-resolved or NetworkManager, that program may overwrite the settings.\n\n" +
			"Reading the settings needs `" + dnsReadPrivilege + "`, changing them `" + dnsModifyPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `node`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": nodeAttribute("DNS settings"),
			"search": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Domain the node appends to a host name without dots, such as `example.org`: " +
					"one domain, as PBS reads only the first of a `search` line. PBS cannot remove it, so leaving it " +
					"out keeps the node's, which this attribute then reports.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 253),
					stringvalidator.RegexMatches(dnsNamePattern, "must be a domain name such as example.org"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"dns1": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: nameserver("first"),
				Validators:          []validator.String{ipAddressValidator{}},
			},
			"dns2": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: nameserver("second"),
				Validators:          []validator.String{ipAddressValidator{}},
			},
			"dns3": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: nameserver("third") + " Requires `dns2`: PBS numbers the nameservers anew from the file.",
				Validators: []validator.String{
					ipAddressValidator{},
					stringvalidator.AlsoRequires(path.MatchRoot("dns2")),
				},
			},
		},
	}
}

// ipAddressValidator accepts an IPv4 or IPv6 address, without a zone, as
// PBS's IP format does.
type ipAddressValidator struct{}

func (ipAddressValidator) Description(_ context.Context) string {
	return "must be an IPv4 or IPv6 address, such as 192.0.2.53 or 2001:db8::53"
}

func (v ipAddressValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v ipAddressValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	addr, err := netip.ParseAddr(req.ConfigValue.ValueString())
	switch {
	case err != nil || addr.Zone() != "":
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP address",
			fmt.Sprintf("Attribute %s %s, without a zone, got %q.", req.Path, v.Description(ctx), req.ConfigValue.ValueString()))
	case addr.IsLinkLocalUnicast() && addr.Is6():
		resp.Diagnostics.AddAttributeError(req.Path, "Link-local nameserver",
			fmt.Sprintf("Attribute %s is the link-local address %s, which the node can reach only with a zone, "+
				"such as %%eth0, and PBS writes none: use a nameserver's global address.", req.Path, addr))
	}
}

func (r *dnsResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"node", "Node name, such as `localhost`."})
}

func (r *dnsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *dnsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planNode(ctx, r.data, req, resp)
}

func (m *dnsModel) fromDNS(node string, dns pbsclient.DNS) {
	m.ID = types.StringValue(node)
	m.Node = types.StringValue(node)
	m.Search = stringOrNull(dns.Search)
	m.DNS1 = stringOrNull(dns.DNS1)
	m.DNS2 = stringOrNull(dns.DNS2)
	m.DNS3 = stringOrNull(dns.DNS3)
}

// dnsChanges returns the PUT that makes the node's current settings what
// plan says, and the nameservers it removes. search is the configured search
// domain: null leaves the node's as it is.
func dnsChanges(current pbsclient.DNS, plan dnsModel, search types.String) (params url.Values, removed []string) {
	params = url.Values{}
	if !search.IsNull() && !search.IsUnknown() && search.ValueString() != current.Search {
		params.Set("search", search.ValueString())
	}
	var deletes []string
	planned := [3]types.String{plan.DNS1, plan.DNS2, plan.DNS3}
	for i, server := range current.Nameservers() {
		property := fmt.Sprintf("dns%d", i+1)
		switch want := planned[i]; {
		case !want.IsNull():
			if want.ValueString() != server {
				params.Set(property, want.ValueString())
			}
		case server != "":
			deletes = append(deletes, property)
			removed = append(removed, server)
		}
	}
	pbsclient.AddDelete(params, deletes...)
	return params, removed
}

// write makes the node's DNS settings what plan says, under the lock of
// resolv.conf and with its digest, and returns the nameservers it removed.
// config is the configuration, whose search domain alone says whether to
// set it: the plan holds the node's when the configuration leaves it out.
func (r *dnsResource) write(ctx context.Context, plan dnsModel, config tfsdk.Config, diags *diag.Diagnostics) []string {
	var search types.String
	diags.Append(config.GetAttribute(ctx, path.Root("search"), &search)...)
	if diags.HasError() {
		return nil
	}
	client := r.data.client
	node := plan.Node.ValueString()
	var removed []string
	err := client.WithConfigLock(pbsclient.ConfigDNS, func() error {
		return client.RetryOnDigestConflict(ctx, func() error {
			current, err := client.GetDNS(ctx, node)
			if err != nil {
				return err
			}
			params, gone := dnsChanges(current, plan, search)
			removed = gone
			if len(params) == 0 {
				return nil
			}
			params.Set(pbsclient.DigestParam, current.Digest)
			return client.UpdateDNS(ctx, node, params)
		})
	})
	if err != nil {
		detail := apiErrorDetail(client, dnsModifyPrivilege, err)
		if pbsclient.IsResolvConfMountPoint(err) {
			detail = "PBS writes /etc/resolv.conf by renaming a new file over it, which fails where the file is a " +
				"mount point: in a container, Docker or Kubernetes mounts it. Set the container's DNS through them " +
				"instead (`--dns` and `--dns-search` of `docker run`, `dns` and `dns_search` in Compose), and leave " +
				"pbs_dns out. Unmounting the file in the container (`cp /etc/resolv.conf /tmp/resolv.conf && umount " +
				"/etc/resolv.conf && cp /tmp/resolv.conf /etc/resolv.conf`) needs a privileged container or " +
				"CAP_SYS_ADMIN, and Docker mounts it again whenever the container starts. " + detail
		}
		diags.AddError("Unable to change the DNS settings of the PBS node", detail)
	}
	return removed
}

// readBack reads the settings after a write and records them, or the plan
// when reading fails: the write took effect.
func (r *dnsResource) readBack(ctx context.Context, plan dnsModel, state *tfsdk.State, identity *tfsdk.ResourceIdentity, diags *diag.Diagnostics) {
	node := plan.Node.ValueString()
	dns, err := r.data.client.GetDNS(ctx, node)
	if err != nil {
		plan.ID = types.StringValue(node)
		if plan.Search.IsUnknown() {
			plan.Search = types.StringNull()
		}
		diags.Append(state.Set(ctx, &plan)...)
		setIdentity(ctx, identity, "node", node, diags)
		diags.AddWarning("Unable to read the DNS settings of the PBS node back",
			fmt.Sprintf("PBS changed the DNS settings of node %s, and they were recorded in state, but reading them "+
				"back failed; the next refresh reads them again. %s", node, apiErrorDetail(r.data.client, dnsReadPrivilege, err)))
		return
	}
	plan.fromDNS(node, dns)
	diags.Append(state.Set(ctx, &plan)...)
	setIdentity(ctx, identity, "node", node, diags)
}

func (r *dnsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dnsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	removed := r.write(ctx, plan, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if len(removed) > 0 {
		resp.Diagnostics.AddWarning("Removed nameservers of the PBS node",
			fmt.Sprintf("Node %s had nameservers this resource does not list, which it removed: %s.",
				plan.Node.ValueString(), strings.Join(removed, ", ")))
	}
	r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

func (r *dnsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dnsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := state.Node.ValueString()
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
	dns, err := r.data.client.GetDNS(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the DNS settings of the PBS node", apiErrorDetail(r.data.client, dnsReadPrivilege, err))
		return
	}
	state.fromDNS(node, dns)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dnsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dnsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, plan, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.readBack(ctx, plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

// Delete leaves the node's DNS settings as they are: see the resource's
// description.
func (r *dnsResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {}

// ImportState imports the DNS settings of a node by the node's name, given
// either as the import id or, from Terraform 1.12, as the identity of an
// import block.
func (r *dnsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	node, ok := importedNode(ctx, req, resp, "DNS settings")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node"), node)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), node)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
}
