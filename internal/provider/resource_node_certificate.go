package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                = &nodeCertificateResource{}
	_ resource.ResourceWithConfigure   = &nodeCertificateResource{}
	_ resource.ResourceWithIdentity    = &nodeCertificateResource{}
	_ resource.ResourceWithImportState = &nodeCertificateResource{}
	_ resource.ResourceWithModifyPlan  = &nodeCertificateResource{}
)

// NewNodeCertificateResource returns the pbs_node_certificate resource.
func NewNodeCertificateResource() resource.Resource { return &nodeCertificateResource{} }

type nodeCertificateResource struct {
	data *providerData
}

type nodeCertificateModel struct {
	ID          types.String `tfsdk:"id"`
	Node        types.String `tfsdk:"node"`
	Source      types.String `tfsdk:"source"`
	Triggers    types.Map    `tfsdk:"triggers"`
	Fingerprint types.String `tfsdk:"fingerprint"`
	Subject     types.String `tfsdk:"subject"`
	Issuer      types.String `tfsdk:"issuer"`
	SAN         types.List   `tfsdk:"san"`
	NotBefore   types.String `tfsdk:"not_before"`
	NotAfter    types.String `tfsdk:"not_after"`
}

// Where the certificate comes from. Only ACME for now; an uploaded
// certificate, "custom", is to follow with attributes of its own.
const certificateSourceACME = "acme"

func (r *nodeCertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node_certificate"
}

func (r *nodeCertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: description,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the certificate a Proxmox Backup Server node serves its web interface and API " +
			"with, on port 8007 (`proxy.pem`). With `source = \"acme\"`, creating the resource has PBS order a " +
			"certificate from the CA of the node's ACME account, for the node's ACME domains — both set with " +
			"`pbs_node_acme` — and install it.\n\n" +
			"**Renewal.** PBS renews the certificate on its own, with the node's ACME settings, in its daily " +
			"update: once two thirds of the certificate's lifetime have passed (from PBS 4.1.9; before that, 30 " +
			"days before it expires). A refresh reads the renewed certificate into the computed " +
			"attributes without planning anything. To order a new certificate now — after changing the node's " +
			"domains, say — change `triggers`.\n\n" +
			"**The fingerprint changes** with every new certificate: when it is ordered, renewed, and when the " +
			"resource is destroyed, which has PBS go back to a new self-signed certificate. Whatever pins the old " +
			"one fails then: the provider itself with `tls_cert_fingerprint`, Proxmox VE's PBS storage " +
			"(`fingerprint` of `proxmox_storage_pbs`), other PBS syncing from this one. With a certificate from a " +
			"public CA, trust it by the CA instead: remove `tls_cert_fingerprint` from the provider, with " +
			"`endpoint` naming one of the certificate's domains, and the fingerprint from the PBS storage.\n\n" +
			"While it changes the certificate, the provider keeps a connection open that it trusted before the " +
			"change, reads the new certificate over it, and trusts the new certificate for the rest of the run, " +
			"so that the run goes on whatever the provider's TLS settings; it warns when they need changing " +
			"before the next run. The guide *Set up PBS for a Proxmox VE cluster* shows the whole switch.\n\n" +
			"Managing the certificate needs `" + certificatesPrivilege + "`, and checking the node's ACME settings " +
			"before an order `" + nodeConfigReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Same value as `node`, present because Terraform requires an `id`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"node": nodeAttribute("certificate"),
			"source": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Where the certificate comes from: `acme`, ordered from the CA of the node's ACME " +
					"account. Changing it replaces the resource, except after an import, which leaves it unset.",
				Validators: []validator.String{stringvalidator.OneOf(certificateSourceACME)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIf(
					func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
						resp.RequiresReplace = !req.StateValue.IsNull()
					},
					"Changing source replaces the resource, unless it was imported.",
					"Changing `source` replaces the resource, unless it was imported.",
				)},
			},
			"triggers": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Arbitrary values that, when any of them changes, have PBS order a new " +
					"certificate in place of the current one, without going back to a self-signed one in between. " +
					"Refer to the node's ACME settings, such as `{ domains = join(\",\", sort(" +
					"pbs_node_acme.this.domains[*].domain)) }`, to order a new certificate whenever they change. " +
					"Mind the CA's rate limits. After an import, the first apply records them without ordering.",
				Validators: []validator.Map{mapvalidator.SizeAtLeast(1)},
			},
			"fingerprint": computedString("SHA-256 fingerprint of the certificate, as PBS shows it: 32 lower-case " +
				"hexadecimal pairs separated by colons. It changes with every renewal."),
			"subject": computedString("Subject of the certificate."),
			"issuer":  computedString("Issuer of the certificate."),
			"san": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "DNS names among the certificate's subject alternative names.",
				PlanModifiers:       []planmodifier.List{listplanmodifier.UseStateForUnknown()},
			},
			"not_before": computedString("Start of the certificate's validity, in RFC 3339 format (UTC)."),
			"not_after":  computedString("End of the certificate's validity, in RFC 3339 format (UTC)."),
		},
	}
}

func (r *nodeCertificateResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = stringIdentitySchema(identityAttribute{"node", "Node name, such as `localhost`."})
}

func (r *nodeCertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan fills in the node, plans the certificate's attributes unknown
// when an order is planned, and warns about what a new certificate breaks.
func (r *nodeCertificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planNode(ctx, r.data, req, resp)
	if resp.Diagnostics.HasError() {
		return
	}
	if req.Plan.Raw.IsNull() {
		r.warnDestroy(ctx, req, resp)
		return
	}
	var plan nodeCertificateModel
	resp.Diagnostics.Append(resp.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	order := req.State.Raw.IsNull()
	if !order {
		var state nodeCertificateModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		// After an import, source is unset: the first apply only records
		// it and the triggers.
		order = !state.Source.IsNull() && !plan.Triggers.Equal(state.Triggers)
		if order {
			plan.Fingerprint, plan.Subject, plan.Issuer = types.StringUnknown(), types.StringUnknown(), types.StringUnknown()
			plan.NotBefore, plan.NotAfter = types.StringUnknown(), types.StringUnknown()
			plan.SAN = types.ListUnknown(types.StringType)
			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		}
	}
	if order && r.data != nil && r.data.client.PinsCertificate() {
		resp.Diagnostics.AddWarning("Ordering a certificate replaces the one the provider pins",
			"This plan has PBS order and install a new certificate on node "+plan.Node.ValueString()+", while the "+
				"provider trusts PBS by tls_cert_fingerprint, which names the current certificate. The provider "+
				"trusts the new certificate for the rest of the apply, and the apply then says how to trust it "+
				"before the next run: by the system's CAs — without tls_cert_fingerprint, with endpoint naming one "+
				"of its domains — for a certificate they trust, or by its new fingerprint for one of a staging or "+
				"private CA.")
	}
}

// warnDestroy warns that destroying the resource gives the node a new
// self-signed certificate.
func (r *nodeCertificateResource) warnDestroy(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	var state nodeCertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.AddWarning("Destroying the certificate gives the node a new self-signed one",
		"Destroying pbs_node_certificate has PBS delete the certificate of node "+state.Node.ValueString()+" and "+
			"generate a new self-signed one, with a new fingerprint; the old certificate is not revoked. The "+
			"provider trusts the new certificate for the rest of the apply. Before the next run, set "+
			"tls_cert_fingerprint to the new fingerprint, which the apply reports, and use it wherever PBS is "+
			"pinned: the fingerprint of Proxmox VE's PBS storage, remotes of other PBS.")
}

// fromCertificate records the certificate the node serves.
func (m *nodeCertificateModel) fromCertificate(node string, cert pbsclient.CertificateInfo, diags *diag.Diagnostics) {
	m.ID = types.StringValue(node)
	m.Node = types.StringValue(node)
	fingerprint := cert.Fingerprint
	if normalised, err := pbsclient.NormaliseFingerprint(cert.Fingerprint); err == nil {
		fingerprint = pbsclient.FormatFingerprint(normalised)
	}
	m.Fingerprint = stringOrNull(fingerprint)
	m.Subject = stringOrNull(cert.Subject)
	m.Issuer = stringOrNull(cert.Issuer)
	san, d := types.ListValueFrom(context.Background(), types.StringType, nonNilStrings(cert.SAN))
	diags.Append(d...)
	m.SAN = san
	m.NotBefore = epochToRFC3339(cert.NotBefore)
	m.NotAfter = epochToRFC3339(cert.NotAfter)
}

// fromUnconfirmed records a certificate the provider could not read: nothing
// about it, since what the server presented was not confirmed to be PBS's.
// The next refresh over a trusted connection fills it in.
func (m *nodeCertificateModel) fromUnconfirmed(node string) {
	m.ID = types.StringValue(node)
	m.Node = types.StringValue(node)
	m.Fingerprint = types.StringNull()
	m.Subject, m.Issuer = types.StringNull(), types.StringNull()
	m.SAN = types.ListNull(types.StringType)
	m.NotBefore, m.NotAfter = types.StringNull(), types.StringNull()
}

// checkACMESettings fails when the node's ACME settings cannot order a
// certificate: PBS would end the order without one, or fail it.
func (r *nodeCertificateResource) checkACMESettings(ctx context.Context, node string, diags *diag.Diagnostics) {
	client := r.data.client
	config, _, err := client.GetNodeConfig(ctx, node)
	if err != nil {
		diags.AddError("Unable to read the ACME settings of the PBS node", apiErrorDetail(client, nodeConfigReadPrivilege, err))
		return
	}
	domains := 0
	for _, raw := range config.ACMEDomains {
		if raw != "" {
			domains++
		}
	}
	if domains == 0 {
		diags.AddError("The PBS node has no ACME domains",
			"Node "+node+" has no ACME domains, so PBS would order no certificate. Set them with pbs_node_acme, and "+
				"make this resource depend on it — with triggers that refer to its domains, or depends_on — so "+
				"that Terraform sets them first.")
		return
	}
	account, err := config.ACMEAccountName()
	if err != nil {
		diags.AddError("Unexpected PBS node configuration",
			fmt.Sprintf("PBS answered an acme property the provider cannot read, %q: %s", config.ACME, err))
		return
	}
	if _, err := client.GetACMEAccount(ctx, account); err != nil {
		if pbsclient.IsNotFound(err) {
			diags.AddError("The ACME account of the PBS node does not exist",
				fmt.Sprintf("Node %s orders certificates with ACME account %q, which PBS does not have. Register it "+
					"with pbs_acme_account, and name it in pbs_node_acme. %s", node, account, err))
			return
		}
		diags.AddError("Unable to read the ACME account of the PBS node", apiErrorDetail(client, certificatesPrivilege, err))
	}
}

// order has the node order a certificate and fills state with it, warning
// about the provider's TLS settings. It reports whether PBS installed one.
func (r *nodeCertificateResource) order(ctx context.Context, plan nodeCertificateModel, state *nodeCertificateModel, diags *diag.Diagnostics) bool {
	client := r.data.client
	node := plan.Node.ValueString()
	r.checkACMESettings(ctx, node, diags)
	if diags.HasError() {
		return false
	}

	change, err := client.ChangeCertificate(ctx, node, func(ctx context.Context) error {
		return client.OrderACMECertificate(ctx, node)
	})
	switch {
	case err != nil && !change.Changed():
		diags.AddError("Unable to order an ACME certificate for the PBS node", orderErrorDetail(client, err))
		return false
	case !change.Changed():
		diags.AddError("PBS installed no new certificate",
			"PBS ordered a certificate for node "+node+" but still serves the one it had: its ACME domains were "+
				"probably removed meanwhile. Check the task log in PBS.")
		return false
	}

	*state = plan
	switch {
	case change.Unconfirmed != nil:
		state.fromUnconfirmed(node)
		diags.AddWarning("Unable to confirm the new PBS certificate",
			"PBS ordered a new certificate for node "+node+", but the provider could not read it over the "+
				"connection it trusted before, so it does not trust the certificate the server presents now, and "+
				"later calls of this run fail. "+unconfirmedAdvice(change.Unconfirmed))
	case err != nil:
		// The only step of the task after it wrote the certificate is having
		// the proxy load it.
		state.fromCertificate(node, change.After, diags)
		diags.AddWarning("The PBS certificate task ended with an error",
			"PBS wrote a new certificate for node "+node+", with fingerprint "+change.After.Fingerprint+", but its "+
				"task then failed, probably while having the proxy load it: the proxy may serve the previous "+
				"certificate until `systemctl reload proxmox-backup-proxy` on the host. Check that first; then "+
				"see to the provider's TLS settings, as the next apply warns. "+err.Error())
	default:
		state.fromCertificate(node, change.After, diags)
		r.warnTrust(change, diags)
	}
	return true
}

// unconfirmedAdvice tells what to do about a certificate the provider could
// not confirm to be PBS's.
func unconfirmedAdvice(unconfirmed *pbsclient.UnconfirmedCertificateError) string {
	return "The server now presents a certificate with SHA-256 fingerprint " +
		pbsclient.FormatFingerprint(unconfirmed.Presented) + ", which the provider could not confirm to be PBS's: " +
		"compare it with `proxmox-backup-manager cert info` on the host, or the dashboard's Show Fingerprint, " +
		"before you pin it anywhere or change the provider's TLS settings to trust it. " + unconfirmed.Error()
}

// orderErrorDetail explains a failed order.
func orderErrorDetail(client *pbsclient.Client, err error) string {
	var taskErr *pbsclient.TaskError
	if errors.As(err, &taskErr) {
		return "The CA did not issue a certificate. The task log in PBS (Administration → Tasks) shows each step; " +
			"common causes are a DNS plugin whose settings or API token are wrong, a validation_delay too short " +
			"for the zone's DNS servers, port 80 not reachable from the CA for a domain without a plugin, and " +
			"the CA's rate limits. " + err.Error()
	}
	return apiErrorDetail(client, certificatesPrivilege, err)
}

// warnTrust warns when the provider's settings do not trust the certificate
// PBS has just installed, which it trusts for the rest of this run only, and
// says what to change: a certificate the system's CAs trust is trusted by
// them, with endpoint naming one of its domains; one they do not trust — from
// Let's Encrypt's staging directory, or a private CA — is pinned.
func (r *nodeCertificateResource) warnTrust(change pbsclient.CertificateChange, diags *diag.Diagnostics) {
	client := r.data.client
	if client.SkipsCertificateVerification() {
		return
	}
	fingerprint := change.After.Fingerprint
	problems := client.CertificateProblems(change.After.PEM)
	pinned, caFile := client.PinsCertificate(), client.UsesCAFile()
	if !pinned && problems.Chain == nil && problems.Host == nil {
		return
	}
	untilNextRun := "PBS now serves a certificate with fingerprint " + fingerprint + ". The provider trusts it for " +
		"the rest of this run only; "
	endpoint := ""
	if problems.Host != nil {
		endpoint = " Set endpoint to one of the certificate's domains, which must resolve to PBS: the certificate " +
			"does not cover " + client.EndpointHost() + " (" + problems.Host.Error() + ")."
	}
	switch {
	case problems.SystemChain != nil && (pinned || problems.Chain != nil):
		detail := untilNextRun + "the system's CAs do not trust it — a certificate of Let's Encrypt's staging " +
			"directory, say, or of a private CA: " + problems.SystemChain.Error() + ". Before the next run, set " +
			"tls_cert_fingerprint (or PBS_TLS_FINGERPRINT) to " + fingerprint + ", or the next run fails to " +
			"connect, and pin it in Proxmox VE's PBS storage too. A pinned fingerprint changes with every renewal."
		if caFile {
			detail += " Remove ca_cert_file (and PBS_CA_CERT_FILE) then, which the fingerprint conflicts with — or " +
				"put the CA's root into it instead of pinning."
		}
		diags.AddWarning("Pin the new PBS certificate by its fingerprint", detail)
	case problems.Chain != nil:
		diags.AddWarning("Remove ca_cert_file from the provider configuration",
			untilNextRun+"ca_cert_file does not hold its CA, while the system's CAs trust it. Before the next run, "+
				"remove ca_cert_file (and PBS_CA_CERT_FILE), so that the provider verifies the certificate against "+
				"the system's CAs, or the next run fails to connect."+endpoint)
	case pinned:
		diags.AddWarning("Remove tls_cert_fingerprint from the provider configuration",
			untilNextRun+"the provider pins the previous one with tls_cert_fingerprint. Before the next run, remove "+
				"tls_cert_fingerprint (and PBS_TLS_FINGERPRINT), so that the provider verifies the certificate "+
				"against the system's CAs, or the next run fails to connect; pinning the new fingerprint instead "+
				"fails at the first renewal. Remove the fingerprint from Proxmox VE's PBS storage "+
				"(proxmox_storage_pbs) too."+endpoint)
	default:
		diags.AddWarning("Set endpoint to a domain of the new PBS certificate",
			untilNextRun+"the provider verifies it against its CAs, and it does not cover the host of endpoint."+endpoint)
	}
}

func (r *nodeCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan nodeCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state nodeCertificateModel
	if !r.order(ctx, plan, &state, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	setIdentity(ctx, resp.Identity, "node", state.Node.ValueString(), &resp.Diagnostics)
}

// Read refreshes the certificate's attributes, which change with every
// renewal without planning anything. A node that serves a self-signed
// certificate has no ACME certificate any more: the resource is gone, and
// Terraform plans to order one.
func (r *nodeCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state nodeCertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := state.Node.ValueString()
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)

	cert, err := r.data.client.NodeProxyCertificate(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the certificate of the PBS node",
			apiErrorDetail(r.data.client, certificatesPrivilege, err))
		return
	}
	if cert.SelfSigned() && (state.Source.IsNull() || state.Source.ValueString() == certificateSourceACME) {
		resp.Diagnostics.AddWarning("The PBS node serves a self-signed certificate",
			"Node "+node+" serves a self-signed certificate, so its ACME certificate is gone — deleted outside "+
				"Terraform, or never ordered for an import —, and pbs_node_certificate is removed from state. A plan "+
				"orders a new certificate.")
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromCertificate(node, cert, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update orders a new certificate when triggers changed; otherwise — or
// after an import, which leaves source and triggers unset — it only records
// the plan.
func (r *nodeCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior nodeCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := plan.Node.ValueString()
	if !prior.Source.IsNull() && !plan.Triggers.Equal(prior.Triggers) {
		var state nodeCertificateModel
		if !r.order(ctx, plan, &state, &resp.Diagnostics) {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
		return
	}

	// The plan holds the certificate's attributes from state. Reading them
	// again could meet a renewal since, which would not match the plan; the
	// next refresh records it. They are unknown only when triggers were
	// unknown at plan time and turned out unchanged.
	if plan.Fingerprint.IsUnknown() {
		cert, err := r.data.client.NodeProxyCertificate(ctx, node)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read the certificate of the PBS node",
				apiErrorDetail(r.data.client, certificatesPrivilege, err))
			return
		}
		plan.fromCertificate(node, cert, &resp.Diagnostics)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
}

// Delete has the node go back to a new self-signed certificate, which the
// provider trusts for the rest of the run, and reports its fingerprint.
func (r *nodeCertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state nodeCertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.data.client
	node := state.Node.ValueString()
	change, err := client.ChangeCertificate(ctx, node, func(ctx context.Context) error {
		return client.DeleteCustomCertificate(ctx, node)
	})
	if err != nil && !change.Changed() {
		resp.Diagnostics.AddError("Unable to delete the certificate of the PBS node", apiErrorDetail(client, certificatesPrivilege, err))
		return
	}
	var detail string
	switch {
	case change.Unconfirmed != nil:
		detail = "PBS deleted the certificate of node " + node + " and generated a new self-signed one, but the " +
			"provider could not read it over the connection it trusted before, so it does not trust the " +
			"certificate the server presents now, and later calls of this run fail. " + unconfirmedAdvice(change.Unconfirmed)
	case err != nil:
		detail = "PBS deleted the certificate of node " + node + " and generated a new self-signed one, with " +
			"SHA-256 fingerprint " + change.After.Fingerprint + ", but then failed, probably while having the proxy " +
			"load it: the proxy may serve the previous certificate until `systemctl reload " +
			"proxmox-backup-proxy` on the host. Once it serves the new one, use its fingerprint wherever PBS is " +
			"pinned: tls_cert_fingerprint of this provider, the fingerprint of Proxmox VE's PBS storage " +
			"(proxmox_storage_pbs), remotes of other PBS. " + err.Error()
	default:
		detail = "PBS deleted the certificate of node " + node + " and generated a new self-signed one, with SHA-256 " +
			"fingerprint " + change.After.Fingerprint + ". Use it wherever PBS is pinned: tls_cert_fingerprint of " +
			"this provider, the fingerprint of Proxmox VE's PBS storage (proxmox_storage_pbs), remotes of other " +
			"PBS. The pbs_fingerprint data source reads it."
		if !client.SkipsCertificateVerification() {
			detail += " The provider trusts it for the rest of this run only."
		}
	}
	resp.Diagnostics.AddWarning("The PBS node serves a new self-signed certificate", detail)
}

// ImportState imports the certificate of a node by the node's name, given
// either as the import id or, from Terraform 1.12, as the identity of an
// import block. source stays unset until the next apply records it, which
// orders nothing.
func (r *nodeCertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	node, ok := importedNode(ctx, req, resp, "certificate")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node"), node)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), node)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
}
