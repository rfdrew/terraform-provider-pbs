package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ resource.Resource                   = &nodeCertificateResource{}
	_ resource.ResourceWithConfigure      = &nodeCertificateResource{}
	_ resource.ResourceWithIdentity       = &nodeCertificateResource{}
	_ resource.ResourceWithImportState    = &nodeCertificateResource{}
	_ resource.ResourceWithModifyPlan     = &nodeCertificateResource{}
	_ resource.ResourceWithValidateConfig = &nodeCertificateResource{}
)

// NewNodeCertificateResource returns the pbs_node_certificate resource.
func NewNodeCertificateResource() resource.Resource { return &nodeCertificateResource{} }

type nodeCertificateResource struct {
	data *providerData
}

type nodeCertificateModel struct {
	ID           types.String          `tfsdk:"id"`
	Node         types.String          `tfsdk:"node"`
	Source       types.String          `tfsdk:"source"`
	Triggers     types.Map             `tfsdk:"triggers"`
	Certificates certificateChainValue `tfsdk:"certificates"`
	KeyWO        types.String          `tfsdk:"key_wo"`
	KeyWOVersion types.Int64           `tfsdk:"key_wo_version"`
	Fingerprint  types.String          `tfsdk:"fingerprint"`
	Subject      types.String          `tfsdk:"subject"`
	Issuer       types.String          `tfsdk:"issuer"`
	SAN          types.List            `tfsdk:"san"`
	NotBefore    types.String          `tfsdk:"not_before"`
	NotAfter     types.String          `tfsdk:"not_after"`
}

// Where the certificate comes from: ordered from an ACME CA, or uploaded.
const (
	certificateSourceACME   = "acme"
	certificateSourceCustom = "custom"
)

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
	// The key goes with every upload of the chain, not only with a new
	// version, so the pair's shared descriptions do not fit.
	keyWO, keyWOVersion := writeOnlySecretAttributes("key", "")
	keyWO.MarkdownDescription = "Private key of the certificate, PEM-encoded and unencrypted — PKCS #8, or a " +
		"PKCS #1 RSA or SEC 1 EC key —, with `source = \"custom\"`, which requires it and `key_wo_version`. The " +
		"provider checks before uploading that it is the key of the first certificate of `certificates`: PBS " +
		"does not, and with a key that is not, its proxy keeps the old certificate and fails to start the next " +
		"time. Write-only: Terraform passes it to PBS without storing it in the plan or state, and PBS never " +
		"returns it. It is sent with every upload of the chain: when the resource is created, when `certificates` " +
		"or `source` changes, when the node no longer serves the certificate, and when `key_wo_version` changes. " +
		"Requires Terraform or OpenTofu 1.11 or later."
	keyWOVersion.MarkdownDescription = "Version of `key_wo`, which Terraform stores in its place. Changing it " +
		"uploads the chain again with `key_wo`, even an unchanged one — but on the first apply after an import, " +
		"which uploads only a chain the node does not serve. Requires `key_wo`."
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the certificate a Proxmox Backup Server node serves its web interface and API " +
			"with, on port 8007 (`proxy.pem`). With `source = \"acme\"`, creating the resource has PBS order a " +
			"certificate from the CA of the node's ACME account, for the node's ACME domains — both set with " +
			"`pbs_node_acme` — and install it. With `source = \"custom\"`, it uploads a certificate chain and its " +
			"key, from your own CA, say, or the `tls` provider. PBS loads either at once, without restarting its " +
			"proxy; connections open before keep the old one.\n\n" +
			"**Renewal.** PBS renews the certificate on its own in its daily update, while the node has ACME " +
			"domains: once two thirds of the certificate's lifetime have passed (from PBS 4.1.9; before that, 30 " +
			"days before it expires). A refresh reads the renewed certificate into the computed " +
			"attributes without planning anything. To order a new certificate now — after changing the node's " +
			"domains, say — change `triggers`, or, with Terraform 1.14.1 or later, invoke the " +
			"`pbs_node_certificate_renew` action with `force = true`: without it, PBS renews only a certificate " +
			"that is due, and a change of domains does not make it due. PBS cannot tell an uploaded certificate " +
			"from an ordered one, so it renews a custom certificate the same way, with an ACME one, on a node with " +
			"ACME domains: keep `pbs_node_acme` away from a node with a custom certificate. A custom certificate " +
			"the node no longer serves shows as a change of `certificates`, and the next apply uploads it " +
			"again.\n\n" +
			"**The fingerprint changes** with every new certificate: when it is ordered, uploaded, renewed, and " +
			"when the resource is destroyed, which has PBS go back to a new self-signed certificate. Whatever " +
			"pins the old one fails then: the provider itself with `tls_cert_fingerprint`, Proxmox VE's PBS " +
			"storage (`fingerprint` of `proxmox_storage_pbs`), other PBS syncing from this one. With a certificate " +
			"from a public CA, trust it by the CA instead: remove `tls_cert_fingerprint` from the provider, with " +
			"`endpoint` naming one of the certificate's domains, and the fingerprint from the PBS storage. A " +
			"custom certificate's `fingerprint` is known when planning once `certificates` is, and the PBS " +
			"storage can follow it in the same apply in any case.\n\n" +
			"While it changes the certificate, the provider keeps a connection open that it trusted before the " +
			"change, reads the new certificate over it, and trusts the new certificate for the rest of the run, " +
			"so that the run goes on whatever the provider's TLS settings; it warns when they need changing " +
			"before the next run. The guide *Set up PBS for a Proxmox VE cluster* shows the whole switch.\n\n" +
			"Managing the certificate needs `" + certificatesPrivilege + "`, and checking the node's ACME settings " +
			"`" + nodeConfigReadPrivilege + "`.",
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
					"account, or `custom`, uploaded from `certificates` and `key_wo`. Changing it installs a " +
					"certificate from the new source in place of the current one. After an import, which leaves it " +
					"unset, the first apply records it without ordering, and uploads only a certificate the node " +
					"does not serve.",
				Validators: []validator.String{stringvalidator.OneOf(certificateSourceACME, certificateSourceCustom)},
			},
			"triggers": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "With `source = \"acme\"`: arbitrary values that, when any of them changes, have " +
					"PBS order a new certificate in place of the current one, without going back to a self-signed " +
					"one in between. Refer to the node's ACME settings, such as `{ domains = join(\",\", sort(" +
					"pbs_node_acme.this.domains[*].domain)) }`, to order a new certificate whenever they change. " +
					"Mind the CA's rate limits. After an import, the first apply records them without ordering.",
				Validators: []validator.Map{mapvalidator.SizeAtLeast(1)},
			},
			"certificates": schema.StringAttribute{
				CustomType: certificateChainType{},
				Optional:   true,
				MarkdownDescription: "With `source = \"custom\"`, which requires it: the certificate chain, " +
					"PEM-encoded — the node's certificate first, then its intermediate CAs, with nothing else between " +
					"them. PBS stores it re-encoded; the same certificates in another layout are no change. Changing " +
					"it uploads the new chain.",
			},
			"key_wo":         keyWO,
			"key_wo_version": keyWOVersion,
			"fingerprint": computedString("SHA-256 fingerprint of the certificate, as PBS shows it: 32 lower-case " +
				"hexadecimal pairs separated by colons. It changes with every new certificate; for a custom one, " +
				"it is known when planning once `certificates` is."),
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

// ValidateConfig checks that the attributes fit the source, and, for a
// custom certificate whose chain and key are known, that the key is the
// certificate's, which PBS does not check.
func (r *nodeCertificateResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config nodeCertificateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Source.IsUnknown() {
		return
	}
	custom := config.Source.ValueString() == certificateSourceCustom
	set := map[string]bool{
		"certificates":   !config.Certificates.IsNull(),
		"key_wo":         !config.KeyWO.IsNull(),
		"key_wo_version": !config.KeyWOVersion.IsNull(),
	}
	for _, name := range []string{"certificates", "key_wo", "key_wo_version"} {
		switch {
		case custom && !set[name] && name != "key_wo_version":
			resp.Diagnostics.AddAttributeError(path.Root(name), "Custom certificate needs "+name,
				"With source = \"custom\", set certificates to the certificate chain and key_wo, with "+
					"key_wo_version, to its private key.")
		case !custom && set[name]:
			resp.Diagnostics.AddAttributeError(path.Root(name), "Attribute needs a custom certificate",
				name+" is for source = \"custom\" only: an ACME certificate's key never leaves PBS.")
		}
	}
	if custom && !config.Triggers.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("triggers"), "Triggers order ACME certificates",
			"triggers order a new ACME certificate, and a custom certificate is uploaded again whenever certificates "+
				"or key_wo_version changes: remove triggers, or set source to \"acme\".")
	}
	if resp.Diagnostics.HasError() || !custom || config.Certificates.IsUnknown() || config.KeyWO.IsUnknown() {
		return
	}
	if _, err := pbsclient.CheckCustomCertificate(config.Certificates.ValueString(), config.KeyWO.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("certificates"), "Invalid custom certificate", err.Error())
	}
}

// ModifyPlan fills in the node, plans the certificate's attributes unknown
// when a new certificate is planned — but for the fingerprint of a custom
// one, which the chain gives —, and warns about what a new certificate
// breaks.
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
	var state *nodeCertificateModel
	if !req.State.Raw.IsNull() {
		state = &nodeCertificateModel{}
		resp.Diagnostics.Append(req.State.Get(ctx, state)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	install := plan.installs(state)
	if !install {
		return
	}
	newFingerprint := ""
	if plan.Source.ValueString() == certificateSourceCustom && !plan.Certificates.IsUnknown() {
		if certs, err := pbsclient.CheckCertificateChain(plan.Certificates.ValueString()); err == nil {
			newFingerprint = pbsclient.FormatFingerprint(pbsclient.CertificateFingerprint(certs[0]))
		}
	}
	if state != nil {
		if newFingerprint != "" && state.Fingerprint.ValueString() == newFingerprint {
			// The node may serve the certificate already: after an import,
			// or with a new key version.
			plan.Fingerprint = types.StringValue(newFingerprint)
		} else {
			plan.Fingerprint = stringOrUnknown(newFingerprint)
			plan.Subject, plan.Issuer = types.StringUnknown(), types.StringUnknown()
			plan.NotBefore, plan.NotAfter = types.StringUnknown(), types.StringUnknown()
			plan.SAN = types.ListUnknown(types.StringType)
		}
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	} else if newFingerprint != "" {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("fingerprint"), newFingerprint)...)
	}
	if r.data == nil || !r.data.client.PinsCertificate() || (state != nil && state.Fingerprint.ValueString() == newFingerprint) {
		return
	}
	if plan.Source.ValueString() == certificateSourceCustom {
		detail := "This plan uploads a certificate to node " + plan.Node.ValueString() + ", while the provider " +
			"trusts PBS by tls_cert_fingerprint, which names the current certificate. The provider trusts the new " +
			"certificate for the rest of the apply; before the next run, trust it by its CA — without " +
			"tls_cert_fingerprint, with endpoint naming one of its domains —, or pin it"
		if newFingerprint != "" {
			detail += ": its fingerprint is " + newFingerprint
		}
		resp.Diagnostics.AddWarning("Uploading a certificate replaces the one the provider pins", detail+".")
		return
	}
	resp.Diagnostics.AddWarning("Ordering a certificate replaces the one the provider pins",
		"This plan has PBS order and install a new certificate on node "+plan.Node.ValueString()+", while the "+
			"provider trusts PBS by tls_cert_fingerprint, which names the current certificate. The provider "+
			"trusts the new certificate for the rest of the apply, and the apply then says how to trust it "+
			"before the next run: by the system's CAs — without tls_cert_fingerprint, with endpoint naming one "+
			"of its domains — for a certificate they trust, or by its new fingerprint for one of a staging or "+
			"private CA.")
}

// stringOrUnknown is s, or unknown for the empty string.
func stringOrUnknown(s string) types.String {
	if s == "" {
		return types.StringUnknown()
	}
	return types.StringValue(s)
}

// installs reports whether applying m, against the prior state, if any,
// installs a new certificate — or, for a custom one, may: it is uploaded
// only when the node does not serve it, or with a new key version.
func (m nodeCertificateModel) installs(prior *nodeCertificateModel) bool {
	switch {
	case prior == nil:
		return true
	case m.Source.ValueString() == certificateSourceCustom:
		return !prior.Source.Equal(m.Source) || m.Certificates.IsUnknown() ||
			!sameCertificateChain(m.Certificates.ValueString(), prior.Certificates.ValueString()) ||
			writeOnlyChanged(m.KeyWOVersion, prior.KeyWOVersion)
	case prior.Source.IsNull():
		// After an import, the first apply only records an ACME source.
		return false
	default:
		return !prior.Source.Equal(m.Source) || !m.Triggers.Equal(prior.Triggers)
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
// certificate: PBS would end the order without one, or fail it — and send
// its acme-err notification. setDomainsFirst ends the advice to set the
// node's domains with pbs_node_acme: how to have Terraform set them before
// it orders. pbs_node_certificate_renew checks the settings too.
func (r *nodeCertificateResource) checkACMESettings(ctx context.Context, node, setDomainsFirst string, diags *diag.Diagnostics) {
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
			"Node "+node+" has no ACME domains, so PBS would order no certificate. Set them with pbs_node_acme, "+
				setDomainsFirst)
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
	r.checkACMESettings(ctx, node, "and make this resource depend on it — with triggers that refer to its domains, "+
		"or depends_on — so that Terraform sets them first.", diags)
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
	r.recordChange(node, change, err, "task", state, diags)
	return true
}

// upload installs the planned custom certificate, with the key in config —
// unless force is false and the node serves the certificate already —, and
// fills state with it. It reports whether the certificate is in place.
func (r *nodeCertificateResource) upload(ctx context.Context, plan nodeCertificateModel, force bool, config tfsdk.Config, state *nodeCertificateModel, diags *diag.Diagnostics) bool {
	client := r.data.client
	node := plan.Node.ValueString()
	certificates := plan.Certificates.ValueString()
	key, ok := writeOnlySecret(ctx, config, "key", diags)
	if diags.HasError() {
		return false
	}
	if !ok {
		diags.AddAttributeError(path.Root("key_wo"), "Custom certificate needs key_wo",
			"Uploading a custom certificate needs its private key, key_wo, which the configuration does not set.")
		return false
	}
	leaf, err := pbsclient.CheckCustomCertificate(certificates, key)
	if err != nil {
		diags.AddAttributeError(path.Root("certificates"), "Invalid custom certificate", err.Error())
		return false
	}

	if !force {
		served, err := client.NodeProxyCertificate(ctx, node)
		if err != nil {
			diags.AddError("Unable to read the certificate of the PBS node", apiErrorDetail(client, certificatesPrivilege, err))
			return false
		}
		if sameCertificateChain(served.PEM, certificates) {
			*state = plan
			state.fromCertificate(node, served, diags)
			return true
		}
	}

	change, err := client.ChangeCertificate(ctx, node, func(ctx context.Context) error {
		return client.UploadCustomCertificate(ctx, node, certificates, key)
	})
	if err != nil && !change.Changed() {
		diags.AddError("Unable to upload the certificate of the PBS node", apiErrorDetail(client, certificatesPrivilege, err))
		return false
	}
	if change.Unconfirmed != nil && change.Unconfirmed.Presented == leaf {
		// The server presents the certificate the configuration holds, which
		// the provider uploaded: it may trust it, and read it now.
		if trustErr := client.TrustCertificate(leaf); trustErr == nil {
			if after, readErr := client.NodeProxyCertificate(ctx, node); readErr == nil {
				change.After, change.Unconfirmed = after, nil
			}
		}
	}
	*state = plan
	switch after, normErr := pbsclient.NormaliseFingerprint(change.After.Fingerprint); {
	case change.Unconfirmed != nil && change.Unconfirmed.Presented == leaf:
		state.fromUnconfirmed(node)
		state.Fingerprint = types.StringValue(pbsclient.FormatFingerprint(leaf))
		diags.AddWarning("Unable to read the new PBS certificate",
			"PBS serves the uploaded certificate on node "+node+", but reading its details failed; the next "+
				"refresh reads them. "+change.Unconfirmed.Error())
		return true
	case change.Unconfirmed != nil:
		diags.AddError("PBS presents another certificate",
			"The provider uploaded a certificate with SHA-256 fingerprint "+pbsclient.FormatFingerprint(leaf)+
				" to node "+node+", but the server now presents another one. "+unconfirmedAdvice(change.Unconfirmed))
		return false
	case normErr != nil || after != leaf:
		diags.AddError("PBS installed another certificate",
			fmt.Sprintf("The provider uploaded a certificate with SHA-256 fingerprint %s to node %s, but PBS now "+
				"reports one with %s. Check the node's certificate (Configuration → Certificates).",
				pbsclient.FormatFingerprint(leaf), node, change.After.Fingerprint))
		return false
	}
	if r.proxyKeptPrevious(ctx, change, leaf) {
		diags.AddError("The PBS proxy did not load the uploaded certificate",
			"PBS wrote the certificate with SHA-256 fingerprint "+pbsclient.FormatFingerprint(leaf)+" to node "+node+
				", but its proxy still serves the previous one: it could not load the new chain — its journal says "+
				"\"error reloading certificate\". The proxy will not start again, at its next restart, reload or "+
				"package upgrade, until it has a certificate it can load: upload another one, or destroy "+
				"pbs_node_certificate, which has PBS generate a new self-signed one. A raised security level in "+
				"ciphers_tls_1_2 of pbs_node_config (@SECLEVEL) is a common cause.")
		return false
	}
	r.recordChange(node, change, err, "upload", state, diags)
	r.warnACMERenewal(ctx, node, diags)
	return true
}

// proxyKeptPrevious reports whether, after a change PBS reports done, its
// proxy still presents the certificate from before on a new connection:
// PBS writes the files before the proxy tries to load them, and only logs
// when it cannot. A certificate other than both — from a TLS front end —
// is no sign of that. The proxy loads the new certificate before PBS
// answers, so a few tries are enough.
func (r *nodeCertificateResource) proxyKeptPrevious(ctx context.Context, change pbsclient.CertificateChange, leaf string) bool {
	before, err := pbsclient.NormaliseFingerprint(change.Before.Fingerprint)
	if err != nil || before == leaf {
		return false
	}
	for attempt := 1; ; attempt++ {
		presented, err := r.data.client.PresentedFingerprint(ctx)
		if err != nil || presented != before {
			return false
		}
		if attempt == proxyLoadAttempts {
			return true
		}
		select {
		case <-time.After(proxyLoadInterval):
		case <-ctx.Done():
			return false
		}
	}
}

// How often, and how far apart, proxyKeptPrevious looks.
const (
	proxyLoadAttempts = 3
	proxyLoadInterval = 500 * time.Millisecond
)

// recordChange fills state with the certificate a change installed and
// warns about it, as what returned err — the task of an order, or an upload
// — ended.
func (r *nodeCertificateResource) recordChange(node string, change pbsclient.CertificateChange, err error, what string, state *nodeCertificateModel, diags *diag.Diagnostics) {
	switch {
	case change.Unconfirmed != nil:
		state.fromUnconfirmed(node)
		diags.AddWarning("Unable to confirm the new PBS certificate",
			"PBS installed a new certificate on node "+node+", but the provider could not read it over the "+
				"connection it trusted before, so it does not trust the certificate the server presents now, and "+
				"later calls of this run fail. "+unconfirmedAdvice(change.Unconfirmed))
	case err != nil:
		// The only step after writing the certificate is having the proxy
		// load it. The provider trusts the new certificate all the same, so
		// its TLS settings need what they need after a change that went
		// well: nothing else warns about them, neither a later plan nor the
		// action, which runs once.
		state.fromCertificate(node, change.After, diags)
		diags.AddWarning("The PBS certificate "+what+" ended with an error",
			"PBS wrote a new certificate for node "+node+", with fingerprint "+change.After.Fingerprint+", but its "+
				what+" then failed, probably while having the proxy load it: the proxy may serve the previous "+
				"certificate until `systemctl reload proxmox-backup-proxy` on the host. Check that first, and only "+
				"then change the provider's TLS settings where another warning says they need it. "+err.Error())
		r.warnTrust(change, diags)
	default:
		state.fromCertificate(node, change.After, diags)
		r.warnTrust(change, diags)
	}
}

// warnACMERenewal warns when the node has ACME domains, with which PBS
// renews a custom certificate with an ACME one.
func (r *nodeCertificateResource) warnACMERenewal(ctx context.Context, node string, diags *diag.Diagnostics) {
	config, _, err := r.data.client.GetNodeConfig(ctx, node)
	if err != nil {
		return
	}
	for _, raw := range config.ACMEDomains {
		if raw != "" {
			diags.AddWarning("PBS will replace the custom certificate with an ACME one",
				"Node "+node+" has ACME domains, set with pbs_node_acme or in its interface. PBS cannot tell an "+
					"uploaded certificate from an ordered one, and its daily update renews whatever certificate the "+
					"node serves, with ACME, as it nears its end: from PBS 4.1.9 once two thirds of its lifetime "+
					"have passed (half, for one shorter than ten days), before that 30 days before it expires. "+
					"Remove the node's ACME domains to keep the custom certificate.")
			return
		}
	}
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
	if client.SkipsCertificateVerification() || !change.Changed() {
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
	var installed bool
	if plan.Source.ValueString() == certificateSourceCustom {
		installed = r.upload(ctx, plan, true, req.Config, &state, &resp.Diagnostics)
	} else {
		installed = r.order(ctx, plan, &state, &resp.Diagnostics)
	}
	if !installed {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	setIdentity(ctx, resp.Identity, "node", state.Node.ValueString(), &resp.Diagnostics)
}

// Read refreshes the certificate's attributes, which change with every
// renewal without planning anything. A node that serves the self-signed
// certificate PBS generates has no certificate of the resource any more:
// the resource is gone, and Terraform plans to install one. A node that does
// not serve the custom certificate of the resource gets it uploaded again.
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
	switch {
	case state.Source.ValueString() == certificateSourceCustom:
		if !sameCertificateChain(state.Certificates.ValueString(), cert.PEM) {
			resp.Diagnostics.AddWarning("The PBS node serves another certificate",
				"Node "+node+" serves a certificate issued by "+cert.Issuer+", not the custom certificate of "+
					"pbs_node_certificate: PBS renewed it with ACME, as it does on a node with ACME domains, or it was "+
					"changed outside Terraform. A plan uploads the custom certificate again.")
			state.Certificates = certificateChainValue{StringValue: types.StringValue(cert.PEM)}
		}
	case cert.Generated():
		resp.Diagnostics.AddWarning("The PBS node serves its own self-signed certificate",
			"Node "+node+" serves the self-signed certificate PBS generated, so its certificate is gone — deleted "+
				"outside Terraform, or never installed for an import —, and pbs_node_certificate is removed from "+
				"state. A plan installs a new certificate.")
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromCertificate(node, cert, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update orders a new certificate when triggers or the source changed, and
// uploads a custom one when the node does not serve it or the key is to be
// sent again; otherwise — or after an import of an ACME certificate, which
// leaves source and triggers unset — it only records the plan.
func (r *nodeCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior nodeCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := plan.Node.ValueString()
	if plan.installs(&prior) {
		var state nodeCertificateModel
		var installed bool
		if plan.Source.ValueString() == certificateSourceCustom {
			// A new key version sends the key again; a new chain, or the
			// first apply after an import, uploads only a chain the node
			// does not serve.
			force := !prior.Source.IsNull() && writeOnlyChanged(plan.KeyWOVersion, prior.KeyWOVersion)
			installed = r.upload(ctx, plan, force, req.Config, &state, &resp.Diagnostics)
		} else {
			installed = r.order(ctx, plan, &state, &resp.Diagnostics)
		}
		if !installed {
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
// orders nothing and uploads only a custom certificate the node does not
// serve.
func (r *nodeCertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	node, ok := importedNode(ctx, req, resp, "certificate")
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node"), node)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), node)...)
	setIdentity(ctx, resp.Identity, "node", node, &resp.Diagnostics)
}
