package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &nodeCertificatesDataSource{}
	_ datasource.DataSourceWithConfigure = &nodeCertificatesDataSource{}
)

// NewNodeCertificatesDataSource returns the pbs_node_certificates data source.
func NewNodeCertificatesDataSource() datasource.DataSource { return &nodeCertificatesDataSource{} }

type nodeCertificatesDataSource struct {
	data *providerData
}

type nodeCertificatesDataSourceModel struct {
	Node         types.String               `tfsdk:"node"`
	Certificates []nodeCertificateDataModel `tfsdk:"certificates"`
}

type nodeCertificateDataModel struct {
	Filename      types.String `tfsdk:"filename"`
	Fingerprint   types.String `tfsdk:"fingerprint"`
	Subject       types.String `tfsdk:"subject"`
	Issuer        types.String `tfsdk:"issuer"`
	NotBefore     types.String `tfsdk:"not_before"`
	NotAfter      types.String `tfsdk:"not_after"`
	SAN           types.List   `tfsdk:"san"`
	PEM           types.String `tfsdk:"pem"`
	PublicKeyType types.String `tfsdk:"public_key_type"`
	PublicKeyBits types.Int64  `tfsdk:"public_key_bits"`
}

func (d *nodeCertificatesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node_certificates"
}

func (d *nodeCertificatesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the certificates of a Proxmox Backup Server node, as the Certificates panel of " +
			"its interface shows them. PBS has only one: `proxy.pem`, which its web interface and API serve on " +
			"port 8007 — the self-signed certificate PBS generates, an ACME one, or a custom one. The list gives " +
			"its fingerprint, subject, validity, DNS names, public key, and the whole PEM file with the chain; the " +
			"private key, `proxy.key`, is never returned. For the fingerprint alone, `pbs_fingerprint` is " +
			"simpler.\n\n" +
			"Needs `" + certificatesPrivilege + "` — unlike `pbs_node_status`, which shows the fingerprint with " +
			"`Sys.Audit on /system/status`.",
		Attributes: map[string]schema.Attribute{
			"node": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Node to read: `localhost` or the node's host name. Defaults to the provider's `node`.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 63),
					stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
				},
			},
			"certificates": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The node's certificates, ordered by `filename`. PBS 4 lists exactly one, " +
					"`proxy.pem`.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"filename": computedString("File name of the certificate in `/etc/proxmox-backup`: `proxy.pem`."),
					"fingerprint": computedString("SHA-256 fingerprint of the certificate, as PBS shows it and " +
						"`pbs_fingerprint` reports it: 32 lower-case hexadecimal pairs separated by colons. Null " +
						"when PBS does not report it."),
					"subject": computedString("Subject of the certificate, as PBS shows it: `<field> = <value>` " +
						"entries separated by commas, such as `O = Proxmox Backup Server, OU = <UUID>, CN = " +
						"pbs.example.com` for the certificate PBS generates."),
					"issuer": computedString("Issuer of the certificate, in the same form; the same as `subject` " +
						"for a self-signed one."),
					"not_before": computedString("Start of the certificate's validity, in RFC 3339 format (UTC); " +
						"null when PBS cannot read it."),
					"not_after": computedString("End of the certificate's validity, in RFC 3339 format (UTC); " +
						"null when PBS cannot read it. The certificate PBS generates is valid for 365,000 days."),
					"san": schema.ListAttribute{
						Computed:    true,
						ElementType: types.StringType,
						MarkdownDescription: "DNS names among the certificate's subject alternative names, in the " +
							"certificate's order, such as `localhost`, the host name and the fully qualified " +
							"domain name for the certificate PBS generates. PBS leaves out IP addresses; empty " +
							"when there are no DNS names.",
					},
					"pem": computedString("The whole `proxy.pem` in PEM format: the certificate, followed by its " +
						"chain when there is one. It holds no private key. Null when PBS does not report it."),
					"public_key_type": computedString("Algorithm of the certificate's public key, as OpenSSL " +
						"names it, such as `rsaEncryption` — the certificate PBS generates has an RSA key — or " +
						"`id-ecPublicKey` for an elliptic-curve key."),
					"public_key_bits": schema.Int64Attribute{
						Computed: true,
						MarkdownDescription: "Size of the public key, in bits, such as `4096` for the RSA key of " +
							"the certificate PBS generates; null when PBS does not report it.",
					},
				}},
			},
		},
	}
}

func (d *nodeCertificatesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *nodeCertificatesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config nodeCertificatesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	certs, err := d.data.client.NodeCertificates(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the certificates of the PBS node",
			apiErrorDetail(d.data.client, certificatesPrivilege, err))
		return
	}
	// PBS lists proxy.pem alone; should a release list more, the order of
	// the file names keeps the list stable.
	sort.Slice(certs, func(i, j int) bool { return certs[i].Filename < certs[j].Filename })

	model := nodeCertificatesDataSourceModel{
		Node:         types.StringValue(node),
		Certificates: make([]nodeCertificateDataModel, 0, len(certs)),
	}
	for _, cert := range certs {
		// Normalised and formatted as pbs_fingerprint does, so that both
		// report the same value.
		fingerprint := cert.Fingerprint
		if normalised, err := pbsclient.NormaliseFingerprint(cert.Fingerprint); err == nil {
			fingerprint = pbsclient.FormatFingerprint(normalised)
		}
		// PBS leaves the size out when OpenSSL cannot tell it; no key has
		// zero bits.
		bits := types.Int64Null()
		if cert.PublicKeyBits > 0 {
			bits = types.Int64Value(cert.PublicKeyBits)
		}
		san, diags := types.ListValueFrom(ctx, types.StringType, nonNilStrings(cert.SAN))
		resp.Diagnostics.Append(diags...)
		model.Certificates = append(model.Certificates, nodeCertificateDataModel{
			Filename:      types.StringValue(cert.Filename),
			Fingerprint:   stringOrNull(fingerprint),
			Subject:       types.StringValue(cert.Subject),
			Issuer:        types.StringValue(cert.Issuer),
			NotBefore:     epochToRFC3339(cert.NotBefore),
			NotAfter:      epochToRFC3339(cert.NotAfter),
			SAN:           san,
			PEM:           stringOrNull(cert.PEM),
			PublicKeyType: types.StringValue(cert.PublicKeyType),
			PublicKeyBits: bits,
		})
	}
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
