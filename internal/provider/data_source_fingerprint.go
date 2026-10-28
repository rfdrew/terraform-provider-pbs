package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &fingerprintDataSource{}
	_ datasource.DataSourceWithConfigure = &fingerprintDataSource{}
)

// NewFingerprintDataSource returns the pbs_fingerprint data source.
func NewFingerprintDataSource() datasource.DataSource { return &fingerprintDataSource{} }

type fingerprintDataSource struct {
	data *providerData
}

type fingerprintDataSourceModel struct {
	Fingerprint types.String `tfsdk:"fingerprint"`
	Subject     types.String `tfsdk:"subject"`
	Issuer      types.String `tfsdk:"issuer"`
	NotBefore   types.String `tfsdk:"not_before"`
	NotAfter    types.String `tfsdk:"not_after"`
	SAN         types.List   `tfsdk:"san"`
}

func (d *fingerprintDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fingerprint"
}

func (d *fingerprintDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reports the SHA-256 fingerprint of the certificate the server's web interface and " +
			"API serve on port 8007 (`proxy.pem`), with the certificate's subject and validity. Proxmox VE " +
			"pins a PBS storage by this fingerprint, and so does another PBS that syncs from this one: pass it " +
			"to the `fingerprint` of `proxmox_storage_pbs` in the bpg/proxmox provider, or of a remote.\n\n" +
			"Reading it needs `" + certificatesPrivilege + "`.\n\n" +
			"~> **The fingerprint changes** whenever the certificate does: a new custom certificate, an ACME " +
			"renewal, or deleting the custom certificate, which makes PBS generate a new self-signed one.",
		Attributes: map[string]schema.Attribute{
			"fingerprint": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "SHA-256 fingerprint of the certificate, as PBS shows it: 32 lower-case " +
					"hexadecimal pairs separated by colons.",
			},
			"subject": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Subject of the certificate.",
			},
			"issuer": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Issuer of the certificate; the same as `subject` for a self-signed one.",
			},
			"not_before": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Start of the certificate's validity, in RFC 3339 format (UTC).",
			},
			"not_after": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "End of the certificate's validity, in RFC 3339 format (UTC).",
			},
			"san": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "DNS names among the certificate's subject alternative names, as PBS lists them, such as `pbs.example.com`; PBS leaves out IP addresses.",
			},
		},
	}
}

func (d *fingerprintDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *fingerprintDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	cert, err := d.data.client.ProxyCertificate(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS certificate",
			apiErrorDetail(d.data.client, certificatesPrivilege, err))
		return
	}

	// PBS shows the fingerprint in its own form already; normalising and
	// formatting it again makes the attribute stable should a release ever
	// change the case or separators.
	fingerprint := cert.Fingerprint
	if normalised, err := pbsclient.NormaliseFingerprint(cert.Fingerprint); err == nil {
		fingerprint = pbsclient.FormatFingerprint(normalised)
	}

	san, diags := types.ListValueFrom(ctx, types.StringType, nonNilStrings(cert.SAN))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &fingerprintDataSourceModel{
		Fingerprint: types.StringValue(fingerprint),
		Subject:     types.StringValue(cert.Subject),
		Issuer:      types.StringValue(cert.Issuer),
		NotBefore:   epochToRFC3339(cert.NotBefore),
		NotAfter:    epochToRFC3339(cert.NotAfter),
		SAN:         san,
	})...)
}

// epochToRFC3339 formats a Unix time in UTC, or null for zero, which PBS
// never sends for a real certificate.
func epochToRFC3339(epoch int64) types.String {
	if epoch == 0 {
		return types.StringNull()
	}
	return types.StringValue(time.Unix(epoch, 0).UTC().Format(time.RFC3339))
}

// nonNilStrings turns a nil slice into an empty one, so that an absent list
// is an empty list rather than null.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
