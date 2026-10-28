package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &acmeToSDataSource{}
	_ datasource.DataSourceWithConfigure = &acmeToSDataSource{}
)

// NewACMEToSDataSource returns the pbs_acme_tos data source.
func NewACMEToSDataSource() datasource.DataSource { return &acmeToSDataSource{} }

type acmeToSDataSource struct {
	data *providerData
}

type acmeToSDataSourceModel struct {
	Directory types.String `tfsdk:"directory"`
	URL       types.String `tfsdk:"url"`
}

func (d *acmeToSDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_tos"
}

func (d *acmeToSDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the URL of the terms of service an ACME directory advertises, which " +
			"`tos_url` of `pbs_acme_account` agrees to. PBS fetches the directory itself, so it must reach the CA. " +
			"Any user may read it.\n\n" +
			"Let's Encrypt publishes a new URL with each version of its subscriber agreement; an account " +
			"registered already records a new one in state without contacting the CA.",
		Attributes: map[string]schema.Attribute{
			"directory": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "URL of the ACME directory. Defaults to Let's Encrypt's production directory, `" +
					pbsclient.DefaultACMEDirectory + "`.",
				Validators: []validator.String{httpsURLValidator()},
			},
			"url": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "URL of the terms of service; null when the directory advertises none.",
			},
		},
	}
}

func (d *acmeToSDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *acmeToSDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config acmeToSDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	directory := config.Directory.ValueString()
	if config.Directory.IsNull() {
		directory = pbsclient.DefaultACMEDirectory
	}
	tos, err := d.data.client.ACMETermsOfService(ctx, directory)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the terms of service of the ACME directory",
			"PBS could not read "+directory+"; it must reach the directory and trust its TLS certificate. "+
				apiErrorDetail(d.data.client, "", err))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &acmeToSDataSourceModel{
		Directory: types.StringValue(directory),
		URL:       stringOrNull(tos),
	})...)
}
