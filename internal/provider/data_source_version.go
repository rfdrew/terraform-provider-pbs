package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &versionDataSource{}
	_ datasource.DataSourceWithConfigure = &versionDataSource{}
)

// NewVersionDataSource returns the pbs_version data source.
func NewVersionDataSource() datasource.DataSource { return &versionDataSource{} }

type versionDataSource struct {
	data *providerData
}

type versionDataSourceModel struct {
	Version types.String `tfsdk:"version"`
	Major   types.Int64  `tfsdk:"major"`
	Minor   types.Int64  `tfsdk:"minor"`
	Release types.Int64  `tfsdk:"release"`
	RepoID  types.String `tfsdk:"repoid"`
}

func (d *versionDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_version"
}

func (d *versionDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reports the version of the Proxmox Backup Server the provider is connected to. " +
			"Every user and API token may read it, without any ACL entry.",
		Attributes: map[string]schema.Attribute{
			"version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Full version, such as `4.2.8`.",
			},
			"major": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Major version, such as `4`. Null when the version does not parse.",
			},
			"minor": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Minor version, such as `2`. Null when the version does not parse.",
			},
			"release": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Release within the minor version, such as `8`. Null when the version does not parse.",
			},
			"repoid": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Git commit the release was built from.",
			},
		},
	}
}

func (d *versionDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

// Read asks the server again rather than reporting what Configure read, so
// that the data source reflects the server even when the provider data comes
// from another configuration.
func (d *versionDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	version, err := d.data.client.ServerVersion(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS version", apiErrorDetail(d.data.client, "", err))
		return
	}

	model := versionDataSourceModel{
		Version: types.StringValue(version.String()),
		Major:   types.Int64Null(),
		Minor:   types.Int64Null(),
		Release: types.Int64Null(),
		RepoID:  types.StringValue(version.RepoID),
	}
	if major, minor, release, ok := version.Parts(); ok {
		model.Major = types.Int64Value(int64(major))
		model.Minor = types.Int64Value(int64(minor))
		model.Release = types.Int64Value(int64(release))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
