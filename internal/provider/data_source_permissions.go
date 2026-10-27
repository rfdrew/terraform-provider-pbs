package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &permissionsDataSource{}
	_ datasource.DataSourceWithConfigure = &permissionsDataSource{}
)

// NewPermissionsDataSource returns the pbs_permissions data source.
func NewPermissionsDataSource() datasource.DataSource { return &permissionsDataSource{} }

type permissionsDataSource struct {
	data *providerData
}

type permissionsDataSourceModel struct {
	AuthID      types.String `tfsdk:"auth_id"`
	Path        types.String `tfsdk:"path"`
	Permissions types.Map    `tfsdk:"permissions"`
}

// privilegeMapType is a map from privilege to whether it propagates.
var privilegeMapType = types.MapType{ElemType: types.BoolType}

func (d *permissionsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_permissions"
}

func (d *permissionsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the privileges a Proxmox Backup Server user or API token has, as PBS works them " +
			"out from its roles: whether a token can back up to a datastore, say. For an API token, these are " +
			"what it can actually do — the privileges of its own ACL entries that its user has too. Every user " +
			"and token may read its own; reading another's needs Sys.Audit on /access.",
		Attributes: map[string]schema.Attribute{
			"auth_id": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "User ID or API token ID to read the privileges of, such as `alice@pbs!ci`. " +
					"Leave it out for the user or token the provider signs in as.",
				Validators: authIDValidators(),
			},
			"path": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Read the privileges on this path only, such as `/datastore/store1`. Leave it " +
					"out for every path with an ACL entry that applies.",
				Validators: aclPathValidators(),
			},
			"permissions": schema.MapAttribute{
				Computed:    true,
				ElementType: privilegeMapType,
				MarkdownDescription: "Privileges by path: for each path, a map from privilege, such as " +
					"`Datastore.Backup`, to whether it also applies below the path. A path where the user or token " +
					"has no privilege has an empty map or is missing, so test with `lookup()` or `try()`.",
			},
		},
	}
}

func (d *permissionsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *permissionsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config permissionsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	permissions, err := d.data.client.Permissions(ctx, config.AuthID.ValueString(), config.Path.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read PBS permissions", apiErrorDetail(d.data.client, "Sys.Audit on /access", err))
		return
	}
	value, diags := types.MapValueFrom(ctx, privilegeMapType, permissions)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	config.Permissions = value
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
