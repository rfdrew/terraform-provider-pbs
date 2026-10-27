package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &rolesDataSource{}
	_ datasource.DataSourceWithConfigure = &rolesDataSource{}
)

// NewRolesDataSource returns the pbs_roles data source.
func NewRolesDataSource() datasource.DataSource { return &rolesDataSource{} }

type rolesDataSource struct {
	data *providerData
}

type rolesDataSourceModel struct {
	Roles []roleDataModel `tfsdk:"roles"`
}

type roleDataModel struct {
	RoleID     types.String `tfsdk:"roleid"`
	Comment    types.String `tfsdk:"comment"`
	Privileges types.List   `tfsdk:"privileges"`
}

func (d *rolesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_roles"
}

func (d *rolesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the roles of a Proxmox Backup Server and the privileges each grants. The set " +
			"of roles is fixed — PBS has no way to define others — and every user and API token may read it.",
		Attributes: map[string]schema.Attribute{
			"roles": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The roles, in the order PBS lists them.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"roleid": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Name of the role, such as `DatastoreBackup`: the `role` of a `pbs_acl`.",
					},
					"comment": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "PBS's description of the role; null when there is none.",
					},
					"privileges": schema.ListAttribute{
						Computed:            true,
						ElementType:         types.StringType,
						MarkdownDescription: "Privileges the role grants, such as `Datastore.Backup`.",
					},
				}},
			},
		},
	}
}

func (d *rolesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *rolesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	roles, err := d.data.client.ListRoles(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS roles", apiErrorDetail(d.data.client, "", err))
		return
	}
	model := rolesDataSourceModel{Roles: make([]roleDataModel, 0, len(roles))}
	for _, role := range roles {
		privileges, diags := types.ListValueFrom(ctx, types.StringType, nonNilStrings(role.Privileges))
		resp.Diagnostics.Append(diags...)
		model.Roles = append(model.Roles, roleDataModel{
			RoleID:     types.StringValue(role.RoleID),
			Comment:    stringOrNull(role.Comment),
			Privileges: privileges,
		})
	}
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
