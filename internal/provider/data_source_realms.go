package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &realmsDataSource{}
	_ datasource.DataSourceWithConfigure = &realmsDataSource{}
)

// NewRealmsDataSource returns the pbs_realms data source.
func NewRealmsDataSource() datasource.DataSource { return &realmsDataSource{} }

type realmsDataSource struct {
	data *providerData
}

type realmDataModel struct {
	Realm   types.String `tfsdk:"realm"`
	Type    types.String `tfsdk:"type"`
	Comment types.String `tfsdk:"comment"`
	Default types.Bool   `tfsdk:"default"`
}

type realmsDataSourceModel struct {
	Realms []realmDataModel `tfsdk:"realms"`
}

func (d *realmsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_realms"
}

func (d *realmsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the realms of a Proxmox Backup Server, the places users sign in at, as the " +
			"sign-in form offers them: the built-in `pam` and `pbs`, and the OpenID Connect, LDAP and Active " +
			"Directory realms. PBS shows the list to anyone, so it needs no privileges.",
		Attributes: map[string]schema.Attribute{
			"realms": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The realms, sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"realm": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Realm name, such as `pam` or `authentik`; users of the realm are `<name>@<realm>`.",
					},
					"type": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Type of the realm: `pam`, `pbs`, `openid`, `ldap` or `ad`.",
					},
					"comment": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Comment; null when there is none.",
					},
					"default": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: "Whether the sign-in form preselects the realm; true for one realm at most.",
					},
				}},
			},
		},
	}
}

func (d *realmsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *realmsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	realms, err := d.data.client.ListRealms(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS realms", apiErrorDetail(d.data.client, "", err))
		return
	}
	sort.Slice(realms, func(i, j int) bool { return realms[i].Realm < realms[j].Realm })
	model := realmsDataSourceModel{Realms: []realmDataModel{}}
	for _, r := range realms {
		model.Realms = append(model.Realms, realmDataModel{
			Realm:   types.StringValue(r.Realm),
			Type:    types.StringValue(r.Type),
			Comment: stringOrNull(r.Comment),
			Default: boolOr(r.Default, false),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
