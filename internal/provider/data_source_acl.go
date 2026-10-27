package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework-validators/boolvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &aclDataSource{}
	_ datasource.DataSourceWithConfigure = &aclDataSource{}
)

// NewACLDataSource returns the pbs_acl data source.
func NewACLDataSource() datasource.DataSource { return &aclDataSource{} }

type aclDataSource struct {
	data *providerData
}

type aclDataSourceModel struct {
	Path    types.String        `tfsdk:"path"`
	Exact   types.Bool          `tfsdk:"exact"`
	AuthID  types.String        `tfsdk:"auth_id"`
	Entries []aclEntryDataModel `tfsdk:"entries"`
}

type aclEntryDataModel struct {
	Path      types.String `tfsdk:"path"`
	AuthID    types.String `tfsdk:"auth_id"`
	Role      types.String `tfsdk:"role"`
	Propagate types.Bool   `tfsdk:"propagate"`
}

func (d *aclDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acl"
}

func (d *aclDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the access control list of a Proxmox Backup Server: which roles users and API " +
			"tokens have on which paths. With " + aclReadPrivilege + " it shows every entry; without it, PBS shows " +
			"only the entries of the API tokens of the user the provider signs in as.",
		Attributes: map[string]schema.Attribute{
			"path": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Read only the entries on this path and, unless `exact` is set, below it, such " +
					"as `/datastore/store1`. Leave it out for every entry.",
				Validators: aclPathValidators(),
			},
			"exact": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Read only the entries on `path` itself, not those below it. Requires `path`.",
				Validators:          []validator.Bool{boolvalidator.AlsoRequires(path.MatchRoot("path"))},
			},
			"auth_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Read only the entries of this user ID or API token ID.",
				Validators:          authIDValidators(),
			},
			"entries": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The entries, sorted by path, user or token ID and role.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"path": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "ACL path the role applies to.",
					},
					"auth_id": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "User ID or API token ID the role is granted to.",
					},
					"role": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Role granted.",
					},
					"propagate": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: "Whether the role also applies below `path`.",
					},
				}},
			},
		},
	}
}

func (d *aclDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *aclDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config aclDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	entries, _, err := d.data.client.ListACL(ctx, config.Path.ValueString(), config.Exact.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read PBS ACL entries", apiErrorDetail(d.data.client, aclReadPrivilege, err))
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.UGID != b.UGID {
			return a.UGID < b.UGID
		}
		return a.RoleID < b.RoleID
	})

	config.Entries = []aclEntryDataModel{}
	for _, e := range entries {
		if !config.AuthID.IsNull() && e.UGID != config.AuthID.ValueString() {
			continue
		}
		config.Entries = append(config.Entries, aclEntryData(e))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func aclEntryData(e pbsclient.ACLEntry) aclEntryDataModel {
	return aclEntryDataModel{
		Path:      types.StringValue(e.Path),
		AuthID:    types.StringValue(e.UGID),
		Role:      types.StringValue(e.RoleID),
		Propagate: types.BoolValue(e.Propagates()),
	}
}
