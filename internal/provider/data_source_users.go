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
	_ datasource.DataSource              = &usersDataSource{}
	_ datasource.DataSourceWithConfigure = &usersDataSource{}
)

// NewUsersDataSource returns the pbs_users data source.
func NewUsersDataSource() datasource.DataSource { return &usersDataSource{} }

type usersDataSource struct {
	data *providerData
}

type usersDataSourceModel struct {
	Realm types.String    `tfsdk:"realm"`
	Users []userDataModel `tfsdk:"users"`
}

func (d *usersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_users"
}

func (d *usersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the users of a Proxmox Backup Server. With " + userReadPrivilege + " the list " +
			"has every user; without it, PBS shows only the user the provider signs in as.",
		Attributes: map[string]schema.Attribute{
			"realm": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "List only the users of this realm, such as `pbs` or `pam`.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(realmPattern, "must be a realm name such as pbs or pam"),
				},
			},
			"users": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The users, sorted by user ID.",
				NestedObject:        schema.NestedAttributeObject{Attributes: userDataAttributes(false)},
			},
		},
	}
}

func (d *usersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *usersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config usersDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	users, err := d.data.client.ListUsers(ctx, false)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS users", apiErrorDetail(d.data.client, userReadPrivilege, err))
		return
	}
	sort.Slice(users, func(i, j int) bool { return users[i].UserID < users[j].UserID })

	config.Users = []userDataModel{}
	for _, u := range users {
		if !config.Realm.IsNull() && pbsclient.Realm(u.UserID) != config.Realm.ValueString() {
			continue
		}
		config.Users = append(config.Users, userData(u))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
