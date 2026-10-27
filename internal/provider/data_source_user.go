package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &userDataSource{}
	_ datasource.DataSourceWithConfigure = &userDataSource{}
)

// NewUserDataSource returns the pbs_user data source.
func NewUserDataSource() datasource.DataSource { return &userDataSource{} }

type userDataSource struct {
	data *providerData
}

// userDataModel is a user as the pbs_user and pbs_users data sources report
// it.
type userDataModel struct {
	UserID    types.String `tfsdk:"userid"`
	Comment   types.String `tfsdk:"comment"`
	Email     types.String `tfsdk:"email"`
	Firstname types.String `tfsdk:"firstname"`
	Lastname  types.String `tfsdk:"lastname"`
	Enable    types.Bool   `tfsdk:"enable"`
	Expire    types.Int64  `tfsdk:"expire"`
}

func userData(u pbsclient.User) userDataModel {
	return userDataModel{
		UserID:    types.StringValue(u.UserID),
		Comment:   stringOrNull(u.Comment),
		Email:     stringOrNull(u.Email),
		Firstname: stringOrNull(u.Firstname),
		Lastname:  stringOrNull(u.Lastname),
		Enable:    types.BoolValue(u.Enabled()),
		Expire:    types.Int64Value(u.Expiry()),
	}
}

// userDataAttributes are the attributes of a user in a data source, all
// computed but the user ID when it is the lookup key.
func userDataAttributes(userIDRequired bool) map[string]schema.Attribute {
	userID := schema.StringAttribute{Computed: true, MarkdownDescription: "User ID, such as `alice@pbs`."}
	if userIDRequired {
		userID = schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "User ID of the user to read, such as `alice@pbs`.",
			Validators:          userIDValidators(),
		}
	}
	return map[string]schema.Attribute{
		"userid":    userID,
		"comment":   schema.StringAttribute{Computed: true, MarkdownDescription: "Comment; null when there is none."},
		"email":     schema.StringAttribute{Computed: true, MarkdownDescription: "Email address; null when there is none."},
		"firstname": schema.StringAttribute{Computed: true, MarkdownDescription: "First name; null when there is none."},
		"lastname":  schema.StringAttribute{Computed: true, MarkdownDescription: "Last name; null when there is none."},
		"enable":    schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the user may sign in."},
		"expire": schema.Int64Attribute{
			Computed:            true,
			MarkdownDescription: "When the account expires, in seconds since the Unix epoch; `0` for never.",
		},
	}
}

func (d *userDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (d *userDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a Proxmox Backup Server user. Reading another user than the one the provider " +
			"signs in as needs " + userReadPrivilege + ".",
		Attributes: userDataAttributes(true),
	}
}

func (d *userDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *userDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config userDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	userID := config.UserID.ValueString()
	user, err := d.data.client.GetUser(ctx, userID)
	if err != nil {
		if pbsclient.IsNotFound(err) {
			resp.Diagnostics.AddAttributeError(path.Root("userid"), "PBS user not found",
				fmt.Sprintf("PBS has no user %q. %s", userID, err))
			return
		}
		resp.Diagnostics.AddError("Unable to read PBS user", apiErrorDetail(d.data.client, userReadPrivilege, err))
		return
	}
	model := userData(user)
	model.UserID = types.StringValue(userID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
