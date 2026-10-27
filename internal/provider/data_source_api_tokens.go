package provider

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &apiTokensDataSource{}
	_ datasource.DataSourceWithConfigure = &apiTokensDataSource{}
)

// NewAPITokensDataSource returns the pbs_api_tokens data source.
func NewAPITokensDataSource() datasource.DataSource { return &apiTokensDataSource{} }

type apiTokensDataSource struct {
	data *providerData
}

type apiTokensDataSourceModel struct {
	UserID types.String        `tfsdk:"userid"`
	Tokens []apiTokenDataModel `tfsdk:"tokens"`
}

type apiTokenDataModel struct {
	TokenID   types.String `tfsdk:"tokenid"`
	UserID    types.String `tfsdk:"userid"`
	TokenName types.String `tfsdk:"token_name"`
	Comment   types.String `tfsdk:"comment"`
	Enable    types.Bool   `tfsdk:"enable"`
	Expire    types.Int64  `tfsdk:"expire"`
}

func (d *apiTokensDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_tokens"
}

func (d *apiTokensDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the API tokens of one Proxmox Backup Server user, or of every user. Only the " +
			"tokens' metadata: PBS shows a token's secret only when it creates the token or regenerates its " +
			"secret. Reading the tokens of " +
			"other users than the one the provider signs in as needs " + userReadPrivilege + ".",
		Attributes: map[string]schema.Attribute{
			"userid": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "List only the tokens of this user, such as `alice@pbs`.",
				Validators:          userIDValidators(),
			},
			"tokens": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The tokens, sorted by token ID.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"tokenid": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Token ID, such as `alice@pbs!ci`.",
					},
					"userid": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "User ID of the user the token belongs to.",
					},
					"token_name": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Name of the token, the part of the token ID after `!`.",
					},
					"comment": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Comment; null when there is none.",
					},
					"enable": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: "Whether the token may sign in.",
					},
					"expire": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: "When the token expires, in seconds since the Unix epoch; `0` for never.",
					},
				}},
			},
		},
	}
}

func (d *apiTokensDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *apiTokensDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config apiTokensDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client := d.data.client

	var tokens []pbsclient.APIToken
	if !config.UserID.IsNull() {
		var err error
		if tokens, err = client.ListAPITokens(ctx, config.UserID.ValueString()); err != nil {
			resp.Diagnostics.AddError("Unable to list PBS API tokens", apiErrorDetail(client, userReadPrivilege, err))
			return
		}
	} else {
		users, err := client.ListUsers(ctx, true)
		if err != nil {
			resp.Diagnostics.AddError("Unable to list PBS API tokens", apiErrorDetail(client, userReadPrivilege, err))
			return
		}
		for _, u := range users {
			tokens = append(tokens, u.Tokens...)
		}
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].TokenID < tokens[j].TokenID })

	config.Tokens = make([]apiTokenDataModel, 0, len(tokens))
	for _, t := range tokens {
		userID, name, _ := pbsclient.SplitTokenID(t.TokenID)
		config.Tokens = append(config.Tokens, apiTokenDataModel{
			TokenID:   types.StringValue(t.TokenID),
			UserID:    types.StringValue(userID),
			TokenName: types.StringValue(name),
			Comment:   stringOrNull(t.Comment),
			Enable:    types.BoolValue(t.Enabled()),
			Expire:    types.Int64Value(t.Expiry()),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
