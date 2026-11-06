package provider

import (
	"context"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The ACME data sources besides pbs_acme_tos: the directories PBS knows by
// name, the schema of the DNS APIs its plugins can use, and its accounts.

var (
	_ datasource.DataSource              = &acmeDirectoriesDataSource{}
	_ datasource.DataSourceWithConfigure = &acmeDirectoriesDataSource{}
	_ datasource.DataSource              = &acmeChallengeSchemaDataSource{}
	_ datasource.DataSourceWithConfigure = &acmeChallengeSchemaDataSource{}
	_ datasource.DataSource              = &acmeAccountsDataSource{}
	_ datasource.DataSourceWithConfigure = &acmeAccountsDataSource{}
)

// --- pbs_acme_directories ----------------------------------------------------

// NewACMEDirectoriesDataSource returns the pbs_acme_directories data source.
func NewACMEDirectoriesDataSource() datasource.DataSource { return &acmeDirectoriesDataSource{} }

type acmeDirectoriesDataSource struct {
	data *providerData
}

type acmeDirectoryDataModel struct {
	Name types.String `tfsdk:"name"`
	URL  types.String `tfsdk:"url"`
}

type acmeDirectoriesDataSourceModel struct {
	Directories []acmeDirectoryDataModel `tfsdk:"directories"`
}

func (d *acmeDirectoriesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_directories"
}

func (d *acmeDirectoriesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the ACME directories a Proxmox Backup Server knows by name, as its web interface " +
			"offers them for a new account: Let's Encrypt's production and staging directories. `directory` of " +
			"`pbs_acme_account` takes any other directory's URL as well. The list is built into PBS; any user may " +
			"read it.",
		Attributes: map[string]schema.Attribute{
			"directories": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The directories, in PBS's order: the first is the one an account uses when it " +
					"names none.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Name of the directory, such as `Let's Encrypt V2`.",
					},
					"url": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "URL of the directory, such as `" + pbsclient.DefaultACMEDirectory + "`.",
					},
				}},
			},
		},
	}
}

func (d *acmeDirectoriesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *acmeDirectoriesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	directories, err := d.data.client.ACMEDirectories(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS ACME directories", apiErrorDetail(d.data.client, "", err))
		return
	}
	model := acmeDirectoriesDataSourceModel{Directories: []acmeDirectoryDataModel{}}
	for _, dir := range directories {
		model.Directories = append(model.Directories, acmeDirectoryDataModel{
			Name: types.StringValue(dir.Name),
			URL:  types.StringValue(dir.URL),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// --- pbs_acme_challenge_schema -------------------------------------------------

// NewACMEChallengeSchemaDataSource returns the pbs_acme_challenge_schema data
// source.
func NewACMEChallengeSchemaDataSource() datasource.DataSource {
	return &acmeChallengeSchemaDataSource{}
}

type acmeChallengeSchemaDataSource struct {
	data *providerData
}

type acmeChallengeFieldDataModel struct {
	Label       types.String `tfsdk:"label"`
	Type        types.String `tfsdk:"type"`
	Description types.String `tfsdk:"description"`
	Optional    types.Bool   `tfsdk:"optional"`
	Default     types.String `tfsdk:"default"`
}

type acmeChallengeAPIDataModel struct {
	Name        types.String                           `tfsdk:"name"`
	Type        types.String                           `tfsdk:"type"`
	Description types.String                           `tfsdk:"description"`
	Fields      map[string]acmeChallengeFieldDataModel `tfsdk:"fields"`
}

type acmeChallengeSchemaDataSourceModel struct {
	APIs map[string]acmeChallengeAPIDataModel `tfsdk:"apis"`
}

func (d *acmeChallengeSchemaDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_challenge_schema"
}

func (d *acmeChallengeSchemaDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the DNS APIs that ACME DNS plugins of a Proxmox Backup Server can use — the " +
			"`api` of `pbs_acme_plugin` — with the settings PBS documents for each, the keys of the plugin's " +
			"`data`. PBS takes them from the acme.sh plugins it ships (the libproxmox-acme-plugins package), and " +
			"its web interface builds its plugin form from them, so the list follows that package's version.\n\n" +
			"Most APIs document no settings: their `fields` are empty, and acme.sh's documentation of the API " +
			"says what it reads. Where fields are documented, `optional` is a hint, not a rule: Cloudflare's " +
			"fields are all marked required, though it takes either a token or a global key. Any user may read " +
			"the schema.",
		Attributes: map[string]schema.Attribute{
			"apis": schema.MapNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The DNS APIs, by the name `api` of `pbs_acme_plugin` takes, such as `cf`.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Display name, such as `Cloudflare Managed DNS`; the API's name when PBS gives none.",
					},
					"type": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Challenge type of the API: `dns`.",
					},
					"description": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Hint on the settings, such as which of them go together; null when there is none.",
					},
					"fields": schema.MapNestedAttribute{
						Computed: true,
						MarkdownDescription: "The settings PBS documents, by the key `data` of `pbs_acme_plugin` takes, " +
							"such as `CF_Token`; empty when it documents none.",
						NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
							"label": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "Display name of the setting; null when it is the key.",
							},
							"type": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "Type of the value: `string` or `integer`; null when the schema says none.",
							},
							"description": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "What the setting is; null when there is no description.",
							},
							"optional": schema.BoolAttribute{
								Computed:            true,
								MarkdownDescription: "Whether the schema marks the setting optional — a hint, see above.",
							},
							"default": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "Value acme.sh uses when the setting is left out, as text, such as `120`; null when there is none.",
							},
						}},
					},
				}},
			},
		},
	}
}

func (d *acmeChallengeSchemaDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *acmeChallengeSchemaDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	schemas, err := d.data.client.ACMEChallengeSchemas(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS ACME challenge schema",
			"PBS reads it from /usr/share/proxmox-acme/dns-challenge-schema.json, which the libproxmox-acme-plugins "+
				"package installs. "+apiErrorDetail(d.data.client, "", err))
		return
	}
	model := acmeChallengeSchemaDataSourceModel{APIs: map[string]acmeChallengeAPIDataModel{}}
	for _, s := range schemas {
		api := acmeChallengeAPIDataModel{
			Name:        types.StringValue(s.Name),
			Type:        types.StringValue(s.Type),
			Description: stringOrNull(s.Description),
			Fields:      map[string]acmeChallengeFieldDataModel{},
		}
		for key, f := range s.Fields {
			api.Fields[key] = acmeChallengeFieldDataModel{
				Label:       stringOrNull(f.Label),
				Type:        stringOrNull(f.Type),
				Description: stringOrNull(f.Description),
				Optional:    types.BoolValue(f.Optional),
				Default:     stringOrNull(f.Default),
			}
		}
		model.APIs[s.ID] = api
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// --- pbs_acme_accounts ---------------------------------------------------------

// NewACMEAccountsDataSource returns the pbs_acme_accounts data source.
func NewACMEAccountsDataSource() datasource.DataSource { return &acmeAccountsDataSource{} }

type acmeAccountsDataSource struct {
	data *providerData
}

type acmeAccountDataModel struct {
	Name      types.String `tfsdk:"name"`
	Directory types.String `tfsdk:"directory"`
	Location  types.String `tfsdk:"location"`
	Status    types.String `tfsdk:"status"`
	Contact   types.String `tfsdk:"contact"`
	ToSURL    types.String `tfsdk:"tos_url"`
}

type acmeAccountsDataSourceModel struct {
	Accounts []acmeAccountDataModel `tfsdk:"accounts"`
}

func (d *acmeAccountsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_acme_accounts"
}

func (d *acmeAccountsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the ACME accounts of a Proxmox Backup Server, as PBS recorded them when it " +
			"registered or last updated them: PBS does not ask the CAs again, so `status` and `contact` can be " +
			"out of date. Deactivated accounts are not listed, nor accounts whose name starts with `_`, which " +
			"PBS takes for deactivated ones. Account keys stay on the server. Needs `" +
			certificatesPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"accounts": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The accounts, sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Account name in PBS, such as `default`.",
					},
					"directory": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "URL of the CA's ACME directory the account is registered at.",
					},
					"location": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "URL of the account at the CA.",
					},
					"status": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "Status of the account as the CA last reported it to PBS: `valid`, `deactivated` or `revoked`.",
					},
					"contact": schema.StringAttribute{
						Computed: true,
						MarkdownDescription: "Contact addresses the CA last returned, separated by commas, as " +
							"`contact` of `pbs_acme_account` takes them; null when it returned none, as Let's Encrypt " +
							"has since June 2025.",
					},
					"tos_url": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "URL of the terms of service agreed to at registration; null when none was.",
					},
				}},
			},
		},
	}
}

func (d *acmeAccountsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *acmeAccountsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	client := d.data.client
	names, err := client.ListACMEAccounts(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list PBS ACME accounts", apiErrorDetail(client, certificatesPrivilege, err))
		return
	}
	sort.Strings(names)
	model := acmeAccountsDataSourceModel{Accounts: []acmeAccountDataModel{}}
	for _, name := range names {
		account, err := client.GetACMEAccount(ctx, name)
		if pbsclient.IsNotFound(err) {
			// Deactivated or deleted since PBS listed it.
			continue
		}
		if err != nil {
			resp.Diagnostics.AddError("Unable to read PBS ACME account", apiErrorDetail(client, certificatesPrivilege, err))
			return
		}
		model.Accounts = append(model.Accounts, acmeAccountDataModel{
			Name:      types.StringValue(name),
			Directory: types.StringValue(account.Directory),
			Location:  types.StringValue(account.Location),
			Status:    stringOrNull(account.Account.Status),
			Contact:   stringOrNull(strings.Join(account.Emails(), ",")),
			ToSURL:    stringOrNull(account.ToS),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
