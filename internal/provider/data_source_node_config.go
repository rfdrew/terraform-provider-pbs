package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &nodeConfigDataSource{}
	_ datasource.DataSourceWithConfigure = &nodeConfigDataSource{}
)

// NewNodeConfigDataSource returns the pbs_node_config data source.
func NewNodeConfigDataSource() datasource.DataSource { return &nodeConfigDataSource{} }

type nodeConfigDataSource struct {
	data *providerData
}

// nodeConfigDataSourceModel is every setting of node.cfg but the ACME ones,
// as the pbs_node_config data source reports them: the resource's
// nodeConfigModel without its id.
type nodeConfigDataSourceModel struct {
	Node           types.String `tfsdk:"node"`
	HTTPProxy      types.String `tfsdk:"http_proxy"`
	EmailFrom      types.String `tfsdk:"email_from"`
	TaskLogMaxDays types.Int64  `tfsdk:"task_log_max_days"`
	DefaultLang    types.String `tfsdk:"default_lang"`
	CiphersTLS12   types.String `tfsdk:"ciphers_tls_1_2"`
	CiphersTLS13   types.String `tfsdk:"ciphers_tls_1_3"`
	ConsentText    types.String `tfsdk:"consent_text"`
	Description    types.String `tfsdk:"description"`
	Location       types.Object `tfsdk:"location"`
}

func (d *nodeConfigDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node_config"
}

func (d *nodeConfigDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	ciphers := " The proxy reads it when it starts, reloads or loads a certificate, so a change may not be in effect yet."
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the settings of a Proxmox Backup Server node, which it keeps in `node.cfg` and " +
			"`pbs_node_config` manages: the HTTP proxy, the sender of its mail, how long it keeps task logs, the " +
			"default language, the TLS ciphers of its proxy, the consent banner, its notes and its location — every " +
			"setting the node has, whether Terraform manages it or not. An unset setting is null, and PBS then uses " +
			"its default. The ACME settings of the same file are left out; `pbs_node_acme` manages them.\n\n" +
			"Needs `" + nodeConfigReadPrivilege + "`.",
		Attributes: map[string]schema.Attribute{
			"node": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Node to read: `localhost` or the node's host name. Defaults to the provider's `node`.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 63),
					stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
				},
			},
			"http_proxy": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				MarkdownDescription: "HTTP proxy PBS connects through to the internet, `[http://][user:password@]host[:port]`; " +
					"null when the node has none. Sensitive, as it may hold a password, which PBS returns.",
			},
			"email_from": computedString("Address the node's mail comes from — the notifications of sendmail " +
				"endpoints that set no `from_address` —; null when unset, and PBS then sends it from `root`."),
			"task_log_max_days": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "Days PBS keeps the logs of finished tasks; null when unset, and PBS then keeps the " +
					"last 20 rotated archives, however old.",
			},
			"default_lang": computedString("Language of the web interface in a browser where none was chosen in " +
				"it, such as `de`; null when unset, and the interface is then in English."),
			"ciphers_tls_1_2": computedString("OpenSSL cipher list the proxy offers for TLS 1.2; null for OpenSSL's " +
				"defaults." + ciphers),
			"ciphers_tls_1_3": computedString("OpenSSL cipher suites the proxy offers for TLS 1.3; null for " +
				"OpenSSL's defaults." + ciphers),
			"consent_text": computedString("Text of the consent banner of the login page, in Markdown, decoded from " +
				"the base64 PBS stores; null when there is none, or, with a warning, when the stored text is not " +
				"base64-encoded UTF-8."),
			"description": computedString("Notes on the node, in Markdown, as PBS reads them back: every line, the " +
				"last one included, ends in a line break; null when there are none."),
			"location": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "Where the node is, which PBS shows on a map; null when unset, and always on PBS " +
					"before 4.2.1, which has no location.",
				Attributes: map[string]schema.Attribute{
					"name": computedString("Name of the place; null when unset."),
					"latitude": schema.Float64Attribute{
						Computed:            true,
						MarkdownDescription: "Latitude in degrees.",
					},
					"longitude": schema.Float64Attribute{
						Computed:            true,
						MarkdownDescription: "Longitude in degrees.",
					},
				},
			},
		},
	}
}

func (d *nodeConfigDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *nodeConfigDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config nodeConfigDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	// PBS reads a missing node.cfg as an empty one (pbs-config/src/node.rs,
	// proxmox-backup 7c86c5ad5, after 4.2.11), so a node without settings
	// is no error.
	settings, _, err := d.data.client.GetNodeSettings(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the settings of the PBS node",
			apiErrorDetail(d.data.client, nodeConfigReadPrivilege, err))
		return
	}
	// Every setting, as an import of pbs_node_config reads them: the same
	// decoding of the consent text, form of the notes and parsing of the
	// location.
	var m nodeConfigModel
	m.Location = types.ObjectNull(nodeLocationTypes)
	m.fromNodeSettings(node, settings, true, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &nodeConfigDataSourceModel{
		Node:           m.Node,
		HTTPProxy:      m.HTTPProxy,
		EmailFrom:      m.EmailFrom,
		TaskLogMaxDays: m.TaskLogMaxDays,
		DefaultLang:    m.DefaultLang,
		CiphersTLS12:   m.CiphersTLS12,
		CiphersTLS13:   m.CiphersTLS13,
		ConsentText:    m.ConsentText,
		Description:    m.Description,
		Location:       m.Location,
	})...)
}
