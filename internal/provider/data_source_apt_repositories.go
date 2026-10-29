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
	_ datasource.DataSource              = &aptRepositoriesDataSource{}
	_ datasource.DataSourceWithConfigure = &aptRepositoriesDataSource{}
)

// NewAPTRepositoriesDataSource returns the pbs_apt_repositories data source.
func NewAPTRepositoriesDataSource() datasource.DataSource { return &aptRepositoriesDataSource{} }

type aptRepositoriesDataSource struct {
	data *providerData
}

type aptRepositoriesDataSourceModel struct {
	Node                 types.String                 `tfsdk:"node"`
	Digest               types.String                 `tfsdk:"digest"`
	Files                []aptFileDataModel           `tfsdk:"files"`
	Repositories         []aptRepositoryDataModel     `tfsdk:"repositories"`
	StandardRepositories []aptStandardRepoDataModel   `tfsdk:"standard_repositories"`
	Errors               []aptFileErrorDataModel      `tfsdk:"errors"`
	Infos                []aptRepositoryInfoDataModel `tfsdk:"infos"`
}

type aptFileDataModel struct {
	Path     types.String `tfsdk:"path"`
	FileType types.String `tfsdk:"file_type"`
	Digest   types.String `tfsdk:"digest"`
}

type aptRepositoryDataModel struct {
	FilePath     types.String `tfsdk:"file_path"`
	Index        types.Int64  `tfsdk:"index"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	Handle       types.String `tfsdk:"handle"`
	FileType     types.String `tfsdk:"file_type"`
	PackageTypes types.List   `tfsdk:"package_types"`
	URIs         types.List   `tfsdk:"uris"`
	Suites       types.List   `tfsdk:"suites"`
	Components   types.List   `tfsdk:"components"`
	Comment      types.String `tfsdk:"comment"`
}

type aptStandardRepoDataModel struct {
	Handle      types.String `tfsdk:"handle"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Configured  types.Bool   `tfsdk:"configured"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	FilePath    types.String `tfsdk:"file_path"`
	Index       types.Int64  `tfsdk:"index"`
}

type aptFileErrorDataModel struct {
	Path  types.String `tfsdk:"path"`
	Error types.String `tfsdk:"error"`
}

type aptRepositoryInfoDataModel struct {
	Path     types.String `tfsdk:"path"`
	Index    types.Int64  `tfsdk:"index"`
	Property types.String `tfsdk:"property"`
	Kind     types.String `tfsdk:"kind"`
	Message  types.String `tfsdk:"message"`
}

func (d *aptRepositoriesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_apt_repositories"
}

func (d *aptRepositoriesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	computedList := func(description string) schema.ListAttribute {
		return schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the APT repositories of a Proxmox Backup Server node, as the Repositories " +
			"panel of its interface shows them: every entry of its APT source files, enabled or not, and the " +
			"standard repositories PBS offers, with whether the node has them. An entry's `file_path` and `index` " +
			"address it in `pbs_apt_repository`.\n\n" +
			"Needs `" + aptReadPrivilege + "`.",
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
			"digest": computedString("Digest of the source files together, which changes whenever one of them does."),
			"files": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The source files PBS could parse: `/etc/apt/sources.list` first, when there is " +
					"one, then the files of `/etc/apt/sources.list.d` in the order PBS read them.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"path":      computedString("Path of the file."),
					"file_type": computedString("Format of the file: `list` for one-line entries, `sources` for deb822 stanzas."),
					"digest":    computedString("SHA-256 digest of the file's content, in hexadecimal."),
				}},
			},
			"repositories": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Every entry of the files, enabled or not, file by file in the order of `files`.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"file_path": computedString("Path of the file that holds the entry."),
					"index": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: "Position of the entry in its file, from 0.",
					},
					"enabled": schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether APT uses the entry."},
					"handle": computedString("Standard repository the provider recognises the entry as, such as " +
						"`enterprise` — the first of `enterprise`, `no-subscription` and `test` whose component the entry " +
						"lists. Null for other repositories, and for entries PBS 4.2.1 and later count by the key that " +
						"signs them, such as a local mirror or the download server over `https://`."),
					"file_type":     computedString("Format of the entry: `list` or `sources`."),
					"package_types": computedList("Package types of the entry: `deb`, `deb-src`."),
					"uris":          computedList("URIs of the entry."),
					"suites":        computedList("Suites of the entry, such as `trixie`."),
					"components":    computedList("Components of the entry, such as `pbs-no-subscription`; empty for an absolute suite."),
					"comment":       computedString("Comment lines above the entry, without their `#`; null when there are none."),
				}},
			},
			"standard_repositories": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The standard repositories PBS offers: `enterprise`, `no-subscription` and `test`.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"handle":      computedString("Handle of the repository, as `pbs_apt_standard_repository` takes it."),
					"name":        computedString("Name of the repository as PBS shows it, such as `No-Subscription`."),
					"description": computedString("Description of the repository as PBS shows it."),
					"configured": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: "Whether the node has an entry of the repository, enabled or not.",
					},
					"enabled": schema.BoolAttribute{
						Computed:            true,
						MarkdownDescription: "Whether the node has an enabled entry of the repository.",
					},
					"file_path": computedString("Path of the file that holds the repository's first entry; null when " +
						"the node has none, or when the provider cannot tell which entry PBS counts: PBS 4.2.1 and later " +
						"also count an entry with another URI, such as a local mirror or the download server over " +
						"`https://`, by the key that signs it."),
					"index": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: "Index of that entry in the file; null when `file_path` is.",
					},
				}},
			},
			"errors": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The source files PBS could not read or parse, which `files` leaves out.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"path":  computedString("Path of the file."),
					"error": computedString("What PBS found wrong with it."),
				}},
			},
			"infos": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "Notes PBS makes on entries, as its interface shows them: their origin, and " +
					"warnings about suites.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"path": computedString("Path of the file of the entry."),
					"index": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: "Index of the entry in the file.",
					},
					"property": computedString("Property of the entry the note is about, such as `Suites`; null when " +
						"it is about the whole entry."),
					"kind": computedString("Kind of note, such as `origin` or `warning`."),
					"message": computedString("The note, such as `Proxmox` for the origin of an entry, or a " +
						"warning."),
				}},
			},
		},
	}
}

func (d *aptRepositoriesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *aptRepositoriesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config aptRepositoriesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	repos, err := d.data.client.APTRepositories(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS APT repositories", apiErrorDetail(d.data.client, aptReadPrivilege, err))
		return
	}
	matcher := d.data.aptMatcher()
	model := aptRepositoriesDataSourceModel{
		Node:                 types.StringValue(node),
		Digest:               types.StringValue(repos.Digest),
		Files:                []aptFileDataModel{},
		Repositories:         []aptRepositoryDataModel{},
		StandardRepositories: []aptStandardRepoDataModel{},
		Errors:               []aptFileErrorDataModel{},
		Infos:                []aptRepositoryInfoDataModel{},
	}
	for _, f := range repos.Files {
		model.Files = append(model.Files, aptFileDataModel{
			Path:     types.StringValue(f.Path),
			FileType: types.StringValue(f.FileType),
			Digest:   stringOrNull(f.DigestHex()),
		})
		for i, e := range f.Repositories {
			details := newAPTEntryDetails(f, e, &resp.Diagnostics)
			model.Repositories = append(model.Repositories, aptRepositoryDataModel{
				FilePath:     types.StringValue(f.Path),
				Index:        types.Int64Value(int64(i)),
				Enabled:      types.BoolValue(e.Enabled),
				Handle:       stringOrNull(matcher.Handle(e)),
				FileType:     details.FileType,
				PackageTypes: details.PackageTypes,
				URIs:         details.URIs,
				Suites:       details.Suites,
				Components:   details.Components,
				Comment:      details.Comment,
			})
		}
	}
	for _, s := range repos.StandardRepos {
		entry := aptStandardRepoDataModel{
			Handle:      types.StringValue(s.Handle),
			Name:        types.StringValue(s.Name),
			Description: types.StringValue(s.Description),
			Configured:  types.BoolValue(s.Status != nil),
			Enabled:     types.BoolValue(s.Status != nil && *s.Status),
			FilePath:    types.StringNull(),
			Index:       types.Int64Null(),
		}
		if s.Status != nil {
			if filePath, index, found := repos.FindStandardRepository(matcher, s.Handle, false); found {
				entry.FilePath, entry.Index = types.StringValue(filePath), types.Int64Value(index)
			}
		}
		model.StandardRepositories = append(model.StandardRepositories, entry)
	}
	for _, e := range repos.Errors {
		model.Errors = append(model.Errors, aptFileErrorDataModel{Path: types.StringValue(e.Path), Error: types.StringValue(e.Error)})
	}
	for _, info := range repos.Infos {
		model.Infos = append(model.Infos, aptRepositoryInfoDataModel{
			Path:     types.StringValue(info.Path),
			Index:    types.Int64Value(info.Index),
			Property: stringOrNull(info.Property),
			Kind:     types.StringValue(info.Kind),
			Message:  types.StringValue(info.Message),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
