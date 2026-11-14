package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// aptListNodeAttribute is the node filter of the APT list resources.
func aptListNodeAttribute() listschema.StringAttribute {
	return listschema.StringAttribute{
		Optional: true,
		MarkdownDescription: "Node whose APT source files to read: `localhost`, which every PBS answers to, or the " +
			"node's host name. Defaults to the provider's `node`; the results' `node` is this name.",
		Validators: []validator.String{
			stringvalidator.LengthBetween(1, 63),
			stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
		},
	}
}

// aptListModel is the configuration of the APT list resources.
type aptListModel struct {
	Node types.String `tfsdk:"node"`
}

// readAPTForList reads the source files of the node the configuration
// selects, and returns the node's name.
func readAPTForList(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) (string, pbsclient.APTRepositories, bool) {
	var filter aptListModel
	diags.Append(config.Get(ctx, &filter)...)
	if diags.HasError() {
		return "", pbsclient.APTRepositories{}, false
	}
	node := filter.Node.ValueString()
	if node == "" {
		node = data.client.Node()
	}
	repos, err := data.client.APTRepositories(ctx, node)
	if err != nil {
		diags.AddError("Unable to read the PBS APT repositories", apiErrorDetail(data.client, aptReadPrivilege, err))
		return "", pbsclient.APTRepositories{}, false
	}
	return node, repos, true
}

// NewAPTRepositoryListResource returns the pbs_apt_repository list
// resource.
func NewAPTRepositoryListResource() list.ListResource {
	return &importedList{
		newResource:   NewAPTRepositoryResource,
		identityOrder: []string{"node", "file_path", "index"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the entries of the APT source files of a Proxmox Backup Server node, for " +
				"`terraform query`, to import them as `pbs_apt_repository` resources: every entry of " +
				"`/etc/apt/sources.list` and of the `.list` and `.sources` files in `/etc/apt/sources.list.d`, " +
				"disabled ones included, by file and index, as `pbs_apt_repositories` lists them. A file PBS cannot " +
				"read or parse is left out, with a warning.\n\n" +
				"Needs `" + aptReadPrivilege + "`.\n\n" +
				"An entry is addressed by its index in its file: should entries before it be added or removed later, " +
				"outside Terraform, the index points to another entry, and the resource then warns (see " +
				"`pbs_apt_repository`). Destroying an imported entry leaves it as it is, enabled or not.\n\n" +
				listRequirementNote,
			Attributes: map[string]listschema.Attribute{"node": aptListNodeAttribute()},
		},
		enumerate: listAPTRepositories,
	}
}

func listAPTRepositories(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	node, repos, ok := readAPTForList(ctx, data, config, diags)
	if !ok {
		return nil
	}
	if len(repos.Errors) > 0 {
		var files []string
		for _, e := range repos.Errors {
			files = append(files, e.Path+" ("+e.Error+")")
		}
		diags.AddWarning("Left out APT source files PBS cannot read",
			fmt.Sprintf("PBS cannot read or parse these APT source files of node %s, so their entries are not listed: "+
				"%s.", node, strings.Join(files, ", ")))
	}
	var objects []listedObject
	for _, file := range repos.Files {
		for i, entry := range file.Repositories {
			index := int64(i)
			description := newAPTEntryDetails(file, entry, diags).describe(ctx)
			if !entry.Enabled {
				description += " (disabled)"
			}
			objects = append(objects, listedObject{
				identity:    map[string]any{"node": node, "file_path": file.Path, "index": index},
				displayName: displayNameWithComment(fmt.Sprintf("%s:%d", file.Path, index), description),
			})
		}
	}
	return objects
}

// NewAPTStandardRepositoryListResource returns the
// pbs_apt_standard_repository list resource.
func NewAPTStandardRepositoryListResource() list.ListResource {
	return &importedList{
		newResource:   NewAPTStandardRepositoryResource,
		identityOrder: []string{"node", "handle"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the standard APT repositories of Proxmox Backup Server that a node has, for " +
				"`terraform query`, to import them as `pbs_apt_standard_repository` resources: those of `enterprise`, " +
				"`no-subscription` and `test` that an entry of the node's source files references, enabled or not, " +
				"as PBS reports them. A standard repository without an entry is not listed.\n\n" +
				"Needs `" + aptReadPrivilege + "`.\n\n" +
				"~> **Destroying an imported standard repository disables it**: PBS cannot remove an entry, so " +
				"destroying a `pbs_apt_standard_repository` disables every enabled entry of the repository — and " +
				"removing its resource block after the import plans exactly that. To stop managing a repository and " +
				"keep it enabled, remove it from the state instead (`terraform state rm`, or a `removed` block with " +
				"`destroy = false`). Manage each repository with one resource only.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{"node": aptListNodeAttribute()},
		},
		enumerate: listAPTStandardRepositories,
	}
}

func listAPTStandardRepositories(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	node, repos, ok := readAPTForList(ctx, data, config, diags)
	if !ok {
		return nil
	}
	var objects []listedObject
	for _, standard := range repos.StandardRepos {
		// Status is null for a repository no entry references, which the
		// resource would remove from the state when it reads it.
		if standard.Status == nil || !slices.Contains(aptStandardHandles, standard.Handle) {
			continue
		}
		description := standard.Name + ", disabled"
		if *standard.Status {
			description = standard.Name + ", enabled"
		}
		objects = append(objects, listedObject{
			identity:    map[string]any{"node": node, "handle": standard.Handle},
			displayName: displayNameWithComment(standard.Handle, description),
		})
	}
	return objects
}
