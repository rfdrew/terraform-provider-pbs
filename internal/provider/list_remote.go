package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// NewRemoteListResource returns the pbs_remote list resource.
func NewRemoteListResource() list.ListResource {
	return &importedList{
		newResource:   NewRemoteResource,
		identityOrder: []string{"name"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the remotes of a Proxmox Backup Server, for `terraform query`, to import " +
				"them as `pbs_remote` resources.\n\n" +
				"PBS lists the remotes on which the provider has `Remote.Audit`, `/remote/<name>` or above, and " +
				"leaves the others out.\n\n" +
				"A remote's password is write-only and never read: the generated configuration has `password_wo = " +
				"null # sensitive` and `password_wo_version = null`, which plans no change, as the imported remote " +
				"keeps the password PBS has. Set both before a change that replaces the remote, of `name`: PBS " +
				"creates a remote only with its password.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: listRemotes,
	}
}

// listRemotes lists the remotes with GET /config/remote, which leaves out
// those the caller may not audit and the passwords (src/api2/config/remote.rs,
// list_remotes).
func listRemotes(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	remotes, err := data.client.ListRemotes(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS remotes", apiErrorDetail(data.client, "Remote.Audit on /remote", err))
		return nil
	}
	objects := make([]listedObject, 0, len(remotes))
	for _, remote := range remotes {
		objects = append(objects, listedObject{
			identity:    map[string]any{"name": remote.Name},
			displayName: displayNameWithComment(remote.Name, remote.Comment),
		})
	}
	return objects
}
