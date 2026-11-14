package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// NewSyncEncryptionKeyListResource returns the pbs_sync_encryption_key list
// resource.
func NewSyncEncryptionKeyListResource() list.ListResource {
	return &importedList{
		newResource:   NewSyncEncryptionKeyResource,
		identityOrder: []string{"id"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the sync encryption keys of a Proxmox Backup Server, PBS 4.2 or newer, for " +
				"`terraform query`, to import them as `pbs_sync_encryption_key` resources; archived keys are listed " +
				"too. `pbs_sync_encryption_key` needs PBS 4.2, so on an older server the list is empty, with a " +
				"warning, rather than failing — also on PBS 4.1.9 and later 4.1 releases, which have sync " +
				"encryption keys already.\n\n" +
				"Listing needs `Sys.Audit` on `/system/encryption-keys/<id>` for each key: PBS leaves out the keys " +
				"the provider's user or token may not audit.\n\n" +
				"PBS never returns a key itself, so the generated configuration has `key_wo = null # sensitive` and " +
				"`key_wo_version = null`, which plans no change and keeps the key PBS has. Leave them null: filled " +
				"in, they replace the key unless `key_wo` holds the same one, as `key_wo_version` describes. **Keep a " +
				"copy of every key outside PBS**: the backups a key encrypted cannot be restored without it.\n\n" +
				"~> **Destroying an imported key deletes it**, archiving it first, as destroying any " +
				"`pbs_sync_encryption_key` does — and removing its resource block after the import plans exactly " +
				"that. PBS refuses to delete a key a sync job holds. To stop managing a key, remove it from the " +
				"state instead.\n\n" + listRequirementNote,
		},
		enumerate: listSyncEncryptionKeys,
	}
}

// listSyncEncryptionKeys names the keys PBS lists, archived ones included.
// Before PBS 4.2 the list is empty, which is not an error: a query of every
// list resource of the provider should work against any PBS it supports.
// PBS 4.1.9 has the keys already (src/api2/config/encryption_keys.rs, and
// the 4.1.9-1 entry of debian/changelog), but pbs_sync_encryption_key
// refuses servers older than 4.2 at plan time (its ModifyPlan), so their
// keys would only give import blocks that cannot be planned.
func listSyncEncryptionKeys(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	if !data.version.AtLeast(pbs42.major, pbs42.minor, pbs42.release) {
		diags.AddWarning("Sync encryption keys need PBS 4.2",
			fmt.Sprintf("pbs_sync_encryption_key needs PBS %s or newer, and the server at %s runs PBS %s, so the list "+
				"is empty: keys a server older than that has, from PBS 4.1.9 on, are not listed.", pbs42,
				data.client.BaseURL(), data.version))
		return nil
	}
	keys, _, err := data.client.ListEncryptionKeys(ctx)
	if err != nil {
		if pbsclient.IsEndpointMissing(err) {
			diags.AddWarning("PBS has no sync encryption keys",
				fmt.Sprintf("The server at %s reports PBS %s, but has no sync encryption keys: it answers that "+
					"GET /config/encryption-keys does not exist, so the list is empty. %s", data.client.BaseURL(),
					data.version, err))
			return nil
		}
		diags.AddError("Unable to list PBS sync encryption keys",
			apiErrorDetail(data.client, "Sys.Audit on /system/encryption-keys", err))
		return nil
	}
	objects := make([]listedObject, 0, len(keys))
	for _, key := range keys {
		displayName := key.ID
		if key.Archived() {
			displayName = displayNameWithComment(key.ID, "archived")
		}
		objects = append(objects, listedObject{identity: map[string]any{"id": key.ID}, displayName: displayName})
	}
	return objects
}
