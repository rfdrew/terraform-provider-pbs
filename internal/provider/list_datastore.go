package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// List resources of datastores and their namespaces.

// NewDatastoreListResource returns the pbs_datastore list resource.
func NewDatastoreListResource() list.ListResource {
	return &importedList{
		newResource:   NewDatastoreResource,
		identityOrder: []string{"name"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the datastores of a Proxmox Backup Server, for `terraform query`, to import " +
				"them as `pbs_datastore` resources: those in a directory, removable ones, mounted or not, and those " +
				"on S3.\n\n" +
				"PBS lists the datastores on which the provider has `Datastore.Audit`, `/datastore/<name>` or " +
				"above, and leaves the others out.\n\n" +
				"The attributes that exist only in Terraform — `reuse_datastore`, `overwrite_in_use`, " +
				"`destroy_data` and `keep_job_configs` — come out at their defaults, `false`, as after any import: " +
				"destroying a datastore of the generated configuration keeps its backups, and deletes its jobs " +
				"and ACL entries. Set `keep_job_configs` before destroying one whose jobs should stay.\n\n" +
				listRequirementNote,
			Attributes: map[string]listschema.Attribute{},
		},
		enumerate: listDatastores,
	}
}

// listDatastores lists the datastores with GET /config/datastore, which
// leaves out those the caller may not audit (src/api2/config/datastore.rs,
// list_datastores) — the privilege reading one needs.
func listDatastores(ctx context.Context, data *providerData, _ tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	datastores, err := data.client.ListDatastores(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS datastores", apiErrorDetail(data.client, "Datastore.Audit on /datastore", err))
		return nil
	}
	objects := make([]listedObject, 0, len(datastores))
	for _, ds := range datastores {
		objects = append(objects, listedObject{
			identity:    map[string]any{"name": ds.Name},
			displayName: displayNameWithComment(ds.Name, ds.Comment),
		})
	}
	return objects
}

// NewNamespaceListResource returns the pbs_namespace list resource.
func NewNamespaceListResource() list.ListResource {
	return &importedList{
		newResource:   NewNamespaceResource,
		identityOrder: []string{"store", "namespace"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the namespaces of a Proxmox Backup Server's datastores, for " +
				"`terraform query`, to import them as `pbs_namespace` resources: those of every datastore, or with " +
				"`store` of one, at every level. The root of a datastore is not a namespace to manage, and is not " +
				"listed.\n\n" +
				"PBS lists the namespaces on which the provider has `Datastore.Audit`, `Datastore.Modify` or " +
				"`Datastore.Backup` — `/datastore/<store>/<namespace>` or above — and leaves the others out. It " +
				"cannot list the namespaces of a datastore it cannot open: a removable datastore that is not " +
				"mounted, or one in a maintenance mode that forbids reading — `offline`, or one PBS sets while it " +
				"unmounts the datastore, refreshes it from S3 or deletes it. They are left out, with a warning. " +
				"Without `store`, so are the namespaces of a datastore PBS fails to list for another reason, such as " +
				"a datastore on a disk that is not mounted, and those of the other datastores are listed; with " +
				"`store`, that fails the list.\n\n" +
				"The attributes that exist only in Terraform come out at their defaults, as after any import: " +
				"`delete_groups = false` and `error_on_protected = true`, so destroying a namespace of the generated " +
				"configuration fails while it holds backups.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{
				"store": listschema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "List only the namespaces of this datastore, such as `store1`.",
					Validators:          safeIDValidators(minSafeIDLength),
				},
			},
		},
		enumerate: listNamespaces,
	}
}

type namespaceListModel struct {
	Store types.String `tfsdk:"store"`
}

// listNamespaces lists the namespaces of one datastore, or of each datastore
// GET /admin/datastore lists: that list has every datastore the caller has a
// privilege on, also one it may only see a namespace of, which GET
// /config/datastore leaves out (src/api2/admin/datastore.rs,
// list_datastores_checked). The namespace list opens the datastore, and
// starts with the parent asked for, here the root.
func listNamespaces(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	var filter namespaceListModel
	diags.Append(config.Get(ctx, &filter)...)
	if diags.HasError() {
		return nil
	}
	client := data.client
	stores := []string{filter.Store.ValueString()}
	if filter.Store.IsNull() {
		items, err := client.ListDatastoreStates(ctx)
		if err != nil {
			diags.AddError("Unable to list PBS datastores", apiErrorDetail(client, "Datastore.Audit on /datastore", err))
			return nil
		}
		stores = stores[:0]
		for _, item := range items {
			stores = append(stores, item.Store)
		}
	}

	var objects []listedObject
	for _, store := range stores {
		namespaces, err := client.ListNamespaces(ctx, store, "", -1)
		switch {
		case pbsclient.IsDatastoreUnavailable(err):
			// Not mounted, or in a maintenance mode that refuses reading:
			// offline, or delete, unmount or s3-refresh, which PBS sets
			// while its own task runs (pbs-api-types' maintenance.rs,
			// MaintenanceMode::check, and pbs-datastore's datastore.rs,
			// lookup_datastore).
			tflog.Info(ctx, "PBS cannot open the datastore to list its namespaces", map[string]any{"store": store, "error": err.Error()})
			diags.AddWarning("Left out the namespaces of datastore "+store,
				fmt.Sprintf("PBS cannot open datastore %q now: it is a removable datastore that is not mounted, or in "+
					"a maintenance mode that forbids reading — \"offline\", or one PBS sets while it unmounts the "+
					"datastore, refreshes it from S3 or deletes it —, so PBS cannot list its namespaces. List again "+
					"once the datastore is mounted, or the maintenance or PBS's task has ended. %s", store, err))
			continue
		case pbsclient.IsNotFound(err) && filter.Store.IsNull():
			// Deleted since it was listed, with its namespaces.
			continue
		case pbsclient.IsForbidden(err) && filter.Store.IsNull():
			// PBS lists a datastore to a caller with a privilege on a
			// namespace of it only, and answers 403 when that namespace
			// does not exist (src/api2/admin/namespace.rs,
			// list_namespaces): there is nothing the caller may see.
			continue
		case pbsclient.IsNotFound(err):
			diags.AddError("Unable to list PBS namespaces",
				fmt.Sprintf("PBS has no datastore %q. Check store. %s", store, err))
			return nil
		case err != nil && filter.Store.IsNull() && !pbsclient.IsUnauthorized(err) && !pbsclient.IsUnreachable(err) &&
			ctx.Err() == nil:
			// PBS fails to open a datastore in more ways than the above: one
			// in a directory whose file system did not mount answers 400
			// "unable to open chunk store at \"/mnt/disk1/store/.chunks\" -
			// No such file or directory (os error 2)" (pbs-datastore's
			// chunk_store.rs, ChunkStore::open, which lookup_datastore calls
			// for a datastore the proxy has not opened yet). What PBS
			// answers about one datastore does not void the namespaces of
			// the others; a PBS that does not answer, or refuses the
			// credentials, fails the list, as it would for every datastore.
			// Nor does a task that held PBS's lock of its datastore
			// configuration for longer than the client tried again: that
			// says which task to wait for.
			tflog.Warn(ctx, "PBS failed to list the namespaces of a datastore", map[string]any{"store": store, "error": err.Error()})
			diags.AddWarning("Left out the namespaces of datastore "+store, namespaceListFailedDetail(store, err))
			continue
		case err != nil:
			diags.AddError("Unable to list PBS namespaces", apiErrorDetail(client, namespaceAuditPrivilege(store, ""), err))
			return nil
		}
		for _, ns := range namespaces {
			if ns == "" {
				continue
			}
			objects = append(objects, listedObject{
				identity:    map[string]any{"store": store, "namespace": ns},
				displayName: namespaceID(store, ns),
			})
		}
	}
	return objects
}

// namespaceListFailedDetail explains why the namespaces of a datastore PBS
// failed to list are left out of a list of every datastore's.
func namespaceListFailedDetail(store string, err error) string {
	what := "Check that PBS can open the datastore, and list again. " + err.Error()
	if pbsclient.IsDatastoreConfigLocked(err) {
		what = datastoreConfigLockAdvice + " " + err.Error()
	}
	return fmt.Sprintf("PBS failed to list the namespaces of datastore %q, so they are left out; those of the "+
		"other datastores are listed. %s", store, what)
}
