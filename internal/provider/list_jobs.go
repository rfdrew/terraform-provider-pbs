package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// List resources of the jobs that work on datastores: prune, verify and
// sync jobs. PBS lists each kind from its own configuration file and leaves
// out the jobs the caller may not read (src/api2/config/prune.rs,
// verify.rs and sync.rs); the store filter is applied here.

// jobStoreListAttribute is the store filter of a job list.
func jobStoreListAttribute() listschema.StringAttribute {
	return listschema.StringAttribute{
		Optional:            true,
		MarkdownDescription: "List only the jobs of this datastore, such as `store1`: those whose `store` it is.",
		Validators:          safeIDValidators(minSafeIDLength),
	}
}

// jobStoreFilter is the configuration of a job list with a store filter
// only.
type jobStoreFilter struct {
	Store types.String `tfsdk:"store"`
}

// selects reports whether the filter selects a job of store.
func (f jobStoreFilter) selects(store string) bool {
	return f.Store.IsNull() || f.Store.ValueString() == store
}

// NewPruneJobListResource returns the pbs_prune_job list resource.
func NewPruneJobListResource() list.ListResource {
	return &importedList{
		newResource:   NewPruneJobResource,
		identityOrder: []string{"id"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the prune jobs of a Proxmox Backup Server, for `terraform query`, to import " +
				"them as `pbs_prune_job` resources: every job, or with `store` those of one datastore.\n\n" +
				"PBS lists the jobs on whose datastore, or namespace, the provider has `Datastore.Audit` or " +
				"`Datastore.Modify`, and leaves the others out. Reading a job, which importing it does, needs " +
				"`Datastore.Audit`.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{"store": jobStoreListAttribute()},
		},
		enumerate: func(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
			var filter jobStoreFilter
			diags.Append(config.Get(ctx, &filter)...)
			if diags.HasError() {
				return nil
			}
			jobs, err := data.client.ListPruneJobs(ctx)
			if err != nil {
				diags.AddError("Unable to list PBS prune jobs", apiErrorDetail(data.client, "Datastore.Audit on /datastore", err))
				return nil
			}
			var objects []listedObject
			for _, job := range jobs {
				if filter.selects(job.Store) {
					objects = append(objects, jobListed(job.ID, job.Comment))
				}
			}
			return objects
		},
	}
}

// NewVerifyJobListResource returns the pbs_verify_job list resource.
func NewVerifyJobListResource() list.ListResource {
	return &importedList{
		newResource:   NewVerifyJobResource,
		identityOrder: []string{"id"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the verify jobs of a Proxmox Backup Server, for `terraform query`, to import " +
				"them as `pbs_verify_job` resources: every job, or with `store` those of one datastore.\n\n" +
				"PBS lists the jobs on whose datastore, or namespace, the provider has `Datastore.Audit` or " +
				"`Datastore.Verify`, and leaves the others out. Reading a job, which importing it does, needs " +
				"`Datastore.Audit` or `Datastore.Verify`.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{"store": jobStoreListAttribute()},
		},
		enumerate: func(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
			var filter jobStoreFilter
			diags.Append(config.Get(ctx, &filter)...)
			if diags.HasError() {
				return nil
			}
			jobs, err := data.client.ListVerifyJobs(ctx)
			if err != nil {
				diags.AddError("Unable to list PBS verify jobs", apiErrorDetail(data.client, "Datastore.Audit on /datastore", err))
				return nil
			}
			var objects []listedObject
			for _, job := range jobs {
				if filter.selects(job.Store) {
					objects = append(objects, jobListed(job.ID, job.Comment))
				}
			}
			return objects
		},
	}
}

// NewSyncJobListResource returns the pbs_sync_job list resource.
func NewSyncJobListResource() list.ListResource {
	return &importedList{
		newResource:   NewSyncJobResource,
		identityOrder: []string{"id"},
		schema: listschema.Schema{
			MarkdownDescription: "Lists the sync jobs of a Proxmox Backup Server, for `terraform query`, to import " +
				"them as `pbs_sync_job` resources: pulls from a remote, local pulls and pushes alike, or with " +
				"`store` and `sync_direction` some of them.\n\n" +
				"PBS lists the jobs the provider may read — with " + syncJobReadDescription + " — and leaves the " +
				"others out.\n\n" + listRequirementNote,
			Attributes: map[string]listschema.Attribute{
				"store": jobStoreListAttribute(),
				"sync_direction": listschema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "List only the jobs of this direction, `pull` or `push`; both when left out.",
					Validators: []validator.String{
						stringvalidator.OneOf(pbsclient.SyncDirectionPull, pbsclient.SyncDirectionPush),
					},
				},
			},
		},
		enumerate: listSyncJobs,
	}
}

type syncJobListModel struct {
	Store         types.String `tfsdk:"store"`
	SyncDirection types.String `tfsdk:"sync_direction"`
}

// listSyncJobs lists the sync jobs of both directions: GET /config/sync
// lists only pulls unless asked for all, which ListSyncJobs does
// (src/api2/admin/sync.rs, ListSyncDirection).
func listSyncJobs(ctx context.Context, data *providerData, config tfsdk.Config, diags *diag.Diagnostics) []listedObject {
	var filter syncJobListModel
	diags.Append(config.Get(ctx, &filter)...)
	if diags.HasError() {
		return nil
	}
	jobs, err := data.client.ListSyncJobs(ctx)
	if err != nil {
		diags.AddError("Unable to list PBS sync jobs", apiErrorDetail(data.client, "Datastore.Audit on /datastore", err))
		return nil
	}
	stores := jobStoreFilter{Store: filter.Store}
	var objects []listedObject
	for _, job := range jobs {
		if !stores.selects(job.Store) || !filter.SyncDirection.IsNull() && job.Direction() != filter.SyncDirection.ValueString() {
			continue
		}
		objects = append(objects, jobListed(job.ID, job.Comment))
	}
	return objects
}

// jobListed is a listed job, named by its ID and comment.
func jobListed(id, comment string) listedObject {
	return listedObject{identity: map[string]any{"id": id}, displayName: displayNameWithComment(id, comment)}
}
