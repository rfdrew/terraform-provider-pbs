package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &datastoreGCAction{}
	_ action.ActionWithConfigure = &datastoreGCAction{}
)

// NewDatastoreGCAction returns the pbs_datastore_gc action.
func NewDatastoreGCAction() action.Action {
	return &datastoreGCAction{}
}

// datastoreGCAction starts a garbage collection of a datastore, as the
// "Start Garbage Collection" button under Datastore → Prune & GC does.
type datastoreGCAction struct {
	actionBase
}

type datastoreGCModel struct {
	Store types.String `tfsdk:"store"`
	taskWaitModel
}

func (a *datastoreGCAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore_gc"
}

func (a *datastoreGCAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Runs garbage collection on a Proxmox Backup Server datastore now, as **Start Garbage " +
			"Collection** under Datastore → Prune & GC does, instead of waiting for its `gc_schedule`. Garbage " +
			"collection frees the chunks that no backup uses any more, such as after a prune.\n\n" +
			"Needs `Datastore.Modify` on the datastore. A removable datastore must be mounted, and the maintenance " +
			"modes `read-only` and `offline` forbid it. PBS runs one garbage collection per datastore at a time: " +
			"while one runs, the action fails. The run counts as the datastore's last garbage collection, as a " +
			"scheduled one does, and sends the same notification.\n\n" +
			"~> PBS only removes chunks that no backup has used for longer than the datastore's " +
			"`tuning.gc_atime_cutoff` (24 hours and 5 minutes by default), so a garbage collection right after a " +
			"prune mostly reports the space as pending removal; a later one frees it.\n\n" +
			"When it waits, the action reports what PBS removed and what is pending removal, from the figures " +
			"`pbs_gc_status` also reads.\n\n" + actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore, such as `pbs_datastore.main.name`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
		}),
	}
}

func (a *datastoreGCAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config datastoreGCModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	store := config.Store.ValueString()
	progress := newActionProgress(ctx, resp)

	upid, err := client.StartGarbageCollection(ctx, store)
	if err != nil {
		resp.Diagnostics.AddError("Unable to start garbage collection of PBS datastore "+store,
			datastoreActionErrorDetail(client, store, "Datastore.Modify", err))
		return
	}
	task := actionTask{client: client, upid: upid, what: fmt.Sprintf("Garbage collection of PBS datastore %q", store)}
	if _, finished := task.await(ctx, config.taskWaitModel, progress, &resp.Diagnostics); !finished {
		return
	}

	// PBS keeps the figures of the last garbage collection that succeeded,
	// with its task: they are this run's only when the task is the same.
	status, ok, err := client.GCJobStatus(ctx, store)
	if err != nil || !ok || status.UPID != upid.Raw {
		return
	}
	progress.say("removed %s in %d chunks; %s in %d chunks pending removal",
		pbsclient.FormatByteSize(status.RemovedBytes), status.RemovedChunks,
		pbsclient.FormatByteSize(status.PendingBytes), status.PendingChunks)
}

// datastoreActionErrorDetail explains why PBS refused to start a task on a
// datastore: privilege is what the call needs on /datastore/<store>.
func datastoreActionErrorDetail(client *pbsclient.Client, store, privilege string, err error) string {
	switch {
	case pbsclient.IsNotFound(err):
		return fmt.Sprintf("PBS has no datastore %q. %s", store, err)
	case pbsclient.IsDatastoreUnavailable(err):
		return fmt.Sprintf("PBS cannot open datastore %q for this: a removable datastore must be mounted, and its "+
			"maintenance mode may forbid it — `offline` everything, `read-only` anything that writes, and PBS "+
			"blocks the datastore while it unmounts it, refreshes it from S3 or deletes it. %s", store, err)
	case pbsclient.IsTaskAlreadyRunning(err):
		return fmt.Sprintf("The same job is already running on datastore %q, and PBS runs one at a time; "+
			"Administration → Tasks in its web interface shows it. Invoke the action again once it has "+
			"finished. %s", store, err)
	}
	return apiErrorDetail(client, datastorePrivilege(privilege, store), err)
}
