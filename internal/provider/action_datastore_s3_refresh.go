package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &datastoreS3RefreshAction{}
	_ action.ActionWithConfigure = &datastoreS3RefreshAction{}
)

// NewDatastoreS3RefreshAction returns the pbs_datastore_s3_refresh action.
func NewDatastoreS3RefreshAction() action.Action {
	return &datastoreS3RefreshAction{}
}

// datastoreS3RefreshAction reads the contents of a datastore on S3 from its
// bucket into the local cache, as "Refresh contents from S3 bucket" under
// the datastore's Content → More does.
type datastoreS3RefreshAction struct {
	actionBase
}

func (a *datastoreS3RefreshAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore_s3_refresh"
}

func (a *datastoreS3RefreshAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Refreshes a Proxmox Backup Server datastore on S3 from its bucket, as **Refresh " +
			"contents from S3 bucket** under the datastore's Content → More in the web interface does: PBS reads the " +
			"namespaces, groups and backup indexes the bucket holds under the datastore's name into the datastore's " +
			"local cache, in place of those the cache had — empty namespaces too from PBS 4.1.5, before only those " +
			"that hold groups. The chunks stay in the bucket. That brings the cache back " +
			"in line with the bucket, such as after the stray objects of a failed backup were removed from the " +
			"bucket by hand, which PBS recommends when the object store ran out of space, or after files of the " +
			"cache were lost or damaged. A datastore created with `reuse_datastore`, such as to take over the " +
			"datastore of a PBS that is gone for good, is refreshed as part of its creation.\n\n" +
			"~> One datastore, one PBS: never have two PBS use the same datastore — the same bucket under the same " +
			"name — not even for a test. Each one's garbage collection deletes from the bucket the chunks that only " +
			"the other's backups use, and a refresh does not prevent that. To have the backups on a second PBS, " +
			"sync them to a datastore of its own.\n\n" +
			"Needs `Datastore.Modify` on the datastore, and `Datastore.Audit` to read its configuration first; the " +
			"`DatastoreAdmin` role has both. The action refuses a datastore that is not on S3 before asking PBS, " +
			"which would leave such a datastore in maintenance mode `s3-refresh`. Every PBS 4 release can refresh " +
			"a datastore.\n\n" +
			"~> PBS puts the datastore into maintenance mode `s3-refresh` for the refresh, replacing any mode it had, " +
			"such as `read-only`: no backup, restore, prune or garbage collection passes until it is done. PBS 4.0.20 " +
			"and later first wait for the operations that use the datastore to end, without limit, and then hold the " +
			"lock of the datastore configuration while they read, which holds up the other datastores of the server " +
			"too: PBS makes operations that open any datastore — backups, restores and jobs of other datastores " +
			"too — and changes to the settings of any wait 10 seconds for it, then fail; the provider tries its own " +
			"such calls again for about five minutes. A refresh that succeeds clears the maintenance mode; it does " +
			"not restore an earlier one, which the next apply of a `pbs_datastore` that configures " +
			"`maintenance_mode` sets again.\n\n" +
			"The refreshes of one provider configuration run one at a time: an invocation waits for another one's " +
			"refresh to end before it starts its own, since from PBS 4.0.20 the task of a refresh started meanwhile " +
			"can fail on that lock and leave its datastore in maintenance mode `s3-refresh`. That covers a refresh " +
			"for as long as its invocation waits for it — not one with `wait = false` or past its `timeout` —, and " +
			"not a refresh started outside Terraform or by another provider configuration. A `pbs_datastore` on S3 " +
			"created with `reuse_datastore`, whose creation refreshes it, waits for them too, and they for it. " +
			"Other datastores the provider creates do not wait for them, as a refresh may wait for its datastore's " +
			"operations for hours. Yet a refresh that still waits for them takes that lock every second to check " +
			"its maintenance mode, and PBS holds the lock while it creates a datastore's chunk store: should that " +
			"take longer than 10 seconds, such as on slow storage or behind a slow S3 endpoint, the refresh fails, " +
			"and can leave its datastore in maintenance mode `s3-refresh`.\n\n" +
			"A refresh that fails leaves the datastore in maintenance mode `s3-refresh`, and the action then says so: " +
			"fix the cause and invoke the action again, or clear the mode under Datastore → Options → Maintenance " +
			"Mode in the web interface, or with `proxmox-backup-manager datastore update <store> --delete " +
			"maintenance-mode` on the host. `pbs_datastore` does not replace a maintenance mode PBS set itself: while " +
			"the datastore is in `s3-refresh`, it keeps the configured `maintenance_mode` in state and warns when it " +
			"reads the datastore.\n\n" +
			"When the wait ends first, the refresh goes on in PBS, which clears the maintenance mode when it is done. " +
			"PBS logs a line per object it reads; the action reports the latest every few seconds.\n\n" +
			actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"store": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the datastore on S3, such as `pbs_datastore.s3.name`.",
				Validators:          safeIDValidators(minSafeIDLength),
			},
		}),
	}
}

func (a *datastoreS3RefreshAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config datastoreActionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	store := config.Store.ValueString()
	progress := newActionProgress(ctx, resp)

	// The provider's refreshes run one at a time, from the call that starts
	// one to the end of the wait for its task: from PBS 4.0.20 the task of a
	// refresh started while another one reads its bucket can fail on PBS's
	// lock of datastore.cfg, and leave its datastore in maintenance mode
	// s3-refresh (see pbsclient.LockS3Refresh).
	_ = client.WithConfigLockWaiting(pbsclient.LockS3Refresh, func() {
		progress.say("Waiting for another S3 refresh of this provider to end before refreshing %q", store)
	}, func() error {
		a.refresh(ctx, client, store, config, progress, &resp.Diagnostics)
		return nil
	})
}

// refresh starts the refresh of store and waits for it as config says.
func (a *datastoreS3RefreshAction) refresh(ctx context.Context, client *pbsclient.Client, store string, config datastoreActionModel,
	progress *actionProgress, diags *diag.Diagnostics) {
	summary := "Unable to refresh PBS datastore " + store + " from S3"

	// PBS refreshes any datastore it is asked to, and leaves one that is
	// not on S3 in maintenance mode s3-refresh (PBS 4.0.20 and later): the
	// backend is checked first. The refresh writes that mode to
	// datastore.cfg under PBS's lock of the file, which the provider's own
	// writes to it hold for as long as a datastore is being created.
	var upid pbsclient.UPID
	var readErr, startErr error
	var backend string
	_ = client.WithConfigLock(pbsclient.ConfigDatastores, func() error {
		var ds pbsclient.Datastore
		if ds, readErr = client.GetDatastore(ctx, store); readErr != nil {
			return nil
		}
		if backend = ds.BackendType(); backend != pbsclient.BackendS3 {
			return nil
		}
		upid, startErr = client.RefreshDatastoreFromS3(ctx, store)
		return nil
	})
	switch {
	case readErr != nil:
		diags.AddError(summary, datastoreActionErrorDetail(client, store, "Datastore.Audit", readErr))
		return
	case backend != pbsclient.BackendS3:
		diags.AddError(summary,
			fmt.Sprintf("Datastore %q is not on S3: its backend is %s. Only a datastore with an S3 `backend` has a "+
				"bucket to refresh from. The action did not ask PBS, which would leave the datastore in maintenance "+
				"mode s3-refresh.", store, backend))
		return
	case startErr != nil:
		diags.AddError(summary, datastoreActionErrorDetail(client, store, "Datastore.Modify", startErr))
		return
	}

	// Once PBS reads from the bucket, it no longer heeds a request to stop,
	// and a refresh left running ends on its own: it is not stopped.
	task := actionTask{client: client, upid: upid, what: fmt.Sprintf("Refreshing PBS datastore %q from S3", store)}
	status, finished := task.await(ctx, config.taskWaitModel, progress, diags)
	switch {
	case finished:
		progress.say("PBS refreshed datastore %q from its bucket", store)
	case status.Status == "stopped":
		warnMaintenanceLeft(ctx, client, store, pbsclient.MaintenanceS3Refresh, "refresh", diags)
	}
}
