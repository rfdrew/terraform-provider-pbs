package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/action/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ action.Action              = &datastoreMountAction{}
	_ action.ActionWithConfigure = &datastoreMountAction{}
	_ action.Action              = &datastoreUnmountAction{}
	_ action.ActionWithConfigure = &datastoreUnmountAction{}
)

// NewDatastoreMountAction returns the pbs_datastore_mount action.
func NewDatastoreMountAction() action.Action {
	return &datastoreMountAction{}
}

// NewDatastoreUnmountAction returns the pbs_datastore_unmount action.
func NewDatastoreUnmountAction() action.Action {
	return &datastoreUnmountAction{}
}

// datastoreMountAction mounts a removable datastore, as the Mount button on
// the datastore's Summary does.
type datastoreMountAction struct {
	actionBase
}

// datastoreUnmountAction unmounts a removable datastore, as the Unmount
// button on the datastore's Summary does.
type datastoreUnmountAction struct {
	actionBase
}

// datastoreActionModel is the configuration of an action that starts a task
// on one datastore.
type datastoreActionModel struct {
	Store types.String `tfsdk:"store"`
	taskWaitModel
}

// removableStoreAttribute is the `store` of the actions on removable
// datastores.
func removableStoreAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		Required:            true,
		MarkdownDescription: "Name of the removable datastore, such as `pbs_datastore.usb.name`.",
		Validators:          safeIDValidators(minSafeIDLength),
	}
}

// removablePrivilege is what mounting and unmounting a datastore need, in
// PBS's router: both privileges, or 403.
func removablePrivilege(store string) string {
	return datastorePrivilege("Datastore.Modify", store) + " and Sys.Modify on /system/disks"
}

// removableNote ends the description of the actions on removable
// datastores.
const removableNote = "`pbs_datastore.mount_status` shows the new state after the next refresh. While the datastore " +
	"is not mounted, PBS cannot open it: its jobs fail, `pbs_datastore` keeps it in state, and `pbs_namespace` keeps " +
	"its namespaces in state, with a warning."

func (a *datastoreMountAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore_mount"
}

func (a *datastoreMountAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Mounts a removable Proxmox Backup Server datastore, as **Mount** on the datastore's " +
			"Summary in the web interface does, once its disk is connected to the PBS host: PBS mounts the file " +
			"system whose UUID is the datastore's `backing_device`, and the task fails when no such disk is " +
			"connected. A datastore that is mounted already stays so, and the action succeeds.\n\n" +
			"Needs `Datastore.Modify` on the datastore and `Sys.Modify` on `/system/disks`. Every PBS 4 release can " +
			"mount removable datastores.\n\n" +
			"After mounting the datastore, PBS starts the sync jobs with `run_on_mount` that sync to or from it, one " +
			"after another, in a task of their own (`mount-sync-jobs` in Administration → Tasks) whose ID PBS does " +
			"not tell: the action reports how many PBS started, and does not wait for them. If one of them has " +
			"`unmount_on_done`, PBS unmounts the datastore again once they are done. A datastore that was mounted " +
			"already starts none.\n\n" +
			"PBS mounts a removable datastore by itself, and starts those sync jobs, when its disk is connected to " +
			"the host, as long as no other datastore is on that disk. The action is for the other cases: a disk that " +
			"holds several datastores, and a datastore that was unmounted — by hand, by `unmount_on_done` or by " +
			"`pbs_datastore_unmount` — while its disk stayed connected. A datastore is on one disk only, its " +
			"`backing_device`: a rotation of several disks needs a removable datastore on each.\n\n" +
			removableNote + "\n\n" + actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"store": removableStoreAttribute(),
		}),
	}
}

func (a *datastoreMountAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config datastoreActionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	store := config.Store.ValueString()
	progress := newActionProgress(ctx, resp)

	// Mounting writes no configuration, unlike unmounting: it needs no
	// lock.
	upid, err := client.MountDatastore(ctx, store)
	if err != nil {
		resp.Diagnostics.AddError("Unable to mount PBS datastore "+store, removableErrorDetail(client, store, err))
		return
	}
	// PBS cannot abort a mount, which takes seconds.
	task := actionTask{client: client, upid: upid, what: fmt.Sprintf("Mounting PBS datastore %q", store)}
	if _, finished := task.await(ctx, config.taskWaitModel, progress, &resp.Diagnostics); !finished {
		return
	}
	reportMount(ctx, client, upid, store, progress)
}

// mountSyncJobsPattern is the line of a mount task's log that says how many
// sync jobs PBS starts after the mount.
var mountSyncJobsPattern = regexp.MustCompile(`^starting (\d+) sync jobs$`)

// reportMount says what a mount that succeeded did, from its log, which is
// a few lines long: whether the datastore was mounted already, and how many
// sync jobs PBS started after mounting it.
func reportMount(ctx context.Context, client *pbsclient.Client, upid pbsclient.UPID, store string, progress *actionProgress) {
	lines, _, _, err := client.TaskLog(ctx, upid, 1, 0)
	if err != nil {
		progress.say("PBS mounted datastore %q", store)
		return
	}
	already, jobs := false, ""
	for _, line := range lines {
		message := strings.TrimSpace(line.Message())
		if strings.HasPrefix(message, "device is already mounted") {
			already = true
		}
		if m := mountSyncJobsPattern.FindStringSubmatch(message); m != nil {
			jobs = m[1]
		}
	}
	switch {
	case already:
		progress.say("PBS datastore %q was mounted already", store)
	case jobs != "":
		progress.say("PBS mounted datastore %q, and started its %s sync jobs with run_on_mount in a task of their "+
			"own, mount-sync-jobs, which the action does not wait for", store, jobs)
	default:
		progress.say("PBS mounted datastore %q", store)
	}
}

func (a *datastoreUnmountAction) Metadata(_ context.Context, req action.MetadataRequest, resp *action.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datastore_unmount"
}

func (a *datastoreUnmountAction) Schema(_ context.Context, _ action.SchemaRequest, resp *action.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Unmounts a removable Proxmox Backup Server datastore, as **Unmount** on the datastore's " +
			"Summary in the web interface does, so that its disk can be disconnected. A datastore that is not " +
			"mounted is left as it is, and the action succeeds.\n\n" +
			"Needs `Datastore.Modify` on the datastore and `Sys.Modify` on `/system/disks`. Every PBS 4 release can " +
			"unmount removable datastores.\n\n" +
			"PBS first puts the datastore into maintenance mode `unmount`, which no new operation passes, and waits " +
			"for the running ones — backups, restores, verifications, syncs, prunes, garbage collection — to end, " +
			"without limit; the action reports how many it waits for. With the datastore's `gc_on_unmount` (PBS " +
			"4.1.8 and later), PBS starts a garbage collection before that, and the unmount waits for it too: allow " +
			"for it in `timeout`. Once nothing uses the datastore, PBS unmounts it and clears the maintenance mode.\n\n" +
			"~> Without `gc_on_unmount`, the maintenance mode `unmount` replaces any mode the datastore had, such as " +
			"`read-only`, and PBS does not restore it afterwards; the next apply of a `pbs_datastore` that configures " +
			"`maintenance_mode` sets it again. With `gc_on_unmount`, PBS instead refuses to unmount a datastore in " +
			"any maintenance mode, since the garbage collection cannot start then: clear `read-only` or `offline` " +
			"first, or set `gc_on_unmount = false`. PBS sets the other modes itself for a task of its own, under " +
			"Administration → Tasks, which is waited for rather than cleared: `unmount` is an unmount still running, " +
			"such as one `unmount_on_done` started, which unmounts the datastore itself; `s3-refresh` a refresh from " +
			"S3; `delete` a deletion, which unmounts the datastore too. Clearing `unmount` stops the unmount. " +
			"Clearing `s3-refresh` stops a refresh only while it still waits for the datastore's operations: once " +
			"it reads the bucket, it holds the lock of PBS's datastore configuration until it ends, and PBS refuses " +
			"to change any datastore's settings meanwhile. `delete` cannot be cleared. A failed unmount or refresh " +
			"leaves its mode behind; the action then says how to clear it.\n\n" +
			"When the wait ends first, the action loses track of the unmount, or Terraform stops the action, the action asks PBS to stop the unmount, which " +
			"would otherwise go on blocking the datastore for as long as operations use it: PBS then leaves the " +
			"datastore mounted, in no maintenance mode. With `wait = false`, nothing stops it. When `umount` itself " +
			"fails, such as for a process outside PBS that uses the mount point, PBS leaves the datastore in " +
			"maintenance mode `unmount`; the action then says how to clear it.\n\n" +
			removableNote + "\n\n" + actionRequirementNote,
		Attributes: taskWaitAttributes(map[string]schema.Attribute{
			"store":   removableStoreAttribute(),
			"timeout": unmountTimeoutAttribute(),
		}),
	}
}

// unmountTimeoutAttribute is the `timeout` of pbs_datastore_unmount, which
// stops the unmount when it runs out, unlike that of other actions.
func unmountTimeoutAttribute() schema.StringAttribute {
	timeout := actionTimeoutAttribute()
	timeout.MarkdownDescription = "How long to wait for the unmount, as a Go duration such as `90m` or `4h`. " +
		"Defaults to the provider's `task_timeout`. When it runs out, the action fails, and asks PBS to stop the " +
		"unmount, which leaves the datastore mounted."
	return timeout
}

func (a *datastoreUnmountAction) Invoke(ctx context.Context, req action.InvokeRequest, resp *action.InvokeResponse) {
	var config datastoreActionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	client := a.client(&resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	store := config.Store.ValueString()
	progress := newActionProgress(ctx, resp)

	// PBS writes the maintenance mode to datastore.cfg before it starts the
	// task, under its lock of the file, which the provider's own writes to
	// it hold for as long as a datastore is being created.
	var upid pbsclient.UPID
	err := client.WithConfigLock(pbsclient.ConfigDatastores, func() error {
		var err error
		upid, err = client.UnmountDatastore(ctx, store)
		return err
	})
	switch {
	case pbsclient.IsDatastoreNotMounted(err):
		progress.say("PBS datastore %q is not mounted; there is nothing to unmount", store)
		return
	case err != nil:
		resp.Diagnostics.AddError("Unable to unmount PBS datastore "+store, unmountErrorDetail(ctx, client, store, err))
		return
	}

	// An unmount that waits blocks the datastore until every operation on
	// it has ended: one the action no longer follows is stopped.
	task := actionTask{client: client, upid: upid, what: fmt.Sprintf("Unmounting PBS datastore %q", store), abortWhenLeft: true}
	status, outcome := task.follow(ctx, config.taskWaitModel, progress, &resp.Diagnostics)
	switch {
	case outcome == taskFinished:
		progress.say("PBS unmounted datastore %q", store)
	case status.Status == "stopped":
		warnMaintenanceLeft(ctx, client, store, pbsclient.MaintenanceUnmount, "unmount", &resp.Diagnostics)
	case outcome == taskLeft && ctx.Err() == nil:
		resp.Diagnostics.AddWarning("Operations on the PBS datastore held up the unmount",
			fmt.Sprintf("PBS unmounts datastore %q only once no operation uses it: no backup, restore, verification, "+
				"sync, prune or garbage collection, such as the one gc_on_unmount starts. %s When PBS stops an unmount "+
				"that waits, it leaves the datastore mounted, in no maintenance mode: a mode it had before the "+
				"unmount, such as read-only, is gone either way, and the next apply of a pbs_datastore that configures "+
				"it sets it again. Invoke the action again once those operations are done, or with a longer "+
				"`timeout`.", store, activeOperationsNote(ctx, client, store)))
	}
}

// activeOperationsNote says how many operations used a datastore when the
// action stopped waiting, or that PBS does not say: reading them needs
// Datastore.Audit, which unmounting does not.
func activeOperationsNote(ctx context.Context, client *pbsclient.Client, store string) string {
	ops, err := client.DatastoreActiveOperations(ctx, store)
	if err != nil {
		return "PBS did not say how many there were when the action stopped waiting."
	}
	return fmt.Sprintf("When the action stopped waiting, PBS counted %d reading and %d writing operations on it.",
		ops.Read, ops.Write)
}

// removableErrorDetail explains why PBS refused to mount or unmount a
// datastore.
func removableErrorDetail(client *pbsclient.Client, store string, err error) string {
	switch {
	case pbsclient.IsForbidden(err):
		return apiErrorDetail(client, removablePrivilege(store), err)
	case pbsclient.IsDatastoreNotRemovable(err):
		return fmt.Sprintf("Datastore %q is not removable: PBS mounts and unmounts only datastores on a removable "+
			"disk, those with a `backing_device`. %s", store, err)
	}
	return datastoreActionErrorDetail(client, store, "Datastore.Modify", err)
}

// unmountErrorDetail explains why PBS refused to unmount a datastore. With
// gc_on_unmount, PBS's API asks its proxy to start a garbage collection
// before it unmounts (do_unmount, src/api2/admin/datastore.rs;
// proxmox-backup 7c86c5ad5, after 4.2.11). When the proxy refuses, PBS
// answers with the proxy's own error: proxmox-rest-server (formatter.rs,
// error_to_response) finds the proxy's HttpError under the context do_unmount
// adds, and the proxy the provider talks to, which hands the protected
// unmount call to PBS's API daemon, passes that answer on as it is (rest.rs,
// proxy_protected_request). In a maintenance mode, that is 400 "datastore
// 'x' is unavailable: <reason>" (pbsclient.IsDatastoreInMaintenance), which
// an unmount meets nowhere else: do_unmount checks no maintenance mode
// itself, and refuses a datastore that is not mounted before the garbage
// collection, with "Datastore 'x' is not mounted", which Invoke has handled
// already. The reason may end with any text — the mode's message — so the
// not-mounted refusal, which IsDatastoreUnavailable covers too, must never get
// this explanation. The context, "unable to start garbage collection before
// unmount", reaches the provider only when PBS cannot reach its proxy, and
// that of the step before, "failed to connect to localhost for starting GC",
// when it cannot set up the connection — read the proxy's certificate, sign
// the ticket (connect_to_localhost, src/client_helpers.rs).
func unmountErrorDetail(ctx context.Context, client *pbsclient.Client, store string, err error) string {
	var apiErr *pbsclient.Error
	switch {
	case errors.As(err, &apiErr) && (apiErr.Message == "unable to start garbage collection before unmount" ||
		apiErr.Message == "failed to connect to localhost for starting GC"):
		return fmt.Sprintf("Datastore %q has gc_on_unmount, and PBS could not start the garbage collection it runs "+
			"before an unmount, so it did not unmount the datastore. PBS answers so when its API cannot reach its "+
			"proxy service, proxmox-backup-proxy, which runs garbage collections, or cannot set up the connection to "+
			"it: check that the service runs, or set gc_on_unmount = false, and invoke the action again. %s", store, err)
	case pbsclient.IsDatastoreInMaintenance(err) && gcOnUnmount(ctx, client, store):
		return fmt.Sprintf("Datastore %q has gc_on_unmount, and PBS could not start the garbage collection it runs "+
			"before an unmount, so it did not unmount the datastore: garbage collection writes to the datastore, "+
			"which its maintenance mode forbids. %s %s", store,
			gcOnUnmountMaintenanceAdvice(store, pbsclient.DatastoreMaintenanceType(err)), err)
	}
	return removableErrorDetail(client, store, err)
}

// gcOnUnmountMaintenanceAdvice says what to do about the maintenance mode
// that kept the garbage collection of gc_on_unmount from starting, by the mode
// pbsclient.DatastoreMaintenanceType read from PBS's reason. A user sets
// read-only and offline, and clears them the same way. PBS sets the others
// for a task of its own, which is waited for. Clearing unmount stops the
// unmount. Clearing s3-refresh stops a refresh only while it still waits for
// the datastore's operations, checking its mode every second: once it reads
// the bucket, it holds PBS's lock of datastore.cfg until it ends
// (run_maintenance_locked, src/api2/admin/datastore.rs), and PBS refuses to
// change any datastore's settings meanwhile, as update_datastore
// (src/api2/config/datastore.rs) waits 10 s for that lock. This advice meets
// mode s3-refresh only while the refresh waits, or after it failed, though:
// while the refresh reads, the garbage collection's lookup_datastore
// (pbs-datastore datastore.rs) fails on the lock before it checks the mode,
// so the unmount gets the lock's error instead. delete cannot be cleared at
// all (pbs-api-types datastore.rs, DataStoreConfig::set_maintenance_mode).
// The deletion unmounts a removable datastore itself once it is done
// (delete_datastore, src/api2/config/datastore.rs).
func gcOnUnmountMaintenanceAdvice(store, mode string) string {
	where := fmt.Sprintf("under Datastore → Options → Maintenance Mode in the web interface, or with "+
		"`proxmox-backup-manager datastore update %s --delete maintenance-mode` on the host", store)
	switch mode {
	case pbsclient.MaintenanceReadOnly, pbsclient.MaintenanceOffline:
		return fmt.Sprintf("Clear maintenance mode %s — by removing maintenance_mode from the pbs_datastore that "+
			"configures it, if one does, or else %s —, or set gc_on_unmount = false, and invoke the action again.",
			mode, where)
	case pbsclient.MaintenanceUnmount:
		return fmt.Sprintf("Mode unmount is an unmount that is still running, such as one unmount_on_done started "+
			"(an unmount-device task under Administration → Tasks), which unmounts the datastore itself: wait for it "+
			"to end, as clearing the mode stops it. A failed unmount leaves the mode behind too: then clear it %s, "+
			"or set gc_on_unmount = false, and invoke the action again.", where)
	case pbsclient.MaintenanceS3Refresh:
		return fmt.Sprintf("Mode s3-refresh is a refresh of the datastore from S3 (an s3-refresh task under "+
			"Administration → Tasks), which clears the mode when it succeeds: wait for it to end, as clearing the "+
			"mode stops it while it still waits for the datastore's operations, and invoke the action again. A "+
			"failed refresh leaves the mode behind: then refresh the "+
			"datastore again once the cause is fixed, or clear the mode %s.", where)
	case pbsclient.MaintenanceDelete:
		return "Mode delete is a deletion of the datastore (a delete-datastore task under Administration → " +
			"Tasks), which unmounts a removable datastore itself once it has deleted it: there is nothing to " +
			"unmount. PBS does not let anyone clear the mode; a deletion that failed leaves it behind, and only " +
			"deleting the datastore again ends it."
	}
	return fmt.Sprintf("A user sets the modes read-only and offline: clear the mode %s, or set gc_on_unmount = "+
		"false, and invoke the action again. PBS sets the others itself while a task of its own runs — an unmount, "+
		"a refresh from S3, a deletion —, under Administration → Tasks: wait for it to end.", where)
}

// gcOnUnmount reports whether PBS runs a garbage collection before it
// unmounts datastore store. Reading the datastore needs Datastore.Audit,
// which unmounting does not: a datastore that cannot be read counts as one
// with gc_on_unmount, since only that garbage collection opens the datastore
// while PBS is asked to unmount it.
func gcOnUnmount(ctx context.Context, client *pbsclient.Client, store string) bool {
	ds, err := client.GetDatastore(ctx, store)
	return err != nil || (ds.GCOnUnmount != nil && *ds.GCOnUnmount)
}

// warnMaintenanceLeft warns when a task that failed — an unmount or a
// refresh from S3, named by what — left datastore store in the maintenance
// mode it set. PBS clears such a mode only when the task succeeds, and
// pbs_datastore does not replace a mode PBS set itself (resource_datastore.go,
// Update), so the user must. Reading the datastore needs Datastore.Audit;
// without it, nothing is said.
func warnMaintenanceLeft(ctx context.Context, client *pbsclient.Client, store, mode, what string, diags *diag.Diagnostics) {
	if ctx.Err() != nil {
		return
	}
	ds, err := client.GetDatastore(ctx, store)
	if err != nil || maintenanceType(ds.MaintenanceMode) != mode {
		return
	}
	where := fmt.Sprintf("under Datastore → Options → Maintenance Mode in the web interface, or with "+
		"`proxmox-backup-manager datastore update %s --delete maintenance-mode` on the host", store)
	advice := fmt.Sprintf("Once the cause is fixed, invoke the action again, which clears the mode when it "+
		"succeeds. Or clear the mode %s: pbs_datastore does not replace a maintenance mode that PBS set itself.", where)
	if mode == pbsclient.MaintenanceUnmount && ds.GCOnUnmount != nil && *ds.GCOnUnmount {
		// The garbage collection that gc_on_unmount starts before an unmount
		// cannot start in maintenance mode unmount: every unmount fails
		// until the mode is gone.
		advice = fmt.Sprintf("Once the cause is fixed, clear the mode %s, then invoke the action again: with "+
			"gc_on_unmount, PBS starts a garbage collection before it unmounts, which the mode forbids, so the "+
			"action fails until the mode is gone. pbs_datastore does not replace a maintenance mode that PBS set "+
			"itself.", where)
	}
	diags.AddWarning("PBS datastore left in maintenance mode "+mode,
		fmt.Sprintf("After the failed %s, PBS left datastore %q in maintenance mode %s, which blocks backups, "+
			"restores and every other operation on it. %s", what, store, mode, advice))
}
