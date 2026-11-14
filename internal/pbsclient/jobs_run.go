package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// What PBS 4.x does when asked to run a sync, verify or prune job now, read
// in its source (src/api2/admin/{sync,verify,prune}.rs,
// src/server/{sync,verify_job,prune_job,jobstate}.rs, pbs-config
// cached_user_info.rs; proxmox-backup 7c86c5ad5, after 4.2.11):
//
//   - POST /admin/sync/{id}/run, /admin/verify/{id}/run and
//     /admin/prune/{id}/run take the job ID only, and every user may call
//     them: the handler looks the job up first — 400 "no such sync 'x'",
//     "no such verification 'x'", "no such prune 'x'" (IsNotFound) — and
//     checks the caller's privileges itself, so that a missing one is a 400
//     too (IsPrivilegeMissing): "missing permissions 'Datastore.Verify' on
//     '/datastore/<store>[/<ns>]'" for a verify job, the same with
//     Datastore.Modify for a prune job, and for a sync job "permission check
//     failed, '<auth id>' is missing access", whose privileges depend on its
//     direction (src/api2/config/sync.rs, check_sync_job_modify_access: those
//     of changing the job).
//   - It then takes the job's lock, which a run holds until it ends, waiting
//     up to 10 s for it: a job that is running, on its schedule or by hand,
//     answers 400 "Unable to acquire lock ..." after those 10 s
//     (IsTaskAlreadyRunning). A local sync job pulling a datastore into
//     itself answers "can't sync to same datastore".
//   - A verify job opens its datastore for reading and a prune job for
//     writing before they start their task: 400 "no such datastore 'x'" for
//     a datastore deleted with keep-job-configs, and "datastore 'x' is not
//     mounted" or "datastore 'x' is unavailable: ..." for a removable
//     datastore that is not mounted or a maintenance mode that forbids it
//     (IsDatastoreUnavailable) — offline, unmount, s3-refresh and delete
//     forbid both, read-only a prune. A sync job opens its datastores, and
//     signs in to its remote, in its task: those failures end the task.
//   - The task is the run the schedule would start, except that it belongs
//     to the caller: type syncjob, with worker ID "<remote or
//     ->:<remote-store>:<store>:<ns>:<id>", for both directions;
//     verificationjob, "<store>:<id>"; prunejob, "<store>" or
//     "<store>:<ns>", the job ID only in the first log line. It records the
//     run as the job's last run and sends the job's notification. The job
//     lists count the next scheduled run from the end of the last run
//     (jobstate.rs, compute_schedule_status), but the scheduler counts from
//     its start (src/bin/proxmox-backup-proxy.rs, check_schedule;
//     jobstate::last_run_time): a run by hand leaves the schedule as it is,
//     and a scheduled time that passes while it runs starts the job again
//     once it has ended, when the scheduler, which looks every minute, finds
//     the lock free. A prune job's disable flag only stops its schedule:
//     such a job runs by hand. A prune prunes the groups the caller may
//     prune, where a scheduled run prunes as root@pam.
//   - A sync and a verification stop when the task is aborted; a prune never
//     looks and runs to its end.
//   - A sync's log ends with "Summary: sync job pulled|pushed <size> in <n>
//     chunks (average rate: <rate>/s)" or "Summary: sync job found no new
//     data to pull|push", then, with remove-vanished, "Summary: removed
//     vanished: snapshots: <n>, groups: <n>, namespaces: <n>", and
//     "sync job '<worker id>' end". A prune logs "Pruning group
//     <ns>:\"<type>/<id>\"" for each group, then a line per backup, "<mark>
//     <type>/<id>/<time>": the mark is "remove", or "keep", "keep
//     protected", "keep partial" or "keep since timestamp in future" — in PBS
//     4.0 "keep", "protected" and "keep-partial". A prune job without
//     retention options logs "No prune selection - keeping all files." (a
//     warning from 4.2.3) and marks every backup "remove" while it keeps
//     them all; a backup it fails to remove logs a warning, "failed to
//     remove dir ...".
//   - GET /admin/sync, /admin/verify and /admin/prune list the jobs the
//     caller may see with their schedule status: next-run, and last-run-upid,
//     last-run-state ("OK", "WARNINGS: <n>" or the error) and
//     last-run-endtime of the last run. A job that is running has a
//     last-run-upid and no last-run-state. The sync list holds pull jobs
//     only unless sync-direction says "all" or "push".

// Kinds of job, as the paths under /admin name them.
const (
	JobKindSync   = "sync"
	JobKindVerify = "verify"
	JobKindPrune  = "prune"
)

// jobRunRequestTimeout is the least time a call that runs a job may take:
// PBS answers it only once it has the job's lock, after up to 10 s when the
// job is running.
const jobRunRequestTimeout = 30 * time.Second

// RunSyncJob runs a sync job now, in its direction, and returns its task.
func (c *Client) RunSyncJob(ctx context.Context, id string) (UPID, error) {
	return c.runJob(ctx, JobKindSync, id)
}

// RunVerifyJob runs a verify job now and returns its task.
func (c *Client) RunVerifyJob(ctx context.Context, id string) (UPID, error) {
	return c.runJob(ctx, JobKindVerify, id)
}

// RunPruneJob runs a prune job now, also when it is disabled, and returns
// its task.
func (c *Client) RunPruneJob(ctx context.Context, id string) (UPID, error) {
	return c.runJob(ctx, JobKindPrune, id)
}

func (c *Client) runJob(ctx context.Context, kind, id string) (UPID, error) {
	return c.StartTask(c.jobRunContext(ctx), http.MethodPost, Path("admin", kind, id, "run"), nil)
}

// jobRunContext returns ctx with a request timeout that outlasts PBS's wait
// for the lock of a running job, when the client's is shorter.
func (c *Client) jobRunContext(ctx context.Context) context.Context {
	if timeout := c.httpClientFor(ctx).Timeout; timeout > 0 && timeout < jobRunRequestTimeout {
		return WithRequestTimeout(ctx, jobRunRequestTimeout)
	}
	return ctx
}

// IsPrivilegeMissing reports whether PBS refused a call for a privilege its
// handler checks itself, which it answers with 400 rather than the 403 of
// IsForbidden: "missing permissions '<privileges>' on '<path>'", or, for a
// sync job, "permission check failed, '<auth id>' is missing access".
func IsPrivilegeMissing(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest &&
		(strings.HasPrefix(apiErr.Message, "missing permissions '") ||
			strings.HasPrefix(apiErr.Message, "permission check failed"))
}

// JobRunStatus is a job as the job lists under /admin report it: when it ran
// last and runs next.
type JobRunStatus struct {
	ID    string `json:"id"`
	Store string `json:"store"`
	// NextRun is when the schedule runs the job next, in seconds since the
	// epoch; unset without a schedule.
	NextRun *int64 `json:"next-run,omitempty"`
	// LastRunUPID is the task of the last run; unset before the first.
	LastRunUPID string `json:"last-run-upid,omitempty"`
	// LastRunState is how the last run ended: "OK", "WARNINGS: <n>" or the
	// error; unset while it runs.
	LastRunState string `json:"last-run-state,omitempty"`
	// LastRunEndtime is when the last run ended, in seconds since the epoch.
	LastRunEndtime *int64 `json:"last-run-endtime,omitempty"`
}

// Running reports whether the job's last run is still going.
func (s JobRunStatus) Running() bool {
	return s.LastRunUPID != "" && s.LastRunState == ""
}

// ListJobRunStatuses lists the jobs of a kind — JobKindSync, JobKindVerify
// or JobKindPrune — that the caller may see, with their last and next runs;
// sync jobs of both directions.
func (c *Client) ListJobRunStatuses(ctx context.Context, kind string) ([]JobRunStatus, error) {
	var params url.Values
	if kind == JobKindSync {
		params = url.Values{"sync-direction": {SyncDirectionAll}}
	}
	var jobs []JobRunStatus
	_, err := c.Get(ctx, Path("admin", kind), params, &jobs)
	return jobs, err
}
