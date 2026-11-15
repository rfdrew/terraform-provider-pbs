package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// What PBS 4.x does when asked to verify or prune the backups of a datastore
// now, without a job, read in its source (src/api2/admin/datastore.rs verify
// and prune_datastore, src/backup/verify.rs, src/backup/hierarchy.rs,
// src/server/prune_job.rs, pbs-config cached_user_info.rs, pbs-datastore
// datastore.rs and hierarchy.rs; proxmox-backup 7c86c5ad5, after 4.2.11, and
// the same in v4.0.11 unless noted):
//
//   - POST /admin/datastore/{store}/verify verifies the whole datastore, or
//     namespace ns and max-depth levels below it (0 to 7, PBS's default 7),
//     when given none of backup-type, backup-id and backup-time; one backup
//     group with backup-type and backup-id; one backup with all three, the
//     time in seconds since the epoch. Other combinations answer 400
//     "parameters do not specify a backup group or snapshot", and max-depth
//     is ignored for a group or a backup. ignore-verified, true unless sent,
//     skips the backups verified before, unless more than outdated-after
//     whole days have passed since; without outdated-after a verified backup
//     is never verified again. read-threads and verify-threads (1 to 32)
//     arrived with rust-proxmox-backup 4.0.20 and PBS 4.1; left out, they
//     are the datastore's tuning default-verification-readers and -workers,
//     then 1 and 4 (src/backup/verify.rs, VerifyWorker::new). The call
//     answers the UPID of task verify, verify_group or verify_snapshot,
//     whose worker ID is "<store>" or "<store>:<ns>", "<store>:<ns>/<type>/
//     <id>" and "<store>:<ns>/<type>/<id>/<time as %08X>".
//   - Every user may call it: the handler answers 403 "permission check
//     failed - missing Datastore.Verify|Datastore.Backup on
//     /datastore/<store>[/<ns>]" (IsForbidden) without either privilege
//     there, before it looks the datastore up. Datastore.Verify verifies
//     everything: for a whole datastore or namespace, every group down to
//     max-depth, without looking at the ACLs of the namespaces below.
//     Datastore.Backup alone verifies the caller's own backups — those the
//     caller wrote, and for a user those of its API tokens too: a group or a
//     backup of another owner answers 400 "backup owner check failed (<auth
//     id> != <owner>)" (IsBackupOwnerCheckFailed), and one whose group does
//     not exist 400 "unable to read \"<path>/owner\" - No such file or
//     directory (os error 2)" (IsBackupGroupMissing), as PBS reads the
//     group's owner first. A whole datastore or namespace logs "limiting to
//     backups owned by <auth id>" and, in each namespace, verifies every
//     group where the caller holds Datastore.Verify, its own where it holds
//     Datastore.Backup, and nothing where it holds neither.
//   - It opens the datastore for reading before it starts the task: 400 "no
//     such datastore 'x'", "datastore 'x' is not mounted" and "datastore 'x'
//     is unavailable: ..." (IsDatastoreUnavailable) for the maintenance
//     modes offline, unmount, s3-refresh and delete; read-only allows it.
//     The task holds the datastore as a read operation until it ends, which
//     an unmount waits for. It takes no job lock, sends no notification and
//     records no last run, so verifications run side by side, and it stops
//     when aborted.
//   - The task logs "verify datastore <store>", "limiting to backups owned by
//     <auth id>" and "found <n> groups" for a whole datastore or namespace;
//     per group "verify group <store>:<type>/<id> (<n> snapshots)" and,
//     after each backup, "percentage done: ..."; per backup "verify
//     <store>:<type>/<id>/<time>", the time in RFC 3339 and UTC, then "
//     check <archive>" lines, or one of "SKIPPED: verify <store>:<backup>
//     (recently verified)", "SKIPPED: verify <store>:<backup> - snapshot does
//     not exist (anymore)." and "SKIPPED: verify <store>:<backup> - could not
//     acquire snapshot lock: <error>". A group it cannot list logs "verify
//     datastore '<store>', root namespace|namespace '<ns>', group
//     <type>/<id> - unable to list backups: <error>". A group or a backup
//     that does not exist, or vanishes during the run, is no error: the task
//     ends OK. A backup that fails ends the task with "verification failed -
//     please check the log for details", after "Failed to verify the
//     following snapshots/groups:" and a line per backup. A namespace that
//     does not exist fails the task with Datastore.Verify ("error on
//     iterating groups in ns '<ns>' - ENOENT: ..."), and with
//     Datastore.Backup alone the task verifies nothing and ends OK, the
//     error going to the daemon's output only.
//   - POST /admin/datastore/{store}/prune-datastore prunes the datastore, or
//     namespace ns and max-depth levels below it (0 to 7, all when left
//     out), with keep-last, keep-hourly, keep-daily, keep-weekly,
//     keep-monthly and keep-yearly (1 or more; none at all keeps every
//     backup) and dry-run (default false). Every user may call it: the
//     handler answers 400, not 403, "missing permissions
//     'Datastore.Modify|Datastore.Prune' on '/datastore/<store>[/<ns>]'"
//     (IsPrivilegeMissing) without either privilege there, before it looks
//     the datastore up. It opens the datastore for writing, so read-only
//     forbids it too, and holds it as a write operation until the task
//     ends. The task, prune with worker ID "<store>:<ns>" ("store1:" at the
//     root), is a prune job's (src/server/prune_job.rs, see jobs_run.go):
//     in each namespace, Datastore.Modify prunes every group, Datastore.Prune
//     only the caller's own, and neither none, without a word. A dry run
//     logs "(dry test run)" after the first line and "would " before every
//     mark, and removes nothing. A namespace that does not exist fails the
//     task with "ENOENT: No such file or directory" (ListGroups::new reading
//     its directory). The task takes no lock, sends no notification and
//     never looks at abort requests.
//   - POST /admin/datastore/{store}/prune prunes one group; it answers a dry
//     run with the list itself, without a task, and logs another line
//     format. It is not used here.

// VerifyOptions say what a verification covers and how. Unset fields are
// left to PBS.
type VerifyOptions struct {
	// NS is the namespace, empty for the root.
	NS string
	// MaxDepth is how many levels of namespaces below NS a verification of
	// a whole datastore or namespace covers.
	MaxDepth *int64
	// BackupType and BackupID name a backup group; with BackupTime, in
	// seconds since the epoch, one backup of it.
	BackupType string
	BackupID   string
	BackupTime *int64
	// IgnoreVerified skips the backups verified before, unless
	// OutdatedAfter days have passed since.
	IgnoreVerified *bool
	OutdatedAfter  *int64
	// ReadThreads and VerifyThreads need PBS 4.0.20 or 4.1.
	ReadThreads   *int64
	VerifyThreads *int64
}

// StartVerify starts a verification of backups of a datastore and returns
// its task.
func (c *Client) StartVerify(ctx context.Context, store string, o VerifyOptions) (UPID, error) {
	params := url.Values{}
	setString := func(name, value string) {
		if value != "" {
			params.Set(name, value)
		}
	}
	setInt := func(name string, value *int64) {
		if value != nil {
			params.Set(name, strconv.FormatInt(*value, 10))
		}
	}
	setString("ns", o.NS)
	setInt("max-depth", o.MaxDepth)
	setString("backup-type", o.BackupType)
	setString("backup-id", o.BackupID)
	setInt("backup-time", o.BackupTime)
	if o.IgnoreVerified != nil {
		params.Set("ignore-verified", FormatBool(*o.IgnoreVerified))
	}
	setInt("outdated-after", o.OutdatedAfter)
	setInt("read-threads", o.ReadThreads)
	setInt("verify-threads", o.VerifyThreads)
	return c.StartTask(ctx, http.MethodPost, Path("admin", "datastore", store, "verify"), params)
}

// PruneDatastoreOptions say what a prune of a datastore covers and how.
type PruneDatastoreOptions struct {
	// NS is the namespace, empty for the root.
	NS string
	// MaxDepth is how many levels of namespaces below NS the prune covers;
	// all of them when unset.
	MaxDepth *int64
	// Keep is the retention. Without any kind, PBS keeps every backup.
	Keep KeepOptions
	// DryRun only logs what the prune would remove.
	DryRun bool
}

// StartPruneDatastore starts a prune of a datastore, or of a namespace in
// it, and returns its task.
func (c *Client) StartPruneDatastore(ctx context.Context, store string, o PruneDatastoreOptions) (UPID, error) {
	params := url.Values{}
	if o.NS != "" {
		params.Set("ns", o.NS)
	}
	if o.MaxDepth != nil {
		params.Set("max-depth", strconv.FormatInt(*o.MaxDepth, 10))
	}
	for name, value := range map[string]*int64{
		"keep-last": o.Keep.KeepLast, "keep-hourly": o.Keep.KeepHourly, "keep-daily": o.Keep.KeepDaily,
		"keep-weekly": o.Keep.KeepWeekly, "keep-monthly": o.Keep.KeepMonthly, "keep-yearly": o.Keep.KeepYearly,
	} {
		if value != nil {
			params.Set(name, strconv.FormatInt(*value, 10))
		}
	}
	if o.DryRun {
		params.Set("dry-run", FormatBool(true))
	}
	return c.StartTask(ctx, http.MethodPost, Path("admin", "datastore", store, "prune-datastore"), params)
}

// IsBackupOwnerCheckFailed reports whether PBS refused to verify a backup
// group or a backup that the caller, which may verify only its own, does
// not own: 400 "backup owner check failed (<auth id> != <owner>)".
func IsBackupOwnerCheckFailed(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest &&
		strings.HasPrefix(apiErr.Message, "backup owner check failed")
}

// IsBackupGroupMissing reports whether PBS refused to verify a backup group,
// or a backup of it, that does not exist, which it says only when the caller
// may verify its own backups only: PBS reads the group's owner first, and
// answers 400 "unable to read \"<path>/owner\" - No such file or directory
// (os error 2)".
func IsBackupGroupMissing(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest &&
		strings.HasPrefix(apiErr.Message, `unable to read "`) &&
		strings.Contains(apiErr.Message, `/owner" - No such file or directory`)
}
