package pbsclient

import (
	"context"
	"net/http"
	"regexp"
)

// What PBS 4.x does when asked to work on a datastore, read in its source
// (src/api2/admin/datastore.rs, src/server/gc_job.rs, pbs-datastore
// datastore.rs; proxmox-backup 7c86c5ad5, after 4.2.11):
//
//   - POST /admin/datastore/{store}/gc (Datastore.Modify on
//     /datastore/{store}, 403 without) opens the datastore for writing, so a
//     removable datastore that is not mounted and the maintenance modes
//     read-only, offline, unmount, s3-refresh and delete fail at once — 400
//     "datastore 'x' is not mounted", "datastore 'x' is unavailable: ..."
//     (IsDatastoreUnavailable); a missing one is 400 "no such datastore
//     'x'". A garbage collection already running answers, after up to 10 s,
//     "garbage collection already running". Otherwise it starts task
//     garbage_collection, worker ID the datastore, which PBS can abort.
//     GET /admin/gc/{store} afterwards shows the figures of the last
//     garbage collection that succeeded, with its UPID: a failed run does
//     not update them. Chunks are only removed once they are older than the
//     atime cutoff (24 h 5 min unless the datastore's tuning says
//     otherwise), so a garbage collection right after a prune mostly
//     reports pending removals.
//   - POST /admin/datastore/{store}/mount and …/unmount (both Datastore.Modify
//     on /datastore/{store} and Sys.Modify on /system/disks, 403 without) are
//     for removable datastores: any other answers 400 "datastore 'x' is not
//     removable", a missing one 400 "no such datastore 'x'". Mounting starts
//     task mount-device, worker ID the datastore, which ends OK at once with
//     "device is already mounted at '<path>'" when it is, and fails with
//     "mounting to tmp path failed: ..." when the disk is not connected.
//     After a mount, and only then, it starts the sync jobs with run-on-mount
//     that sync to or from the datastore, in a task of their own,
//     mount-sync-jobs, whose UPID it does not tell; its own log says
//     "starting <n> sync jobs". Mounting checks no maintenance mode, and PBS
//     cannot abort it.
//   - Unmounting answers 400 "Datastore 'x' is not mounted" (with a capital
//     D) for a datastore that is not mounted, checking no maintenance mode
//     before. With gc-on-unmount (PBS 4.1.8), it then starts a garbage
//     collection as root@pam, through its proxy, unless one is running
//     already. When the proxy refuses, the call fails with the proxy's own
//     error, since proxmox-rest-server answers with the HttpError under the
//     context PBS adds (formatter.rs, error_to_response), and the proxy
//     passes the API daemon's answer to the protected call on as it is
//     (rest.rs, proxy_protected_request): in any maintenance mode —
//     read-only, offline, unmount, s3-refresh, delete — 400 "datastore 'x'
//     is unavailable: <reason>" (IsDatastoreInMaintenance), whose reason
//     ends with the mode's free-text message for read-only, offline and
//     s3-refresh. Only when PBS cannot reach its proxy does the call fail
//     with 400 "unable to start garbage collection before unmount", the
//     context itself, and when it cannot even set up the connection — read
//     the proxy's certificate, sign the ticket — with 400 "failed to connect
//     to localhost for starting GC".
//     It then sets maintenance mode unmount, replacing any other, and starts
//     task unmount-device, which waits without limit for the operations that
//     use the datastore — backups, restores, verifications, syncs, the
//     garbage collection — to end, logging "waiting for active operations to
//     finsish before continuing: read <r>, write <w>" (sic; before PBS
//     4.0.20 "cannot unmount yet, still <r> read and <w> write operations
//     active") whenever the numbers change. Every second of that wait it
//     checks the maintenance mode, which takes the lock of datastore.cfg
//     (expect_maintenance_type; expect_maintanance_unmounting before PBS
//     4.0.20). Aborting the task, anyone changing the maintenance mode, or
//     that lock held by another task for longer than the 10 s PBS waits for
//     it all end the wait, and the task, with "aborted, due to user
//     request". PBS resets the mode then only when it is still the task's
//     own and PBS gets the lock; otherwise the mode stays — unmount when the
//     lock is still held, which PBS logs as "maintenance mode was not as
//     expected: Unable to acquire lock ..." with DatastoreConfigLockFile, or
//     whatever mode someone set, such as read-only. Once the wait is over,
//     it runs umount holding the lock and clears the mode; an umount that
//     fails leaves the datastore in maintenance mode unmount.
//   - PUT /admin/datastore/{store}/s3-refresh (Datastore.Modify on
//     /datastore/{store}) starts task s3-refresh, worker ID the datastore,
//     which reads the datastore's contents — indexes, groups and
//     namespaces, not chunks — from its bucket into the local cache, in
//     maintenance mode s3-refresh, replacing any other mode. It clears the
//     mode when it succeeds; a failure leaves the mode s3-refresh. From PBS
//     4.0.20 the call sets the mode before it starts the task, and the task
//     waits for the datastore's operations as an unmount does, aborted the
//     same way, then reads holding the lock of datastore.cfg, which every
//     datastore lookup on the server takes too; before, the task set the
//     mode itself and read at once. Calls PBS refuses meanwhile for that
//     lock — 400 "Unable to acquire lock ..." after 10 s,
//     IsDatastoreConfigLocked — Call tries again for about five minutes
//     (locks.go); a task that needs the lock, such as that of a second
//     refresh, fails on it, which LockS3Refresh keeps this provider's own
//     refreshes from. PBS does not check that the datastore is
//     on S3: from PBS 4.0.20 a datastore that is not fails the task with
//     "store 'x' not backed by S3" and stays in maintenance mode s3-refresh,
//     so callers check the backend first.
//   - GET /admin/datastore/{store}/active-operations (Datastore.Audit)
//     answers {"read": <n>, "write": <n>}: the operations an unmount or a
//     refresh waits for (pbs-datastore task_tracking.rs).

// StartGarbageCollection starts a garbage collection of a datastore and
// returns its task.
func (c *Client) StartGarbageCollection(ctx context.Context, store string) (UPID, error) {
	return c.StartTask(ctx, http.MethodPost, Path("admin", "datastore", store, "gc"), nil)
}

// MountDatastore mounts a removable datastore and returns the task that does
// it. A datastore that is mounted already stays so, and the task ends OK.
func (c *Client) MountDatastore(ctx context.Context, store string) (UPID, error) {
	return c.StartTask(ctx, http.MethodPost, Path("admin", "datastore", store, "mount"), nil)
}

// UnmountDatastore unmounts a removable datastore and returns the task that
// does it, which waits for the operations that use the datastore first.
// IsDatastoreNotMounted reports a datastore that is not mounted.
func (c *Client) UnmountDatastore(ctx context.Context, store string) (UPID, error) {
	return c.StartTask(ctx, http.MethodPost, Path("admin", "datastore", store, "unmount"), nil)
}

// RefreshDatastoreFromS3 reads the contents of a datastore on S3 from its
// bucket into the local cache, and returns the task that does it. PBS does
// not check the backend: a datastore that is not on S3 fails the task and
// stays in maintenance mode s3-refresh.
func (c *Client) RefreshDatastoreFromS3(ctx context.Context, store string) (UPID, error) {
	return c.StartTask(ctx, http.MethodPut, Path("admin", "datastore", store, "s3-refresh"), nil)
}

// ActiveOperations counts the operations that use a datastore.
type ActiveOperations struct {
	Read  int64 `json:"read"`
	Write int64 `json:"write"`
}

// DatastoreActiveOperations returns how many operations use a datastore.
func (c *Client) DatastoreActiveOperations(ctx context.Context, store string) (ActiveOperations, error) {
	var ops ActiveOperations
	_, err := c.Get(ctx, Path("admin", "datastore", store, "active-operations"), nil, &ops)
	return ops, err
}

// datastoreNameInError matches a datastore's name in PBS's errors about it:
// a PROXMOX_SAFE_ID (pbs-api-types datastore.rs, DATASTORE_SCHEMA;
// proxmox-schema api_types.rs, SAFE_ID_REGEX_STR), which holds no quote, so
// that a pattern can anchor the whole message around it.
const datastoreNameInError = `[A-Za-z0-9_][A-Za-z0-9._\-]*`

var (
	// datastoreNotMountedPattern is the whole of PBS's answer for a
	// removable datastore that is not mounted, in both spellings.
	datastoreNotMountedPattern = regexp.MustCompile(`^[Dd]atastore '` + datastoreNameInError + `' is not mounted$`)
	// datastoreNotRemovablePattern is the whole of PBS's answer when asked to
	// mount or unmount a datastore that is not removable.
	datastoreNotRemovablePattern = regexp.MustCompile(`^datastore '` + datastoreNameInError + `' is not removable$`)
)

// IsDatastoreNotMounted reports whether PBS refused a call because the
// removable datastore is not mounted. There are two spellings, read in its
// source (pbs-datastore datastore.rs and src/api2/admin/datastore.rs;
// proxmox-backup 7c86c5ad5, after 4.2.11):
//
//   - 400 "Datastore 'x' is not mounted", with a capital D, comes only from
//     an unmount: ensure_datastore_is_mounted, which do_unmount calls before
//     it opens anything, is its only source an API call reaches.
//   - 400 "datastore 'x' is not mounted" comes from every call that opens the
//     datastore (lookup_datastore), after its check of the maintenance mode.
//     An unmount meets it only when the disk goes away between its own check
//     and the garbage collection that gc-on-unmount starts.
//
// The whole message must match, case and all: a maintenance mode's refusal,
// "datastore 'x' is unavailable: read-only maintenance mode: <message>",
// ends with the free text a user gave the mode, which may well end in
// "' is not mounted" too (IsDatastoreInMaintenance). IsDatastoreUnavailable
// covers both.
func IsDatastoreNotMounted(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && datastoreNotMountedPattern.MatchString(apiErr.Message)
}

// IsDatastoreNotRemovable reports whether PBS refused to mount or unmount a
// datastore that is not removable: 400 "datastore 'x' is not removable", the
// whole message.
func IsDatastoreNotRemovable(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && datastoreNotRemovablePattern.MatchString(apiErr.Message)
}
