package pbsclient

import (
	"context"
	"net/url"
)

// Sync jobs copy backups between two datastores, on a schedule; they live in
// sync.cfg. One job type serves three cases:
//
//   - pull from a remote: from remote-store on the remote to store here;
//   - local pull, without a remote: from remote-store, another datastore of
//     this server, to store;
//   - push, sync-direction "push": from store here to remote-store on the
//     remote, which a push job always has.
//
// What PBS 4.2 does, read in its source (src/api2/config/sync.rs):
//
//   - A read leaves out every property at its default; a pull job has no
//     sync-direction.
//   - Listing returns only pull jobs unless sync-direction says "all" or
//     "push"; ListSyncJobs always asks for all. GET /config/sync/{id} reads
//     a job of either direction.
//   - Creating a job checks the caller's privileges and the combination of
//     properties, but not that the datastores, namespaces or remote exist. A
//     push job without a remote fails the privilege check, "permission check
//     failed", and a local job pulling a datastore into itself "source and
//     target datastore can't be the same".
//   - resync-corrupt cannot be deleted, only set to false, and a push job
//     refuses it; unmount-on-done needs run-on-mount.
//   - A missing job is 400 "no such sync 'x'"-style on GET and PUT, and 404
//     "job 'x' does not exist." on DELETE; IsNotFound covers both.
//   - Deleting a datastore deletes the jobs whose store it is, of both
//     directions, unless keep-job-configs is set.
//   - active-encryption-key, from PBS 4.2, is for push jobs only. Whenever an
//     update replaces or deletes it, PBS appends the key it had to
//     associated-key, unless that holds it already — even when the same
//     update sets associated-key, except when it deletes the active key. A
//     key the owner or the caller may not use, Sys.Modify on
//     /system/encryption-keys/{key}, or an archived active key, is 400 "no
//     such key or cannot access key 'k'".

// Sync directions. A job without one pulls.
const (
	SyncDirectionPull = "pull"
	SyncDirectionPush = "push"
	// SyncDirectionAll lists the jobs of both directions.
	SyncDirectionAll = "all"
)

// SyncJob is a sync job as PBS reports it.
type SyncJob struct {
	ID string `json:"id"`
	// Store is the local datastore: the target of a pull, the source of a
	// push.
	Store string `json:"store"`
	// NS is the namespace in Store, empty for the datastore's root.
	NS string `json:"ns,omitempty"`
	// Remote is empty for a local sync job.
	Remote string `json:"remote,omitempty"`
	// RemoteStore is the datastore on the remote, or for a local sync job
	// the local datastore pulled from.
	RemoteStore string `json:"remote-store"`
	// RemoteNS is the namespace in RemoteStore, empty for its root.
	RemoteNS string `json:"remote-ns,omitempty"`
	// SyncDirection is empty for a pull job.
	SyncDirection string `json:"sync-direction,omitempty"`
	// MaxDepth is how many levels of namespaces below the namespace the job
	// syncs; unset means all.
	MaxDepth       *int64   `json:"max-depth,omitempty"`
	Schedule       string   `json:"schedule,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	RemoveVanished *bool    `json:"remove-vanished,omitempty"`
	GroupFilter    []string `json:"group-filter,omitempty"`
	TransferLast   *int64   `json:"transfer-last,omitempty"`
	EncryptedOnly  *bool    `json:"encrypted-only,omitempty"`
	VerifiedOnly   *bool    `json:"verified-only,omitempty"`
	ResyncCorrupt  *bool    `json:"resync-corrupt,omitempty"`
	RunOnMount     *bool    `json:"run-on-mount,omitempty"`
	UnmountOnDone  *bool    `json:"unmount-on-done,omitempty"`
	WorkerThreads  *int64   `json:"worker-threads,omitempty"`
	// RateIn, BurstIn, RateOut and BurstOut are byte sizes, in the spelling
	// PBS stores them in; SameByteSize compares them.
	RateIn   string `json:"rate-in,omitempty"`
	BurstIn  string `json:"burst-in,omitempty"`
	RateOut  string `json:"rate-out,omitempty"`
	BurstOut string `json:"burst-out,omitempty"`
	// ActiveEncryptionKey is the sync encryption key a push job encrypts
	// with, from PBS 4.2; AssociatedKey the keys it keeps for decrypting,
	// those it encrypted with before among them.
	ActiveEncryptionKey string   `json:"active-encryption-key,omitempty"`
	AssociatedKey       []string `json:"associated-key,omitempty"`
	Comment             string   `json:"comment,omitempty"`
}

// Direction is the job's sync direction, pull when PBS reports none.
func (j SyncJob) Direction() string {
	if j.SyncDirection == "" {
		return SyncDirectionPull
	}
	return j.SyncDirection
}

// ListSyncJobs lists the sync jobs of both directions that the caller may
// read.
func (c *Client) ListSyncJobs(ctx context.Context) ([]SyncJob, error) {
	var jobs []SyncJob
	_, err := c.Get(ctx, "/config/sync", url.Values{"sync-direction": {SyncDirectionAll}}, &jobs)
	return jobs, err
}

// GetSyncJob reads one sync job, of either direction.
func (c *Client) GetSyncJob(ctx context.Context, id string) (SyncJob, error) {
	var job SyncJob
	_, err := c.Get(ctx, Path("config", "sync", id), nil, &job)
	return job, err
}

// CreateSyncJob creates a sync job from params, which must hold "id",
// "store" and "remote-store".
func (c *Client) CreateSyncJob(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/sync", params, nil)
	return err
}

// UpdateSyncJob changes the properties params carries, and deletes those
// named in its delete parameter.
func (c *Client) UpdateSyncJob(ctx context.Context, id string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "sync", id), params, nil)
	return err
}

// DeleteSyncJob deletes a sync job.
func (c *Client) DeleteSyncJob(ctx context.Context, id string) error {
	_, err := c.Delete(ctx, Path("config", "sync", id), nil, nil)
	return err
}
