package pbsclient

import (
	"context"
)

// Besides their configuration, PBS reports how datastores are doing: whether
// a removable one is mounted, how full each is, and how its last garbage
// collection went. What PBS 4.0 and 4.2 do, as read in its source
// (src/api2/admin/datastore.rs, src/api2/admin/gc.rs, src/api2/status/mod.rs):
//
//   - GET /config/datastore lists the configuration of the datastores the
//     caller has Datastore.Audit on.
//   - GET /admin/datastore lists every datastore the caller has
//     Datastore.Audit or Datastore.Backup on, or a privilege on a namespace
//     of, with its mount status, maintenance mode and backend type.
//   - GET /status/datastore-usage lists the same datastores with the size,
//     use and free space of the file system each is on, an estimate of when
//     it is full, and the status of the last garbage collection. A removable
//     datastore that is not mounted, and one PBS cannot open — in maintenance
//     mode "offline", say — are listed without figures, the latter with the
//     error; one the caller may only see a namespace of, without figures and
//     without an error.
//   - GET /admin/gc/{store} answers the garbage collection status of one
//     datastore as a list of one, or of none without Datastore.Audit or
//     Datastore.Backup on it. It opens the datastore, and fails while it is
//     not mounted or offline. A missing datastore is 400 "no such datastore
//     'x'".
//
// The figures of a garbage collection are those of the last run since the
// datastore was created, kept in its chunk store; they are zero before the
// first.

// Mount states, as MountStatus reports them.
const (
	MountStatusMounted      = "mounted"
	MountStatusNotMounted   = "notmounted"
	MountStatusNonRemovable = "nonremovable"
)

// DatastoreListItem is a datastore as GET /admin/datastore lists it.
type DatastoreListItem struct {
	Store string `json:"store"`
	// Comment is left out unless the caller has Datastore.Audit or
	// Datastore.Backup on the datastore.
	Comment     string `json:"comment,omitempty"`
	MountStatus string `json:"mount-status,omitempty"`
	Maintenance string `json:"maintenance,omitempty"`
	BackendType string `json:"backend-type,omitempty"`
}

// GCStatus is the outcome of a datastore's last garbage collection.
type GCStatus struct {
	// UPID is the last garbage collection's task, empty before the first.
	UPID           string `json:"upid,omitempty"`
	IndexFileCount int64  `json:"index-file-count"`
	IndexDataBytes int64  `json:"index-data-bytes"`
	DiskBytes      int64  `json:"disk-bytes"`
	DiskChunks     int64  `json:"disk-chunks"`
	RemovedBytes   int64  `json:"removed-bytes"`
	RemovedChunks  int64  `json:"removed-chunks"`
	PendingBytes   int64  `json:"pending-bytes"`
	PendingChunks  int64  `json:"pending-chunks"`
	RemovedBad     int64  `json:"removed-bad"`
	StillBad       int64  `json:"still-bad"`
	// CacheStats is set by releases with the garbage collection cache.
	CacheStats *GCCacheStats `json:"cache-stats,omitempty"`
}

// GCCacheStats are the hits and misses of garbage collection's cache.
type GCCacheStats struct {
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
}

// GCJobStatus is the garbage collection status of one datastore: its
// schedule, when it runs next, how its last run went, and that run's figures.
type GCJobStatus struct {
	Store    string `json:"store"`
	Schedule string `json:"schedule,omitempty"`
	// NextRun, LastRunEndtime and Duration are in seconds, the times since
	// the Unix epoch.
	NextRun        *int64 `json:"next-run,omitempty"`
	LastRunEndtime *int64 `json:"last-run-endtime,omitempty"`
	LastRunState   string `json:"last-run-state,omitempty"`
	Duration       *int64 `json:"duration,omitempty"`
	GCStatus
}

// DatastoreUsage is how full a datastore is, as GET /status/datastore-usage
// lists it. The figures are those of the file system the datastore is on, in
// bytes, and nil when PBS gives none.
type DatastoreUsage struct {
	Store       string `json:"store"`
	Total       *int64 `json:"total,omitempty"`
	Used        *int64 `json:"used,omitempty"`
	Avail       *int64 `json:"avail,omitempty"`
	MountStatus string `json:"mount-status,omitempty"`
	BackendType string `json:"backend-type,omitempty"`
	// EstimatedFullDate is when the datastore is expected to be full, in
	// seconds since the Unix epoch, from a month of history: 0 when its use
	// does not change, a time in the past when it shrinks, nil without
	// enough history.
	EstimatedFullDate *int64 `json:"estimated-full-date,omitempty"`
	// Error is why PBS could not open the datastore, if it could not.
	Error    string    `json:"error,omitempty"`
	GCStatus *GCStatus `json:"gc-status,omitempty"`
}

// ListDatastores lists the configuration of the datastores the caller may
// audit.
func (c *Client) ListDatastores(ctx context.Context) ([]Datastore, error) {
	var datastores []Datastore
	_, err := c.Get(ctx, "/config/datastore", nil, &datastores)
	return datastores, err
}

// ListDatastoreStates lists the datastores the caller may see, with their
// mount status and maintenance mode.
func (c *Client) ListDatastoreStates(ctx context.Context) ([]DatastoreListItem, error) {
	var items []DatastoreListItem
	_, err := c.Get(ctx, "/admin/datastore", nil, &items)
	return items, err
}

// DatastoreMountStatus returns the mount status of one datastore — one of
// the MountStatus constants — from the list of datastores, and "" when the
// list does not have it. A datastore that is not removable is
// MountStatusNonRemovable without asking PBS.
func (c *Client) DatastoreMountStatus(ctx context.Context, ds Datastore) (string, error) {
	if ds.BackingDevice == "" {
		return MountStatusNonRemovable, nil
	}
	items, err := c.ListDatastoreStates(ctx)
	if err != nil {
		return "", err
	}
	for _, item := range items {
		if item.Store == ds.Name {
			return item.MountStatus, nil
		}
	}
	return "", nil
}

// ListDatastoreUsage lists how full the datastores the caller may see are.
func (c *Client) ListDatastoreUsage(ctx context.Context) ([]DatastoreUsage, error) {
	var usage []DatastoreUsage
	_, err := c.Get(ctx, "/status/datastore-usage", nil, &usage)
	return usage, err
}

// GCJobStatus reads the garbage collection status of a datastore. ok is false
// when PBS answers none, because the caller has neither Datastore.Audit nor
// Datastore.Backup on it.
func (c *Client) GCJobStatus(ctx context.Context, store string) (status GCJobStatus, ok bool, err error) {
	var list []GCJobStatus
	if _, err := c.Get(ctx, Path("admin", "gc", store), nil, &list); err != nil {
		return GCJobStatus{}, false, err
	}
	for _, s := range list {
		if s.Store == store {
			return s, true, nil
		}
	}
	return GCJobStatus{}, false, nil
}
