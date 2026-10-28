package pbsclient

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// Datastores live in datastore.cfg. What PBS 4.0 and 4.2 do, as observed on
// real servers:
//
//   - POST /config/datastore answers with the UPID of a create-datastore
//     task, although the schema says null, and HTTP 200 even when the task
//     is going to fail: an error such as "datastore path not empty" is only
//     in the task's exit status. The configuration entry is written by the
//     task, tens of milliseconds after the answer.
//   - A datastore is created in an empty directory, or one with dotfiles and
//     lost+found only. The task fails with "datastore path not empty" on a
//     directory with anything else, backups say, and with an EEXIST on
//     .chunks on one that holds a chunk store alone, as a datastore deleted
//     without destroy-data leaves; reuse-datastore takes over such a chunk
//     store, and fails on a directory without one.
//   - A deletion that cannot remove the data ends with warnings and keeps
//     the datastore, in maintenance mode "delete".
//   - DELETE answers with the UPID of a delete-datastore task. Without
//     destroy-data the directory and its chunk store stay behind; without
//     keep-job-configs PBS deletes the datastore's prune, verify and sync
//     jobs along with it.
//   - A read leaves out every property at its default. A missing datastore
//     is 400 "no such datastore 'x'" on GET and 404 "datastore 'x' does not
//     exist." on DELETE; IsNotFound covers both.
//   - notify, tuning and maintenance-mode are property strings;
//     ParsePropertyString reads them.

// Maintenance types. A caller may set read-only and offline; PBS sets the
// others itself, while it unmounts a removable datastore, deletes a datastore
// or refreshes the cache of an S3-backed one.
const (
	MaintenanceReadOnly  = "read-only"
	MaintenanceOffline   = "offline"
	MaintenanceDelete    = "delete"
	MaintenanceUnmount   = "unmount"
	MaintenanceS3Refresh = "s3-refresh"
)

// IsInternalMaintenance reports whether PBS sets the maintenance type itself,
// for an operation in progress, rather than a caller.
func IsInternalMaintenance(maintenanceType string) bool {
	switch maintenanceType {
	case MaintenanceDelete, MaintenanceUnmount, MaintenanceS3Refresh:
		return true
	}
	return false
}

// Datastore is a datastore's configuration as PBS reports it. Property
// strings are left as PBS sends them.
type Datastore struct {
	Name             string `json:"name"`
	Path             string `json:"path"`
	Comment          string `json:"comment,omitempty"`
	GCSchedule       string `json:"gc-schedule,omitempty"`
	GCOnUnmount      *bool  `json:"gc-on-unmount,omitempty"`
	VerifyNew        *bool  `json:"verify-new,omitempty"`
	NotifyUser       string `json:"notify-user,omitempty"`
	NotificationMode string `json:"notification-mode,omitempty"`
	Notify           string `json:"notify,omitempty"`
	Tuning           string `json:"tuning,omitempty"`
	MaintenanceMode  string `json:"maintenance-mode,omitempty"`
	// Backend is set for a datastore on S3, BackingDevice for a removable
	// one; both are given at creation only.
	Backend       string `json:"backend,omitempty"`
	BackingDevice string `json:"backing-device,omitempty"`
}

// Datastore backends, as BackendType reports them.
const (
	BackendFilesystem = "filesystem"
	BackendS3         = "s3"
)

// BackendType is where the datastore keeps its chunks: BackendFilesystem, the
// default, or BackendS3. A backend PBS describes in a way this client cannot
// read is returned as PBS wrote it.
func (d Datastore) BackendType() string {
	if d.Backend == "" {
		return BackendFilesystem
	}
	backend, err := ParsePropertyString(d.Backend, "type")
	if err != nil {
		return d.Backend
	}
	if t := backend["type"]; t != "" {
		return t
	}
	return BackendFilesystem
}

// DatastoreDeletion says what DeleteDatastore deletes besides the
// configuration entry.
type DatastoreDeletion struct {
	// DestroyData deletes the datastore's directory and everything in it.
	DestroyData bool
	// KeepJobConfigs keeps the datastore's prune, verify and sync jobs,
	// which PBS otherwise deletes along with it.
	KeepJobConfigs bool
}

// A created datastore's configuration entry is written by the task that
// creates it; when PBS answers without a task, it is looked for this many
// times, this far apart, before giving up.
const (
	datastoreEntryPolls    = 20
	datastoreEntryInterval = 250 * time.Millisecond
)

// GetDatastore reads one datastore's configuration.
func (c *Client) GetDatastore(ctx context.Context, name string) (Datastore, error) {
	var ds Datastore
	_, err := c.Get(ctx, Path("config", "datastore", name), nil, &ds)
	return ds, err
}

// CreateDatastore creates a datastore from params, which must hold "name"
// and "path", and waits for the create-datastore task, whose exit status
// carries the errors the answer does not; a failed task is a *TaskError, and
// leaves no datastore behind. Read the new datastore with WaitForDatastore.
//
// The task holds PBS's lock on datastore.cfg while it creates the chunk
// store, and other writes to the file wait for it for 10 seconds at most, so
// callers hold WithConfigLock(ConfigDatastores) for the whole call.
func (c *Client) CreateDatastore(ctx context.Context, params url.Values) error {
	env, err := c.Post(ctx, "/config/datastore", params, nil)
	if err != nil {
		return err
	}
	return c.WaitTaskIn(ctx, env.Data)
}

// WaitForDatastore reads a datastore CreateDatastore created, waiting a few
// seconds for its configuration entry should it not be there yet.
func (c *Client) WaitForDatastore(ctx context.Context, name string) (Datastore, error) {
	for attempt := 1; ; attempt++ {
		ds, err := c.GetDatastore(ctx, name)
		if err == nil || !IsNotFound(err) {
			return ds, err
		}
		if attempt >= datastoreEntryPolls {
			return ds, fmt.Errorf("the configuration of datastore %q did not appear after %d reads %s apart: %w",
				name, datastoreEntryPolls, datastoreEntryInterval, err)
		}
		if err := c.sleep(ctx, datastoreEntryInterval); err != nil {
			return ds, err
		}
	}
}

// UpdateDatastore changes the properties params carries, and deletes those
// named in its delete parameter.
func (c *Client) UpdateDatastore(ctx context.Context, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "datastore", name), params, nil)
	return err
}

// DeleteDatastore deletes a datastore's configuration, and with it what
// deletion says, and waits for the delete-datastore task.
func (c *Client) DeleteDatastore(ctx context.Context, name string, deletion DatastoreDeletion) error {
	params := url.Values{}
	if deletion.DestroyData {
		params.Set("destroy-data", "true")
	}
	if deletion.KeepJobConfigs {
		params.Set("keep-job-configs", "true")
	}
	env, err := c.Delete(ctx, Path("config", "datastore", name), params, nil)
	if err != nil {
		return err
	}
	return c.WaitTaskIn(ctx, env.Data)
}
