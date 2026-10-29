package pbsclient

import (
	"context"
	"sync"
	"time"
)

// Configuration files hold many objects each — every ACL entry is in
// acl.cfg, every user and token in user.cfg, every notification target in
// notifications.cfg — and their digest covers the whole file: changing one
// remote changes the digest every other remote reports. Terraform writes
// resources in parallel, so two writes based on the same digest would fail
// one another. Resources therefore serialise their writes per file with
// WithConfigLock, and retry a write that still meets a digest conflict —
// from a writer outside this provider — with RetryOnDigestConflict.
//
// The lock belongs to the Client, so it covers every resource of one provider
// configuration. Two provider configurations pointing at the same server, or
// any writer outside Terraform, are not covered.

// Configuration files, as names for WithConfigLock.
const (
	ConfigACL           = "acl.cfg"
	ConfigUsers         = "user.cfg"
	ConfigDatastores    = "datastore.cfg"
	ConfigRemotes       = "remote.cfg"
	ConfigSyncJobs      = "sync.cfg"
	ConfigVerifyJobs    = "verification.cfg"
	ConfigPruneJobs     = "prune.cfg"
	ConfigDomains       = "domains.cfg"
	ConfigNotifications = "notifications.cfg"
	ConfigNode          = "node.cfg"
	ConfigNetwork       = "interfaces"
	ConfigACMEPlugins   = "acme/plugins.cfg"
	// ConfigAPTSources stands for every APT source file of the node, which
	// share one digest.
	ConfigAPTSources = "apt/sources.list"
)

type configLocks struct {
	mu    sync.Mutex
	files map[string]*sync.Mutex
}

func (l *configLocks) lock(file string) *sync.Mutex {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.files == nil {
		l.files = map[string]*sync.Mutex{}
	}
	m, ok := l.files[file]
	if !ok {
		m = &sync.Mutex{}
		l.files[file] = m
	}
	return m
}

// WithConfigLock runs fn while holding the lock of one configuration file.
func (c *Client) WithConfigLock(file string, fn func() error) error {
	m := c.configLocks.lock(file)
	m.Lock()
	defer m.Unlock()
	return fn()
}

// digestRetries bounds RetryOnDigestConflict. A conflict means someone else
// wrote the file between this provider's read and write; a handful of
// retries outlasts a person clicking through the UI, while a loop that never
// wins points at something rewriting the file all the time.
const digestRetries = 5

// RetryOnDigestConflict runs fn, which should read the current digest and
// write with it, again while it fails with a digest conflict, with a short
// pause in between.
func (c *Client) RetryOnDigestConflict(ctx context.Context, fn func() error) error {
	delay := 100 * time.Millisecond
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil || !IsDigestConflict(err) || attempt >= digestRetries {
			return err
		}
		if err := c.sleep(ctx, delay); err != nil {
			return err
		}
		delay *= 2
	}
}
