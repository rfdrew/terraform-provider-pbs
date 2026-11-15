package pbsclient

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
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

// LockS3Refresh is not a file: it is the name for WithConfigLock of this
// provider's own S3 refreshes — those of pbs_datastore_s3_refresh, and the
// one creating a datastore on S3 with reuse-datastore makes —, which run one
// at a time. From PBS 4.0.20 a
// refresh reads its bucket holding PBS's lock of datastore.cfg (see
// IsDatastoreConfigLocked), and the task of a second refresh started
// meanwhile needs that lock too, to open its datastore, to check its
// maintenance mode while it waits for the datastore's operations, and to
// start reading: when the first one still reads, it waits 10 s for it,
// fails, and can leave its datastore in maintenance mode s3-refresh, which
// only the call that started it set (src/api2/admin/datastore.rs, s3_refresh,
// do_s3_refresh and run_maintenance_locked; proxmox-backup 7c86c5ad5, after
// 4.2.11). The refresh holds this lock from the call that starts it to the
// end of its task, when it waits for it. It is not ConfigDatastores, which
// the datastore writes of this provider take, so that they do not wait
// through the first part of a refresh, which waits without limit for the
// datastore's operations and keeps PBS's lock free meanwhile.
//
// That first part is not quite free of PBS's lock, though: while a refresh
// waits for its datastore's operations, its task takes the lock every second
// to check that the maintenance mode is still s3-refresh, and fails when it
// waits for it in vain, which may leave its datastore in that mode
// (run_maintenance_locked and expect_maintenance_type,
// src/api2/admin/datastore.rs:2691-2695, 2881-2919). A datastore this
// provider creates meanwhile can make it fail so: its create-datastore task
// holds the lock while it makes the chunk store (do_create_datastore,
// src/api2/config/datastore.rs:106-243), for longer than 10 s on slow storage
// or with a slow S3 endpoint. Datastore creates deliberately do not take
// LockS3Refresh all the same — but that of a datastore on S3 taken over with
// reuse-datastore, which is a refresh itself —, as they would wait, for
// hours perhaps, for the operations of another datastore.
//
// Whoever takes both takes LockS3Refresh first, then ConfigDatastores.
const LockS3Refresh = "s3-refresh"

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

// WithConfigLockWaiting is WithConfigLock, calling waiting first when the
// lock is held, so that a caller can say what it waits for.
func (c *Client) WithConfigLockWaiting(file string, waiting func(), fn func() error) error {
	m := c.configLocks.lock(file)
	if !m.TryLock() {
		waiting()
		m.Lock()
	}
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

// PBS's lock of its datastore configuration, /etc/proxmox-backup/.datastore.lck,
// guards more than the file: PBS takes it to change the settings of any
// datastore, and to open any datastore, and a task that holds it for long — an
// S3 refresh reading its bucket from PBS 4.0.20, a datastore creation making
// its chunk store — makes every such call wait 10 s for it and then fail
// (IsDatastoreConfigLocked has the details). Call tries such a call again, for
// about five minutes, so that a refresh started by an action, by a datastore
// taken over on S3, or outside Terraform holds an apply up rather than fail
// it.
//
// Trying again is safe because PBS takes the lock before it changes anything:
// the create, update and delete of a datastore and its unmount and S3 refresh
// take it first (src/api2/config/datastore.rs:279, 483, 741;
// src/api2/admin/datastore.rs:2764, 2846; proxmox-backup 7c86c5ad5, after
// 4.2.11), and every call that opens a datastore takes it in
// DataStore::lookup_datastore before it looks at the datastore
// (pbs-datastore/src/datastore.rs:578-581). The one exception is the unmount
// of a datastore with gc-on-unmount, which first starts a garbage collection
// through the proxy (src/api2/admin/datastore.rs:2746-2761): the unmount
// tried again finds that garbage collection running and waits for it rather
// than starting another. A task that fails on the lock is not tried again:
// that is the task's own outcome.
//
// While the lock is held, each request PBS waits on ties up a worker thread
// of a PBS daemon for 10 s, and Terraform makes up to ten calls at once. The
// client therefore sends one request at a time to find out whether the lock
// is free: the first call refused becomes the probe, and sends its request
// again after a pause of datastoreLockPause, as often as PBS refuses it, up
// to datastoreLockAttempts requests in all; calls refused meanwhile wait for
// the probe, and send theirs again once PBS let the probe through. A probe
// that stops before PBS answered it — its request failed, or its context
// ended — hands over to a call that waits for it, which probes on from the
// probe's count: one wait for the lock takes about five minutes, however
// many calls take turns probing in it.
//
// When the probe gives up, so do the calls that wait for it, and from then
// on calls PBS refuses fail at once instead of probing again, until
// datastoreLockCoolOff passes without a refusal, or a call succeeds on a
// route — a method and path — PBS refused for the lock since: a list over
// many datastores, or a plan of many namespaces, does not wait five minutes
// for each, nor for every sixth, which a window counted from the give-up
// alone would let probe again, as each refusal takes PBS 10 s. A success on
// such a route shows that the lock is free, as PBS takes the lock to answer
// it, which its refusal showed. A success on another route shows nothing, as
// PBS answers many calls without the lock — reads of datastore.cfg, its
// version, a task's status —, and neither does an error on such a route, as
// PBS checks privileges before it opens a datastore: the cool-off goes on.
//
// The request timeout bounds each request, so the retry sees PBS's answer
// only when it is well above PBS's 10 s.

const (
	// datastoreLockAttempts bounds the requests PBS refuses for the lock in
	// one wait for it: those of a call, counting those of the probes it took
	// over. PBS waits 10 s before it answers each, so with datastoreLockPause
	// in between they take about five minutes.
	datastoreLockAttempts = 27
	// datastoreLockPause is the pause before a probe tries again.
	datastoreLockPause = time.Second
	// datastoreLockCoolOff is how long after a probe gave up, or after the
	// last call refused since, calls refused for the lock fail at once — but
	// for a call that succeeded on a route PBS refused, which ends it.
	datastoreLockCoolOff = time.Minute
)

// datastoreLockGate is the client's probe of PBS's lock of its datastore
// configuration.
type datastoreLockGate struct {
	mu sync.Mutex
	// probe is the probe in flight, if any.
	probe *datastoreLockProbe
	// waiting counts the calls that wait for it.
	waiting int
	// gaveUp is when the last probe gave up, or when PBS last refused a call
	// failed at once since; zero once a probe got through, or a call
	// succeeded on a route in refusedRoutes.
	gaveUp time.Time
	// refusedRoutes holds the routes, as "METHOD /path", PBS refused for the
	// lock since a probe last got through or the cool-off last ended: those
	// on which a call that succeeds ends the cool-off.
	refusedRoutes map[string]struct{}
}

// endCoolOffLocked ends the cool-off, with g.mu held: the lock is free.
func (g *datastoreLockGate) endCoolOffLocked() {
	g.gaveUp = time.Time{}
	clear(g.refusedRoutes)
}

// datastoreLockProbe is one call probing the lock for the others.
type datastoreLockProbe struct {
	// done is closed when the probe ends, with outcome and refused set.
	done    chan struct{}
	outcome datastoreLockOutcome
	// refused is how many requests PBS refused for the lock in the wait the
	// probe ended: those of its call, counting those of the probes it took
	// over. A call that takes over from it probes on from there.
	refused int
}

// datastoreLockOutcome is how a probe ended.
type datastoreLockOutcome int

const (
	// datastoreLockLeft: the probe stopped before PBS answered it about the
	// lock — its context ended, or its request failed —, and a call that
	// waited for it may probe in its place, from its count.
	datastoreLockLeft datastoreLockOutcome = iota
	// datastoreLockThrough: PBS answered the probe with something else than
	// the lock's error.
	datastoreLockThrough
	// datastoreLockGaveUp: PBS refused datastoreLockAttempts requests of the
	// probe, counting those of the probes it took over.
	datastoreLockGaveUp
)

// datastoreLockRetry is one call's part in it: how many of its requests PBS
// refused for the lock — counting those of the probes it took over —, and
// its probe while it is the one probing.
type datastoreLockRetry struct {
	refused int
	probe   *datastoreLockProbe
}

// retryDatastoreLock decides, for a call whose request PBS has just refused
// for the lock of its datastore configuration, whether to send the request
// again. It returns true once the call may: after a pause when the call
// probes, or when the probe it waited for got through. It returns false when
// the call is to fail with PBS's answer: its requests, counting those of the
// probes it took over, used up datastoreLockAttempts, the probe gave up, a
// probe gave up and PBS has kept refusing calls, each less than
// datastoreLockCoolOff after the last, or ctx ended. A call failed at once
// moves the cool-off on. A call whose probe stopped without PBS's answer
// probes in its place, from its count, or waits for the call that does.
func (c *Client) retryDatastoreLock(ctx context.Context, r *datastoreLockRetry, method, path string) bool {
	r.refused++
	g := &c.datastoreLock
	g.mu.Lock()
	if g.refusedRoutes == nil {
		g.refusedRoutes = map[string]struct{}{}
	}
	g.refusedRoutes[method+" "+path] = struct{}{}
	g.mu.Unlock()
	fields := map[string]any{"method": method, "path": path, "refused": r.refused}
	if r.refused >= datastoreLockAttempts {
		tflog.Info(ctx, "PBS's lock of its datastore configuration stayed taken; giving up", fields)
		c.endDatastoreLockProbe(r, datastoreLockGaveUp)
		return false
	}
	for r.probe == nil {
		g.mu.Lock()
		if t := now(); !g.gaveUp.IsZero() && t.Sub(g.gaveUp) < datastoreLockCoolOff {
			g.gaveUp = t
			g.mu.Unlock()
			tflog.Info(ctx, "PBS's lock of its datastore configuration is taken, and the provider gave up waiting "+
				"for it; not trying again", fields)
			return false
		}
		if g.probe == nil {
			r.probe = &datastoreLockProbe{done: make(chan struct{})}
			g.probe = r.probe
			g.mu.Unlock()
			break
		}
		probe := g.probe
		g.waiting++
		g.mu.Unlock()
		tflog.Info(ctx, "PBS's lock of its datastore configuration is taken; waiting for another call that tries again", fields)
		select {
		case <-probe.done:
		case <-ctx.Done():
		}
		g.mu.Lock()
		g.waiting--
		g.mu.Unlock()
		switch {
		case ctx.Err() != nil:
			return false
		case probe.outcome == datastoreLockThrough:
			tflog.Info(ctx, "PBS let another call through its lock of the datastore configuration; trying again", fields)
			return true
		case probe.outcome == datastoreLockGaveUp:
			return false
		}
		// The probe stopped without an answer: this call may probe in its
		// place, from its count, so that the wait does not start over.
		r.refused = max(r.refused, probe.refused)
		fields["refused"] = r.refused
	}
	g.mu.Lock()
	fields["waiting"] = g.waiting
	g.mu.Unlock()
	tflog.Info(ctx, "PBS's lock of its datastore configuration is taken by a task, such as an S3 refresh; trying again", fields)
	if err := c.sleep(ctx, datastoreLockPause); err != nil {
		c.endDatastoreLockProbe(r, datastoreLockLeft)
		return false
	}
	return true
}

// endDatastoreLockProbe ends the call's probe, if it runs one, and wakes the
// calls that wait for it. A probe that got through ends the cool-off, and one
// that gave up starts it.
func (c *Client) endDatastoreLockProbe(r *datastoreLockRetry, outcome datastoreLockOutcome) {
	probe := r.probe
	if probe == nil {
		return
	}
	r.probe = nil
	g := &c.datastoreLock
	g.mu.Lock()
	switch outcome {
	case datastoreLockGaveUp:
		g.gaveUp = now()
	case datastoreLockThrough:
		g.endCoolOffLocked()
	}
	probe.outcome = outcome
	probe.refused = r.refused
	if g.probe == probe {
		g.probe = nil
	}
	g.mu.Unlock()
	close(probe.done)
}

// datastoreLockSucceeded ends the cool-off, if it runs, after a call
// succeeded on a route in refusedRoutes, which shows that the lock is free. A
// success on any other route leaves it running until it lapses.
func (c *Client) datastoreLockSucceeded(method, path string) {
	g := &c.datastoreLock
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.refusedRoutes[method+" "+path]; ok {
		g.endCoolOffLocked()
	}
}
