package pbsclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Calls PBS refuses because a task holds the lock of its datastore
// configuration are tried again, one call at a time probing for the others;
// see locks.go.

// The routes CreateNamespace and ListNamespaces of store1 call, which PBS
// answers only once it has opened the datastore, and so taken the lock.
const (
	namespacePostRoute = "POST /admin/datastore/store1/namespace"
	namespaceGetRoute  = "GET /admin/datastore/store1/namespace"
)

// lockedRoute answers a route with text, PBS's error for a lock it waited
// for in vain, for the first refusals requests — every request when refusals
// is negative — and with success after that. It counts the requests, and the
// most that were in flight at once when one after the first solo began.
type lockedRoute struct {
	mu        sync.Mutex
	refusals  int
	solo      int
	requests  int
	inFlight  int
	maxFlight int
}

func newLockedRoute(f *fakePBS, route, text string, refusals int, success string) *lockedRoute {
	l := &lockedRoute{refusals: refusals}
	f.handle(route, func(w http.ResponseWriter, _ *http.Request) {
		l.mu.Lock()
		l.requests++
		refuse := l.refusals < 0 || l.requests <= l.refusals
		l.inFlight++
		if l.requests > l.solo {
			l.maxFlight = max(l.maxFlight, l.inFlight)
		}
		l.mu.Unlock()
		// PBS answers after 10 s; a moment lets requests that overlap show.
		time.Sleep(2 * time.Millisecond)
		l.mu.Lock()
		l.inFlight--
		l.mu.Unlock()
		if refuse {
			writeFakeResponse(w, http.StatusBadRequest, text)
			return
		}
		writeFakeResponse(w, http.StatusOK, success)
	})
	return l
}

// counts returns how many requests were made, and the most in flight at once.
func (l *lockedRoute) counts() (requests, maxFlight int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.requests, l.maxFlight
}

// setRefusals changes how many requests in all are refused.
func (l *lockedRoute) setRefusals(refusals int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refusals = refusals
}

// recordedPauses replaces a client's sleep, recording each pause; before,
// when set, runs at the start of the nth pause, counting from 1.
type recordedPauses struct {
	mu     sync.Mutex
	pauses []time.Duration
	before func(n int)
}

func recordPauses(c *Client) *recordedPauses {
	p := &recordedPauses{}
	c.sleep = p.sleep
	return p
}

func (p *recordedPauses) sleep(ctx context.Context, d time.Duration) error {
	p.mu.Lock()
	p.pauses = append(p.pauses, d)
	n, before := len(p.pauses), p.before
	p.mu.Unlock()
	if before != nil {
		before(n)
	}
	return ctx.Err()
}

func (p *recordedPauses) all() []time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.pauses)
}

// datastoreLockPauses returns n pauses of datastoreLockPause.
func datastoreLockPauses(n int) []time.Duration {
	return slices.Repeat([]time.Duration{datastoreLockPause}, n)
}

// requireLockedError fails the test unless err is PBS's refusal for the
// lock of the datastore configuration, as PBS sent it.
func requireLockedError(t *testing.T, err error) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) || !IsDatastoreConfigLocked(err) || apiErr.Message != datastoreConfigLockedText {
		t.Fatalf("error = %v, want PBS's refusal for the lock of the datastore configuration", err)
	}
}

func TestCallRetriesDatastoreConfigLock(t *testing.T) {
	fake := newFakePBS()
	route := newLockedRoute(fake, namespacePostRoute, datastoreConfigLockedText, 2, `{"data":null}`)
	c := fake.client(t)
	pauses := recordPauses(c)

	if err := c.CreateNamespace(context.Background(), "store1", "dept1"); err != nil {
		t.Fatal(err)
	}
	if requests, _ := route.counts(); requests != 3 {
		t.Fatalf("made %d requests, want 3: two refused, one through", requests)
	}
	if got := pauses.all(); !slices.Equal(got, datastoreLockPauses(2)) {
		t.Fatalf("paused %v, want a pause of %s before each of the two tries", got, datastoreLockPause)
	}
	if form := fake.lastCall(t, namespacePostRoute).form; form.Get("name") != "dept1" {
		t.Fatalf("the request tried again had form %v", form)
	}
}

func TestCallGivesUpOnDatastoreConfigLock(t *testing.T) {
	fake := newFakePBS()
	route := newLockedRoute(fake, namespacePostRoute, datastoreConfigLockedText, -1, "")
	c := fake.client(t)
	pauses := recordPauses(c)

	requireLockedError(t, c.CreateNamespace(context.Background(), "store1", "dept1"))
	if requests, _ := route.counts(); requests != datastoreLockAttempts {
		t.Fatalf("made %d requests, want %d", requests, datastoreLockAttempts)
	}
	if got := pauses.all(); !slices.Equal(got, datastoreLockPauses(datastoreLockAttempts-1)) {
		t.Fatalf("paused %v", got)
	}
	// PBS waits 10 s before each answer: the attempts and pauses make about
	// five minutes.
	if total := datastoreLockAttempts*10*time.Second + (datastoreLockAttempts-1)*datastoreLockPause; total < 4*time.Minute+30*time.Second || total > 5*time.Minute+30*time.Second {
		t.Fatalf("the attempts take %s with PBS's 10 s each, want about five minutes", total)
	}
}

// A job's lock means the job runs, for hours perhaps: that is not tried
// again.
func TestCallDoesNotRetryJobLock(t *testing.T) {
	fake := newFakePBS()
	route := newLockedRoute(fake, "POST /admin/sync/offsite/run", jobLockedText, -1, "")
	c := fake.client(t)
	pauses := recordPauses(c)

	_, err := c.StartTask(context.Background(), http.MethodPost, "/admin/sync/offsite/run", nil)
	if !IsTaskAlreadyRunning(err) || IsDatastoreConfigLocked(err) {
		t.Fatalf("error = %v, want a job that is running", err)
	}
	if requests, _ := route.counts(); requests != 1 || len(pauses.all()) != 0 {
		t.Fatalf("made %d requests and %d pauses, want one request", requests, len(pauses.all()))
	}
}

// A call whose context ends while it waits stops with PBS's answer, and
// leaves the probe to the next call, which does not give up at once.
func TestCallStopsRetryingDatastoreConfigLockOnCancel(t *testing.T) {
	fake := newFakePBS()
	route := newLockedRoute(fake, namespacePostRoute, datastoreConfigLockedText, 1, `{"data":null}`)
	c := fake.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}

	requireLockedError(t, c.CreateNamespace(ctx, "store1", "dept1"))
	if requests, _ := route.counts(); requests != 1 {
		t.Fatalf("made %d requests, want 1", requests)
	}

	route.setRefusals(2)
	pauses := recordPauses(c)
	if err := c.CreateNamespace(context.Background(), "store1", "dept1"); err != nil {
		t.Fatalf("the next call: %v", err)
	}
	if got := pauses.all(); !slices.Equal(got, datastoreLockPauses(1)) {
		t.Fatalf("the next call paused %v, want one pause", got)
	}
}

// Trying again keeps the ticket: a password client signs in once.
func TestCallRetriesDatastoreConfigLockWithTicket(t *testing.T) {
	fake := newFakePBS()
	route := newLockedRoute(fake, namespacePostRoute, datastoreConfigLockedText, 3, `{"data":null}`)
	c := fake.passwordClient(t)
	recordPauses(c)

	if err := c.CreateNamespace(context.Background(), "store1", "dept1"); err != nil {
		t.Fatal(err)
	}
	if requests, _ := route.counts(); requests != 4 {
		t.Fatalf("made %d requests, want 4", requests)
	}
	if n := fake.count("POST /access/ticket"); n != 1 {
		t.Fatalf("signed in %d times, want once", n)
	}
	call := fake.lastCall(t, namespacePostRoute)
	if call.header.Get(csrfHeader) == "" {
		t.Fatalf("the request tried again had no CSRF token: %v", call.header)
	}
}

// Two calls refused at the same time: one probes, the other waits for it
// and tries again once the probe got through, so that PBS has one request of
// theirs at a time; when the probe gives up, so does the other call.
func TestCallsProbeDatastoreConfigLockOneAtATime(t *testing.T) {
	fake := newFakePBS()
	// Two first requests, two probes refused, then the lock is free. The
	// first two requests may overlap; none after them may.
	route := newLockedRoute(fake, namespaceGetRoute, datastoreConfigLockedText, 4, `{"data":[{"ns":""}]}`)
	route.solo = 2
	c := fake.client(t)
	pauses := recordPauses(c)
	// The prober waits for the other call to wait for it before it probes.
	pauses.before = func(n int) {
		if n == 1 {
			waitForDatastoreLockWaiters(t, c, 1)
		}
	}

	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := c.ListNamespaces(context.Background(), "store1", "", -1)
			errs <- err
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	requests, maxFlight := route.counts()
	// 2 first requests, 2 probes refused, 1 through, and the waiting call's
	// own.
	if requests != 6 {
		t.Fatalf("made %d requests, want 6", requests)
	}
	if maxFlight != 1 {
		t.Fatalf("%d requests were in flight at once after the first two", maxFlight)
	}
	if got := pauses.all(); !slices.Equal(got, datastoreLockPauses(3)) {
		t.Fatalf("paused %v, want the probe's three pauses only", got)
	}

	// The lock stays taken: the probe gives up, and the waiting call with
	// it, after its one request.
	fake = newFakePBS()
	route = newLockedRoute(fake, namespaceGetRoute, datastoreConfigLockedText, -1, "")
	c = fake.client(t)
	pauses = recordPauses(c)
	pauses.before = func(n int) {
		if n == 1 {
			waitForDatastoreLockWaiters(t, c, 1)
		}
	}
	for range 2 {
		go func() {
			_, err := c.ListNamespaces(context.Background(), "store1", "", -1)
			errs <- err
		}()
	}
	for range 2 {
		requireLockedError(t, <-errs)
	}
	if requests, _ := route.counts(); requests != datastoreLockAttempts+1 {
		t.Fatalf("made %d requests, want %d", requests, datastoreLockAttempts+1)
	}
}

// waitForDatastoreLockWaiters waits until n calls wait for the probe.
func waitForDatastoreLockWaiters(t *testing.T, c *Client, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.datastoreLock.mu.Lock()
		waiting := c.datastoreLock.waiting
		c.datastoreLock.mu.Unlock()
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%d calls wait for the probe, want %d", waiting, n)
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// A probe that stops before PBS answered it — its context ended, or its
// request failed — hands over to the call that waits for it, which probes on
// from the probe's count: the two give up after datastoreLockAttempts
// refusals between them, about five minutes, not five more each.
func TestCallTakesOverDatastoreConfigLockProbe(t *testing.T) {
	// stopAt is how many refusals the probe has had when it stops.
	const stopAt = 20
	errLost := errors.New("connection reset by peer")
	for _, how := range []string{"context ended", "request failed"} {
		t.Run(how, func(t *testing.T) {
			fake := newFakePBS()
			route := newLockedRoute(fake, namespaceGetRoute, datastoreConfigLockedText, -1, "")
			c := fake.client(t)
			var failNext atomic.Bool
			c.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if failNext.CompareAndSwap(true, false) {
					return nil, errLost
				}
				return fake.RoundTrip(req)
			})
			pauses := recordPauses(c)
			probeCtx, stopProbe := context.WithCancel(context.Background())
			defer stopProbe()
			waiter := make(chan error, 1)
			// The probe has the other call wait for it at its first pause,
			// and stops at its stopAt-th: the pause ends with its context,
			// or its next request fails.
			pauses.before = func(n int) {
				switch n {
				case 1:
					go func() {
						_, err := c.ListNamespaces(context.Background(), "store1", "", -1)
						waiter <- err
					}()
					waitForDatastoreLockWaiters(t, c, 1)
				case stopAt:
					if how == "context ended" {
						stopProbe()
					} else {
						failNext.Store(true)
					}
				}
			}

			_, err := c.ListNamespaces(probeCtx, "store1", "", -1)
			if how == "context ended" {
				requireLockedError(t, err)
			} else if !errors.Is(err, errLost) {
				t.Fatalf("the probe: error = %v, want its request's", err)
			}
			requireLockedError(t, <-waiter)
			requests, maxFlight := route.counts()
			// The probe's stopAt, the other call's first, and the other
			// call's datastoreLockAttempts-stopAt as the probe.
			if requests != datastoreLockAttempts+1 {
				t.Fatalf("PBS refused %d requests, want %d: the call that took over started over", requests, datastoreLockAttempts+1)
			}
			if maxFlight != 1 {
				t.Fatalf("%d requests were in flight at once", maxFlight)
			}
			if got := pauses.all(); !slices.Equal(got, datastoreLockPauses(datastoreLockAttempts)) {
				t.Fatalf("paused %d times, want %d", len(got), datastoreLockAttempts)
			}
		})
	}
}

// A call whose context ends while it waits for the probe returns PBS's
// refusal at once, without sending its request again; the probe goes on.
func TestCallStopsWaitingForDatastoreConfigLockOnCancel(t *testing.T) {
	fake := newFakePBS()
	// The probe's first request, the waiting call's, and the probe's second
	// are refused; then the lock is free.
	route := newLockedRoute(fake, namespaceGetRoute, datastoreConfigLockedText, 3, `{"data":[{"ns":""}]}`)
	c := fake.client(t)
	pauses := recordPauses(c)
	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	defer cancelWaiter()
	var waiterErr error
	pauses.before = func(n int) {
		if n != 1 {
			return
		}
		waiter := make(chan error, 1)
		go func() {
			_, err := c.ListNamespaces(waiterCtx, "store1", "", -1)
			waiter <- err
		}()
		waitForDatastoreLockWaiters(t, c, 1)
		cancelWaiter()
		select {
		case waiterErr = <-waiter:
		case <-time.After(10 * time.Second):
			waiterErr = errors.New("the waiting call did not stop when its context ended")
		}
	}

	if _, err := c.ListNamespaces(context.Background(), "store1", "", -1); err != nil {
		t.Fatalf("the probe: %v", err)
	}
	requireLockedError(t, waiterErr)
	// The probe's three and the waiting call's one.
	if requests, _ := route.counts(); requests != 4 {
		t.Fatalf("made %d requests, want 4: the waiting call sent its request again", requests)
	}
	if got := pauses.all(); !slices.Equal(got, datastoreLockPauses(2)) {
		t.Fatalf("paused %v, want the probe's two pauses only", got)
	}
	c.datastoreLock.mu.Lock()
	waiting := c.datastoreLock.waiting
	c.datastoreLock.mu.Unlock()
	if waiting != 0 {
		t.Fatalf("%d calls still wait", waiting)
	}
}

// After a probe gave up, a call refused within the cool-off fails at once;
// after it, a call probes again.
func TestCallDatastoreConfigLockCoolOff(t *testing.T) {
	fake := newFakePBS()
	route := newLockedRoute(fake, namespacePostRoute, datastoreConfigLockedText, -1, `{"data":null}`)
	c := fake.client(t)
	pauses := recordPauses(c)
	clock := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	t.Cleanup(func() { now = time.Now })
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(d)
	}
	ctx := context.Background()

	requireLockedError(t, c.CreateNamespace(ctx, "store1", "dept1"))
	if requests, _ := route.counts(); requests != datastoreLockAttempts {
		t.Fatalf("made %d requests, want %d", requests, datastoreLockAttempts)
	}

	advance(datastoreLockCoolOff - time.Second)
	requireLockedError(t, c.CreateNamespace(ctx, "store1", "dept2"))
	if requests, _ := route.counts(); requests != datastoreLockAttempts+1 {
		t.Fatalf("within the cool-off: %d requests in all, want one more", requests)
	}
	if got := len(pauses.all()); got != datastoreLockAttempts-1 {
		t.Fatalf("within the cool-off: %d pauses in all, want none more", got)
	}

	// The refusal moved the cool-off on: two seconds later a call still
	// fails at once.
	advance(2 * time.Second)
	requireLockedError(t, c.CreateNamespace(ctx, "store1", "dept2"))
	if requests, _ := route.counts(); requests != datastoreLockAttempts+2 {
		t.Fatalf("within the moved cool-off: %d requests in all, want one more", requests)
	}

	// Once a minute passed without a refusal, a call probes again: refused
	// twice more, then through.
	advance(datastoreLockCoolOff + time.Second)
	route.setRefusals(datastoreLockAttempts + 4)
	if err := c.CreateNamespace(ctx, "store1", "dept3"); err != nil {
		t.Fatalf("after the cool-off: %v", err)
	}
	if requests, _ := route.counts(); requests != datastoreLockAttempts+5 {
		t.Fatalf("after the cool-off: %d requests in all, want %d", requests, datastoreLockAttempts+5)
	}
	if got := len(pauses.all()); got != datastoreLockAttempts+1 {
		t.Fatalf("after the cool-off: %d pauses in all, want two more", got)
	}
}

// Serial calls PBS keeps refusing, each 10 s after the last, as a listing
// over many datastores makes them, fail at once after the first gave up:
// none probes again while the refusals go on.
func TestCallDatastoreConfigLockCoolOffSlides(t *testing.T) {
	fake := newFakePBS()
	route := newLockedRoute(fake, namespacePostRoute, datastoreConfigLockedText, -1, `{"data":null}`)
	c := fake.client(t)
	pauses := recordPauses(c)
	clock := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	t.Cleanup(func() { now = time.Now })
	ctx := context.Background()

	const calls = 10
	for i := range calls {
		requireLockedError(t, c.CreateNamespace(ctx, "store1", fmt.Sprintf("dept%d", i)))
		clockMu.Lock()
		clock = clock.Add(10 * time.Second)
		clockMu.Unlock()
	}
	if requests, _ := route.counts(); requests != datastoreLockAttempts+calls-1 {
		t.Fatalf("made %d requests, want %d: only the first call probes", requests, datastoreLockAttempts+calls-1)
	}
	if got := len(pauses.all()); got != datastoreLockAttempts-1 {
		t.Fatalf("paused %d times, want %d", got, datastoreLockAttempts-1)
	}

	// A call that succeeds on the route PBS refused ends the cool-off at
	// once.
	route.setRefusals(0)
	if err := c.CreateNamespace(ctx, "store1", "free"); err != nil {
		t.Fatalf("a free lock: %v", err)
	}
	c.datastoreLock.mu.Lock()
	gaveUp := c.datastoreLock.gaveUp
	c.datastoreLock.mu.Unlock()
	if !gaveUp.IsZero() {
		t.Fatalf("the cool-off goes on after a call got through: %v", gaveUp)
	}
}

// The cool-off ends only with a call that succeeds on a route PBS refused
// for the lock: PBS answers reads of datastore.cfg, its version and others
// without the lock, and checks privileges before it opens a datastore, so
// neither a success elsewhere nor an error on that route shows the lock
// free.
func TestCallDatastoreConfigLockCoolOffOutlastsOtherAnswers(t *testing.T) {
	fake := newFakePBS()
	route := newLockedRoute(fake, namespacePostRoute, datastoreConfigLockedText, -1, "")
	fake.reply("GET /config/datastore/store1", http.StatusOK, `{"data":{"name":"store1","path":"/mnt/datastore/store1"}}`)
	c := fake.client(t)
	pauses := recordPauses(c)
	clock := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	t.Cleanup(func() { now = time.Now })
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(d)
	}
	ctx := context.Background()

	requireLockedError(t, c.CreateNamespace(ctx, "store1", "dept1"))
	advance(10 * time.Second)
	if _, err := c.GetDatastore(ctx, "store1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "/version", nil, nil); err != nil {
		t.Fatal(err)
	}
	advance(10 * time.Second)
	requireLockedError(t, c.CreateNamespace(ctx, "store1", "dept2"))
	if requests, _ := route.counts(); requests != datastoreLockAttempts+1 {
		t.Fatalf("after successes on other routes: %d requests in all, want %d", requests, datastoreLockAttempts+1)
	}
	if got := len(pauses.all()); got != datastoreLockAttempts-1 {
		t.Fatalf("after successes on other routes: %d pauses in all, want none more", got)
	}

	// PBS refuses the privilege before it opens the datastore.
	fake.reply(namespacePostRoute, http.StatusForbidden, "permission check failed")
	if err := c.CreateNamespace(ctx, "store1", "dept3"); !IsForbidden(err) {
		t.Fatalf("error = %v, want PBS's refusal of the privilege", err)
	}
	advance(10 * time.Second)
	route = newLockedRoute(fake, namespacePostRoute, datastoreConfigLockedText, -1, "")
	requireLockedError(t, c.CreateNamespace(ctx, "store1", "dept2"))
	if requests, _ := route.counts(); requests != 1 {
		t.Fatalf("after an error on the route: %d requests, want 1", requests)
	}
	if got := len(pauses.all()); got != datastoreLockAttempts-1 {
		t.Fatalf("after an error on the route: %d pauses in all, want none more", got)
	}
}

// WithConfigLockWaiting says when it has to wait, and only then.
func TestWithConfigLockWaiting(t *testing.T) {
	c := newFakePBS().client(t)
	waited := 0
	ran := false
	if err := c.WithConfigLockWaiting(LockS3Refresh, func() { waited++ }, func() error { ran = true; return nil }); err != nil || !ran || waited != 0 {
		t.Fatalf("a free lock: err = %v, ran = %v, waited %d times", err, ran, waited)
	}

	held, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = c.WithConfigLock(LockS3Refresh, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	order := make(chan string, 2)
	done := make(chan error)
	go func() {
		done <- c.WithConfigLockWaiting(LockS3Refresh, func() {
			order <- "waiting"
			close(release)
		}, func() error {
			order <- "ran"
			return errors.New("fn's error")
		})
	}()
	if err := <-done; err == nil || err.Error() != "fn's error" {
		t.Fatalf("err = %v, want fn's", err)
	}
	if first, second := <-order, <-order; first != "waiting" || second != "ran" {
		t.Fatalf("order: %s, %s", first, second)
	}
	// Another lock name is a lock of its own.
	if err := c.WithConfigLockWaiting(ConfigDatastores, func() { t.Error("waited for another lock") }, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
