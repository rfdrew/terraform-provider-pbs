package provider

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// fakeS3StoreJSON is GET /config/datastore/store1 of a datastore on S3,
// with maintenance as its maintenance mode, if any.
func fakeS3StoreJSON(maintenance string) string {
	extra := ""
	if maintenance != "" {
		extra = `,"maintenance-mode":"` + maintenance + `"`
	}
	return `{"data":{"name":"store1","path":"/var/cache/pbs/store1","backend":"type=s3,client=ep1,bucket=backups"` + extra + `}}`
}

// newS3RefreshHarness serves datastore store1 on S3, as GET
// /config/datastore/store1 answers it in turn — the last answer repeats —,
// and a refresh that starts the task next returns.
func newS3RefreshHarness(t *testing.T, next func() *fakeTask, configs ...string) (*protocolHarness, *fakePBS, *fakeTasks) {
	t.Helper()
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	if len(configs) == 0 {
		configs = []string{fakeS3StoreJSON("")}
	}
	fake.replies("GET /config/datastore/store1", http.StatusOK, configs...)
	fake.handle("PUT /admin/datastore/store1/s3-refresh", tasks.starter(func(*http.Request) *fakeTask {
		task := next()
		task.workerType, task.workerID = "s3-refresh", "store1"
		return task
	}))
	return newProtocolHarness(t, fake), fake, tasks
}

func TestDatastoreS3RefreshActionRefreshes(t *testing.T) {
	h, fake, _ := newS3RefreshHarness(t, func() *fakeTask {
		return &fakeTask{running: 1, log: []string{`Created namespace "ns/dept1/.namespace"`, `Fetching object "vm/100/owner"`}}
	})
	got := h.invokeAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "PBS started task UPID:pbs-tasks:")
	requireProgressContaining(t, got, `Fetching object "vm/100/owner"`)
	requireProgressContaining(t, got, `PBS refreshed datastore "store1" from its bucket`)
	if fake.count("PUT /admin/datastore/store1/s3-refresh") != 1 {
		t.Fatalf("routes: %v", fake.routes())
	}
}

// PBS would refresh a datastore that is not on S3, fail, and leave it in
// maintenance mode s3-refresh: the action does not ask.
func TestDatastoreS3RefreshActionRefusesOtherBackends(t *testing.T) {
	for name, config := range map[string]string{
		"directory": `{"data":{"name":"store1","path":"/srv/store1"}}`,
		"removable": `{"data":{"name":"store1","path":"store1","backing-device":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			h, fake, _ := newS3RefreshHarness(t, func() *fakeTask { return &fakeTask{} }, config)
			got := h.invokeAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to refresh PBS datastore store1 from S3")
			requireProtocolErrorContaining(t, got.diagnostics, `Datastore "store1" is not on S3: its backend is filesystem`)
			if fake.count("PUT /admin/datastore/store1/s3-refresh") != 0 {
				t.Fatalf("the refresh was started: %v", fake.routes())
			}
		})
	}
}

func TestDatastoreS3RefreshActionReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"missing", "no such datastore 'store1'", `PBS has no datastore "store1"`, http.StatusBadRequest},
		{"forbidden", "permission check failed", "Datastore.Audit on /datastore/store1", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/datastore/store1", tc.status, tc.body)
			h := newProtocolHarness(t, fake)
			got := h.invokeAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to refresh PBS datastore store1 from S3")
			requireProtocolErrorContaining(t, got.diagnostics, tc.want)
			if fake.count("PUT /admin/datastore/store1/s3-refresh") != 0 {
				t.Fatalf("the refresh was started: %v", fake.routes())
			}
		})
	}
}

func TestDatastoreS3RefreshActionStartErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"forbidden", "permission check failed", "Datastore.Modify on /datastore/store1", http.StatusForbidden},
		{"deleted", "datastore is being deleted", "datastore is being deleted", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/datastore/store1", http.StatusOK, fakeS3StoreJSON(""))
			fake.reply("PUT /admin/datastore/store1/s3-refresh", tc.status, tc.body)
			h := newProtocolHarness(t, fake)
			got := h.invokeAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to refresh PBS datastore store1 from S3")
			requireProtocolErrorContaining(t, got.diagnostics, tc.want)
		})
	}
}

// A refresh that fails leaves the datastore in maintenance mode s3-refresh,
// which the action says how to clear.
func TestDatastoreS3RefreshActionTaskFails(t *testing.T) {
	h, _, _ := newS3RefreshHarness(t, func() *fakeTask {
		return &fakeTask{log: []string{`Fetching object "vm/100/owner"`}, exit: "failed to list object: unexpected status code 403 Forbidden"}
	}, fakeS3StoreJSON(""), fakeS3StoreJSON("type=s3-refresh"))
	got := h.invokeAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, `Refreshing PBS datastore "store1" from S3 failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "TASK ERROR: failed to list object")
	requireProtocolWarningContaining(t, got.diagnostics, "left in maintenance mode s3-refresh")
	requireProtocolWarningContaining(t, got.diagnostics, "invoke the action again")
	requireProtocolWarningContaining(t, got.diagnostics, "--delete maintenance-mode")
}

// From PBS 4.0.20 a refresh waits for the datastore's operations as an
// unmount does, and ends as if stopped when it cannot take the lock of
// datastore.cfg to check its maintenance mode, such as while a datastore's
// creation holds it: the action explains that, and the mode left behind.
func TestDatastoreS3RefreshActionWaitFailsOnTheDatastoreConfigLock(t *testing.T) {
	h, _, _ := newS3RefreshHarness(t, func() *fakeTask {
		return &fakeTask{exit: "aborted, due to user request", log: []string{
			"waiting for active operations to finsish before continuing: read 1, write 0", maintenanceLockLogLine,
		}}
	}, fakeS3StoreJSON(""), fakeS3StoreJSON("type=s3-refresh"))
	got := h.invokeAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, `Refreshing PBS datastore "store1" from S3 failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "could not check that mode while the task waited for the datastore's operations")
	requireProtocolErrorContaining(t, got.diagnostics, datastoreConfigLockHolders)
	requireProtocolWarningContaining(t, got.diagnostics, "left in maintenance mode s3-refresh")
}

// A refresh that is still running goes on in PBS, which clears the mode
// when it is done: the action neither stops it nor warns about the mode.
func TestDatastoreS3RefreshActionTimeout(t *testing.T) {
	h, _, tasks := newS3RefreshHarness(t, func() *fakeTask {
		return &fakeTask{running: -1}
	}, fakeS3StoreJSON(""), fakeS3StoreJSON("type=s3-refresh"))
	got := h.invokeAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "did not finish")
	requireProtocolErrorContaining(t, got.diagnostics, "The task goes on in PBS")
	for _, d := range got.diagnostics {
		if strings.Contains(d.Summary, "maintenance mode") {
			t.Fatalf("unexpected diagnostic %q: %s", d.Summary, d.Detail)
		}
	}
	if tasks.all()[0].aborted {
		t.Fatal("the refresh was asked to stop")
	}
}

func TestDatastoreS3RefreshActionWithoutWaiting(t *testing.T) {
	h, fake, _ := newS3RefreshHarness(t, func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1", "wait": false})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "not waiting for it")
	for _, route := range fake.routes() {
		if strings.Contains(route, "/tasks/") {
			t.Fatalf("followed the task: %v", fake.routes())
		}
	}
}

func TestDatastoreS3RefreshActionValidation(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake)
	configured := len(fake.routes())
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"store": "x"}, "store"},
		{map[string]any{"store": "store1", "timeout": "soon"}, "positive duration"},
	} {
		requireProtocolErrorContaining(t, h.validateAction(t, "pbs_datastore_s3_refresh", h.actionValue(t, "pbs_datastore_s3_refresh", tc.attrs)), tc.want)
	}
	unknown := h.actionValue(t, "pbs_datastore_s3_refresh", map[string]any{"store": tfUnknown, "wait": tfUnknown, "timeout": tfUnknown})
	requireNoProtocolErrors(t, h.validateAction(t, "pbs_datastore_s3_refresh", unknown))
	requireNoProtocolErrors(t, h.planAction(t, "pbs_datastore_s3_refresh", unknown))
	if routes := fake.routes(); len(routes) != configured {
		t.Fatalf("validating and planning called PBS: %v", routes[configured:])
	}
}

// streamedAction is an action invoked in the background, whose events are
// read as Terraform reads them: its progress messages also go to progress
// as they come, and done receives the whole invocation once it completed.
type streamedAction struct {
	progress chan string
	done     chan actionInvocation
}

// startAction invokes an action without waiting for it.
func (h *protocolHarness) startAction(t *testing.T, typeName string, attrs map[string]any) *streamedAction {
	t.Helper()
	stream, err := h.actionServer(t).InvokeAction(context.Background(), &tfprotov6.InvokeActionRequest{
		ActionType:         typeName,
		Config:             dynamicValue(t, h.actionValue(t, typeName, attrs)),
		ClientCapabilities: &tfprotov6.InvokeActionClientCapabilities{},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &streamedAction{progress: make(chan string, 1000), done: make(chan actionInvocation, 1)}
	go func() {
		var got actionInvocation
		for event := range stream.Events {
			switch e := event.Type.(type) {
			case tfprotov6.ProgressInvokeActionEventType:
				got.progress = append(got.progress, e.Message)
				a.progress <- e.Message
			case tfprotov6.CompletedInvokeActionEventType:
				got.diagnostics = append(got.diagnostics, e.Diagnostics...)
				got.completed = true
			}
		}
		a.done <- got
	}()
	return a
}

// awaitProgress waits for a progress message that contains want.
func (a *streamedAction) awaitProgress(t *testing.T, want string) {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case message := <-a.progress:
			if strings.Contains(message, want) {
				return
			}
		case <-timeout:
			t.Fatalf("no progress message contains %q", want)
		}
	}
}

// await waits for the action to complete.
func (a *streamedAction) await(t *testing.T) actionInvocation {
	t.Helper()
	select {
	case got := <-a.done:
		if !got.completed {
			t.Fatalf("the action did not complete; progress: %q", got.progress)
		}
		return got
	case <-time.After(30 * time.Second):
		t.Fatal("the action did not complete within 30 s")
		return actionInvocation{}
	}
}

// From PBS 4.0.20 the task of a refresh started while another one reads its
// bucket fails on PBS's lock of datastore.cfg: the provider's refreshes run
// one at a time, and one that has to wait says so.
func TestDatastoreS3RefreshActionsRunOneAtATime(t *testing.T) {
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	var mu sync.Mutex
	started := map[string]*fakeTask{}
	var overlaps []string
	for _, store := range []string{"store1", "store2"} {
		fake.reply("GET /config/datastore/"+store, http.StatusOK, fmt.Sprintf(
			`{"data":{"name":%q,"path":"/var/cache/pbs/%s","backend":"type=s3,client=ep1,bucket=backups"}}`, store, store))
		fake.handle("PUT /admin/datastore/"+store+"/s3-refresh", tasks.starter(func(*http.Request) *fakeTask {
			tasks.mu.Lock()
			for _, other := range tasks.tasks {
				if other.workerType == "s3-refresh" && !other.stopped {
					overlaps = append(overlaps, fmt.Sprintf("%s started while %s ran", store, other.workerID))
				}
			}
			tasks.mu.Unlock()
			// The first refresh runs until the test lets it end.
			task := &fakeTask{workerType: "s3-refresh", workerID: store, running: 1}
			if store == "store1" {
				task.running = -1
			}
			mu.Lock()
			started[store] = task
			mu.Unlock()
			return task
		}))
	}
	h := newProtocolHarness(t, fake)

	first := h.startAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
	first.awaitProgress(t, "PBS started task")
	second := h.startAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store2"})
	second.awaitProgress(t, `Waiting for another S3 refresh of this provider to end before refreshing "store2"`)
	if n := fake.count("PUT /admin/datastore/store2/s3-refresh"); n != 0 {
		t.Fatalf("the second refresh started while the first ran: %v", fake.routes())
	}

	mu.Lock()
	running := started["store1"]
	mu.Unlock()
	tasks.mu.Lock()
	running.running = 0
	tasks.mu.Unlock()
	for _, action := range []*streamedAction{first, second} {
		requireNoProtocolErrors(t, action.await(t).diagnostics)
	}
	if fake.count("PUT /admin/datastore/store2/s3-refresh") != 1 || len(overlaps) > 0 {
		t.Fatalf("overlaps %q; routes: %v", overlaps, fake.routes())
	}
}

// startCreate applies the creation of a resource without waiting for it; the
// response arrives on the channel it returns.
func (h *protocolHarness) startCreate(t *testing.T, typeName string, config tftypes.Value,
	planned *tfprotov6.PlanResourceChangeResponse) <-chan *tfprotov6.ApplyResourceChangeResponse {
	t.Helper()
	req := &tfprotov6.ApplyResourceChangeRequest{
		TypeName:        typeName,
		PriorState:      dynamicValue(t, tftypes.NewValue(h.resourceType(t, typeName), nil)),
		PlannedState:    planned.PlannedState,
		Config:          dynamicValue(t, config),
		PlannedPrivate:  planned.PlannedPrivate,
		PlannedIdentity: planned.PlannedIdentity,
	}
	done := make(chan *tfprotov6.ApplyResourceChangeResponse, 1)
	go func() {
		resp, err := h.server.ApplyResourceChange(context.Background(), req)
		if err != nil {
			resp = &tfprotov6.ApplyResourceChangeResponse{Diagnostics: []*tfprotov6.Diagnostic{{
				Severity: tfprotov6.DiagnosticSeverityError, Summary: err.Error(),
			}}}
		}
		done <- resp
	}()
	return done
}

// awaitApply waits for an apply startCreate started.
func awaitApply(t *testing.T, done <-chan *tfprotov6.ApplyResourceChangeResponse) *tfprotov6.ApplyResourceChangeResponse {
	t.Helper()
	select {
	case resp := <-done:
		return resp
	case <-time.After(30 * time.Second):
		t.Fatal("the apply did not complete within 30 s")
		return nil
	}
}

// newS3ReuseHarness serves datastore store1 on S3 and the tests' bucket, for
// a datastore created on it with reuse_datastore, and the refresh of store1,
// which starts the task next returns. overlap records it when that refresh
// starts while a create-datastore task runs, or a create while a refresh
// runs.
func newS3ReuseHarness(t *testing.T, next func() *fakeTask) (h *protocolHarness, fake *fakePBS, datastores *fakeDatastores,
	tasks *fakeTasks, overlaps func() []string) {
	t.Helper()
	fake = newFakePBS()
	datastores = newFakeDatastores(fake)
	datastores.addS3Bucket(s3StoreEndpoint, s3StoreBucket)
	datastores.addDatastore("store1", fakeProperties{
		"path": "/var/cache/pbs/store1", "backend": "type=s3,client=" + s3StoreEndpoint + ",bucket=" + s3StoreBucket,
	})
	tasks = newFakeTasks(fake)
	var mu sync.Mutex
	var found []string
	running := func(workerType string) bool {
		tasks.mu.Lock()
		defer tasks.mu.Unlock()
		for _, task := range tasks.tasks {
			if task.workerType == workerType && !task.stopped {
				return true
			}
		}
		return false
	}
	note := func(overlap string) {
		mu.Lock()
		defer mu.Unlock()
		found = append(found, overlap)
	}
	fake.handle("PUT /admin/datastore/store1/s3-refresh", tasks.starter(func(*http.Request) *fakeTask {
		if running("create-datastore") {
			note("the refresh started while a create-datastore task ran")
		}
		task := next()
		task.workerType, task.workerID = "s3-refresh", "store1"
		return task
	}))
	fake.handle("POST /config/datastore", func(w http.ResponseWriter, req *http.Request) {
		if running("s3-refresh") {
			note("the create started while an s3-refresh task ran")
		}
		datastores.createDatastore(w, req)
	})
	return newProtocolHarness(t, fake), fake, datastores, tasks, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(found)
	}
}

// From PBS 4.0.20, the task that creates a datastore on S3 with
// reuse_datastore refreshes it from the bucket, and fails on PBS's lock of
// datastore.cfg while another refresh reads its bucket, as a refresh started
// while it reads does: such a create waits for the provider's refreshes, and
// they for it.
func TestDatastoreS3ReuseCreateAndRefreshRunOneAtATime(t *testing.T) {
	reuse := s3StoreAttributes(map[string]any{"reuse_datastore": true})

	t.Run("create waits for refresh", func(t *testing.T) {
		var refresh *fakeTask
		h, fake, datastores, tasks, overlaps := newS3ReuseHarness(t, func() *fakeTask {
			// The refresh runs until the test lets it end.
			refresh = &fakeTask{running: -1}
			return refresh
		})
		datastores.addS3Backups(s3StoreBucket, "s3store")
		action := h.startAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
		action.awaitProgress(t, "PBS started task")

		config := h.resourceValue(t, "pbs_datastore", reuse)
		planned := h.plan(t, "pbs_datastore", nil, config)
		requireNoProtocolErrors(t, planned.Diagnostics)
		created := h.startCreate(t, "pbs_datastore", config, planned)
		time.Sleep(500 * time.Millisecond)
		if n := fake.count("POST /config/datastore"); n != 0 {
			t.Fatalf("the datastore was created while the refresh ran: %v", fake.routes())
		}

		tasks.mu.Lock()
		refresh.running = 0
		tasks.mu.Unlock()
		requireNoProtocolErrors(t, action.await(t).diagnostics)
		applied := awaitApply(t, created)
		requireNoProtocolErrors(t, applied.Diagnostics)
		if state := h.decodeResource(t, "pbs_datastore", applied.NewState); state.IsNull() || stringAt(t, state, "id") != "s3store" {
			t.Fatalf("state = %s", state)
		}
		if n := fake.count("POST /config/datastore"); n != 1 || len(overlaps()) > 0 {
			t.Fatalf("overlaps %q; routes: %v", overlaps(), fake.routes())
		}
	})

	t.Run("refresh waits for create", func(t *testing.T) {
		h, fake, datastores, tasks, overlaps := newS3ReuseHarness(t, func() *fakeTask { return &fakeTask{running: 1} })
		// The create task runs until the test lets it end, and then saves
		// the datastore, refreshed.
		create := &fakeTask{workerType: "create-datastore", workerID: "s3store", running: -1, onStop: func() {
			datastores.addDatastore("s3store", fakeProperties{
				"path": "/mnt/datastore/s3-cache", "backend": "type=s3,client=" + s3StoreEndpoint + ",bucket=" + s3StoreBucket,
			})
		}}
		fake.handle("POST /config/datastore", tasks.starter(func(*http.Request) *fakeTask { return create }))

		config := h.resourceValue(t, "pbs_datastore", reuse)
		planned := h.plan(t, "pbs_datastore", nil, config)
		requireNoProtocolErrors(t, planned.Diagnostics)
		created := h.startCreate(t, "pbs_datastore", config, planned)
		for deadline := time.Now().Add(10 * time.Second); fake.count("POST /config/datastore") == 0; {
			if time.Now().After(deadline) {
				t.Fatal("the create did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}

		action := h.startAction(t, "pbs_datastore_s3_refresh", map[string]any{"store": "store1"})
		action.awaitProgress(t, `Waiting for another S3 refresh of this provider to end before refreshing "store1"`)
		if n := fake.count("PUT /admin/datastore/store1/s3-refresh"); n != 0 {
			t.Fatalf("the refresh started while the datastore was created: %v", fake.routes())
		}

		tasks.mu.Lock()
		create.running = 0
		tasks.mu.Unlock()
		requireNoProtocolErrors(t, awaitApply(t, created).Diagnostics)
		requireNoProtocolErrors(t, action.await(t).diagnostics)
		if n := fake.count("PUT /admin/datastore/store1/s3-refresh"); n != 1 || len(overlaps()) > 0 {
			t.Fatalf("overlaps %q; routes: %v", overlaps(), fake.routes())
		}
	})
}
