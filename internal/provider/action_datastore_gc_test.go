package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// newGCHarness serves a garbage collection of datastore store1 whose task
// is what next returns, and GET /admin/gc/store1 with the figures of the
// last garbage collection that succeeded, as PBS keeps them.
func newGCHarness(t *testing.T, next func() *fakeTask, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeTasks) {
	t.Helper()
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	var lastSucceeded string
	fake.handle("POST /admin/datastore/store1/gc", func(w http.ResponseWriter, req *http.Request) {
		task := next()
		task.workerType, task.workerID = "garbage_collection", "store1"
		var upid string
		stop := task.onStop
		task.onStop = func() {
			if task.exit == "OK" || strings.HasPrefix(task.exit, "WARNINGS") {
				lastSucceeded = upid
			}
			if stop != nil {
				stop()
			}
		}
		upid = tasks.start(task)
		writeData(w, upid, "")
	})
	fake.handle("GET /admin/gc/store1", func(w http.ResponseWriter, _ *http.Request) {
		writeData(w, []map[string]any{{
			"store": "store1", "upid": lastSucceeded, "removed-bytes": 3 << 30, "removed-chunks": 1200,
			"pending-bytes": 512 << 20, "pending-chunks": 210,
		}}, "")
	})
	return newProtocolHarness(t, fake, opts...), fake, tasks
}

func TestDatastoreGCActionWaitsAndReports(t *testing.T) {
	h, fake, _ := newGCHarness(t, func() *fakeTask {
		return &fakeTask{running: 1, log: []string{"starting garbage collection on store store1", "marked 100% (2 of 2 index files)"}}
	})

	got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "PBS started task UPID:pbs-tasks:")
	// The latest line of the log is forwarded, the task's result line is
	// not.
	requireProgressContaining(t, got, "marked 100% (2 of 2 index files)")
	for _, message := range got.progress {
		if strings.Contains(message, "TASK OK") {
			t.Fatalf("the result line was forwarded: %q", got.progress)
		}
	}
	requireProgressContaining(t, got, "removed 3 GiB in 1200 chunks; 512 MiB in 210 chunks pending removal")
	if fake.count("POST /admin/datastore/store1/gc") != 1 {
		t.Fatalf("routes: %v", fake.routes())
	}
}

// The figures PBS keeps are those of the last garbage collection that
// succeeded: after one that warned they are the run's, and nothing is
// reported when they belong to another run.
func TestDatastoreGCActionWarnings(t *testing.T) {
	h, _, _ := newGCHarness(t, func() *fakeTask {
		return &fakeTask{log: []string{"marked 100% (2 of 2 index files)", "unable to access chunk 0123, required by \"vm/100\""}, exit: "WARNINGS: 1"}
	})
	got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "ended with warnings")
	requireProtocolWarningContaining(t, got.diagnostics, "unable to access chunk 0123")
	requireProtocolWarningContaining(t, got.diagnostics, "TASK WARNINGS: 1")
	requireProgressContaining(t, got, "removed 3 GiB")
}

func TestDatastoreGCActionTaskFails(t *testing.T) {
	h, _, _ := newGCHarness(t, func() *fakeTask {
		return &fakeTask{log: []string{"starting garbage collection on store store1"}, exit: "atime safety check failed: …"}
	})
	got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, `Garbage collection of PBS datastore "store1" failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "TASK ERROR: atime safety check failed")
	requireProtocolErrorContaining(t, got.diagnostics, "proxmox-backup-manager task log")
	for _, message := range got.progress {
		if strings.HasPrefix(message, "removed ") {
			t.Fatalf("a failed run reported figures: %q", got.progress)
		}
	}
}

// A task that fails on PBS's lock of its datastore configuration, which
// another task held, says which tasks hold it for long and what to do.
func TestDatastoreGCActionTaskFailsOnTheDatastoreConfigLock(t *testing.T) {
	exit := `Unable to acquire lock "/etc/proxmox-backup/.datastore.lck" - Interrupted system call (os error 4)`
	h, _, _ := newGCHarness(t, func() *fakeTask { return &fakeTask{exit: exit} })
	got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, exit)
	requireProtocolErrorContaining(t, got.diagnostics, "(os error 4). The task could not take the lock of PBS's datastore configuration")
	requireProtocolErrorContaining(t, got.diagnostics, "an S3 refresh holds it")
	requireProtocolErrorContaining(t, got.diagnostics, "Administration → Tasks")
}

// With wait = false the action ends once the task has started, without
// polling it.
func TestDatastoreGCActionWithoutWaiting(t *testing.T) {
	h, fake, _ := newGCHarness(t, func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1", "wait": false})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "not waiting for it")
	for _, route := range fake.routes() {
		if strings.Contains(route, "/status") {
			t.Fatalf("polled the task: %v", fake.routes())
		}
	}
}

// A timeout ends the wait, not the task, which a garbage collection is left
// to finish.
func TestDatastoreGCActionTimeout(t *testing.T) {
	h, _, tasks := newGCHarness(t, func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "did not finish")
	requireProtocolErrorContaining(t, got.diagnostics, "The task goes on in PBS")
	requireProtocolErrorContaining(t, got.diagnostics, "Raise the action's `timeout`")
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the task was asked to stop")
		}
	}
}

// When Terraform stops the action, it stops waiting at once and sends no
// progress any more, which invokeActionWith checks as Terraform reads the
// events; the garbage collection goes on.
func TestDatastoreGCActionCancelled(t *testing.T) {
	h, _, tasks := newGCHarness(t, func() *fakeTask { return &fakeTask{running: -1, log: []string{"starting"}} })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	got := h.invokeActionWith(ctx, t, "pbs_datastore_gc", h.actionValue(t, "pbs_datastore_gc", map[string]any{"store": "store1"}))
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the action went on for %s after it was cancelled", elapsed)
	}
	if !got.stopped || !got.completed {
		t.Fatalf("the action did not complete after it was cancelled: %+v", got)
	}
	requireProtocolErrorContaining(t, got.diagnostics, "Terraform stopped the action while PBS task")
	requireProgressContaining(t, got, "starting")
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the garbage collection was asked to stop")
		}
	}
}

func TestDatastoreGCActionStartErrors(t *testing.T) {
	for _, tc := range []struct {
		name, status, body, want string
	}{
		{"missing", "400", "no such datastore 'store1'", `PBS has no datastore "store1"`},
		{"unmounted", "400", "datastore 'store1' is not mounted", "a removable datastore must be mounted"},
		{"maintenance", "400", "datastore 'store1' is unavailable: read-only maintenance mode: ", "maintenance mode may forbid it"},
		{"running", "400", "garbage collection already running", "already running"},
		{"forbidden", "403", "permission check failed", "Datastore.Modify on /datastore/store1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			code := http.StatusBadRequest
			if tc.status == "403" {
				code = http.StatusForbidden
			}
			fake.reply("POST /admin/datastore/store1/gc", code, tc.body)
			h := newProtocolHarness(t, fake)
			got := h.invokeAction(t, "pbs_datastore_gc", map[string]any{"store": "store1"})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to start garbage collection of PBS datastore store1")
			requireProtocolErrorContaining(t, got.diagnostics, tc.want)
		})
	}
}

func TestDatastoreGCActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"store": "x"}, "store"},
		{map[string]any{"store": "store1", "timeout": "0s"}, "positive duration"},
		{map[string]any{"store": "store1", "timeout": "soon"}, "positive duration"},
	} {
		diags := h.validateAction(t, "pbs_datastore_gc", h.actionValue(t, "pbs_datastore_gc", tc.attrs))
		requireProtocolErrorContaining(t, diags, tc.want)
	}
	// Values only known at apply are fine while planning.
	diags := h.validateAction(t, "pbs_datastore_gc", h.actionValue(t, "pbs_datastore_gc", map[string]any{"store": tfUnknown, "timeout": tfUnknown}))
	requireNoProtocolErrors(t, diags)
	requireNoProtocolErrors(t, h.planAction(t, "pbs_datastore_gc", h.actionValue(t, "pbs_datastore_gc", map[string]any{"store": tfUnknown})))
}

// Every action and list resource is served with a valid schema; the
// framework checks them when it serves the provider's schema, which
// newProtocolHarness requires to have no errors.
func TestActionAndListSchemasAreServed(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	if len(h.schemas.ActionSchemas) == 0 || len(h.schemas.ListResourceSchemas) == 0 {
		t.Fatalf("actions: %d, list resources: %d", len(h.schemas.ActionSchemas), len(h.schemas.ListResourceSchemas))
	}
	for name, s := range h.schemas.ActionSchemas {
		if !strings.Contains(s.Schema.Block.Description, "Terraform 1.14.1") {
			t.Errorf("action %s does not say what it needs", name)
		}
	}
	for name, s := range h.schemas.ListResourceSchemas {
		if !strings.Contains(s.Block.Description, "Terraform 1.14 or later") {
			t.Errorf("list resource %s does not say what it needs", name)
		}
		if _, ok := h.identities[name]; !ok {
			t.Errorf("list resource %s lists a resource without identity", name)
		}
	}
	metadata, err := h.server.GetMetadata(context.Background(), &tfprotov6.GetMetadataRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Actions) != len(h.schemas.ActionSchemas) || len(metadata.ListResources) != len(h.schemas.ListResourceSchemas) {
		t.Fatalf("metadata lists %d actions and %d list resources", len(metadata.Actions), len(metadata.ListResources))
	}
}
