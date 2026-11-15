package provider

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const pruneActionRoute = "POST /admin/datastore/store1/prune-datastore"

// newPruneHarness serves prunes of datastore store1 whose task is what next
// returns, with the worker type and ID PBS gives it.
func newPruneHarness(t *testing.T, next func() *fakeTask) (*protocolHarness, *fakePBS, *fakeTasks) {
	t.Helper()
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	fake.handle(pruneActionRoute, tasks.starter(func(req *http.Request) *fakeTask {
		_ = req.ParseForm()
		task := next()
		task.workerType, task.workerID = "prune", `store1\x3a`+strings.ReplaceAll(req.PostForm.Get("ns"), "/", `\x2f`)
		// PBS ignores a request to stop a prune.
		task.ignoresAbort = true
		return task
	}))
	return newProtocolHarness(t, fake), fake, tasks
}

// The action sends the kinds of keep that are set and nothing else, and
// dry-run only for a dry run.
func TestDatastorePruneActionParameters(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]any
		want  url.Values
	}{
		{"keep", map[string]any{"keep": map[string]any{"last": 2, "daily": 7}}, url.Values{"keep-last": {"2"}, "keep-daily": {"7"}}},
		{
			"namespace", map[string]any{"ns": "dept1/hosts", "max_depth": 0, "keep": map[string]any{"weekly": 4, "monthly": 6, "yearly": 1, "hourly": 24}},
			url.Values{
				"ns": {"dept1/hosts"}, "max-depth": {"0"}, "keep-hourly": {"24"}, "keep-weekly": {"4"},
				"keep-monthly": {"6"}, "keep-yearly": {"1"},
			},
		},
		{"dry run", map[string]any{"keep": map[string]any{"last": 1}, "dry_run": true}, url.Values{"keep-last": {"1"}, "dry-run": {"true"}}},
		{"no dry run", map[string]any{"keep": map[string]any{"last": 1}, "dry_run": false}, url.Values{"keep-last": {"1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, fake, _ := newPruneHarness(t, func() *fakeTask { return &fakeTask{} })
			tc.attrs["store"] = "store1"
			got := h.invokeAction(t, "pbs_datastore_prune", tc.attrs)
			requireNoProtocolErrors(t, got.diagnostics)
			if form := fake.lastCall(t, pruneActionRoute).form; !reflect.DeepEqual(form, tc.want) {
				t.Fatalf("form = %v, want %v", form, tc.want)
			}
			if fake.count(pruneActionRoute) != 1 {
				t.Fatalf("routes: %v", fake.routes())
			}
		})
	}
}

// The summary counts the lines of the log as PBS 4.2 writes them; a backup
// PBS fails to remove is a warning of the task, which the action passes on.
func TestDatastorePruneActionReportsSummary(t *testing.T) {
	h, _, _ := newPruneHarness(t, func() *fakeTask {
		return &fakeTask{running: 1, exit: "WARNINGS: 1", log: []string{
			"Starting datastore prune on datastore 'store1', root namespace, down to full depth",
			"retention options: --keep-last 2",
			`Pruning group :"vm/100"`,
			"remove vm/100/2026-11-01T10:00:00Z",
			"keep vm/100/2026-11-02T10:00:00Z",
			"keep vm/100/2026-11-03T10:00:00Z",
			`Pruning group dept1:"ct/200"`,
			"remove ct/200/2026-11-01T10:00:00Z",
			`failed to remove dir "ns/dept1/ct/200/2026-11-01T10:00:00Z": Device or resource busy`,
			"keep protected ct/200/2026-11-02T10:00:00Z",
		}}
	})
	got := h.invokeAction(t, "pbs_datastore_prune", map[string]any{"store": "store1", "keep": map[string]any{"last": 2}})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, `Prune of PBS datastore "store1" ended with warnings`)
	requireProtocolWarningContaining(t, got.diagnostics, "Device or resource busy")
	requireProgressContaining(t, got, "pruned 2 backup groups: kept 4 backups, removed 1, failed to remove 1")
}

// A dry run reports what PBS would do, and says nothing changed.
func TestDatastorePruneActionDryRun(t *testing.T) {
	h, _, _ := newPruneHarness(t, func() *fakeTask {
		return &fakeTask{log: []string{
			"Starting datastore prune on datastore 'store1', namespace 'dept1', down to full depth",
			"(dry test run)",
			"retention options: --ns dept1 --keep-last 1",
			`Pruning group dept1:"vm/100"`,
			"would remove vm/100/2026-11-01T10:00:00Z",
			"would keep protected vm/100/2026-11-02T10:00:00Z",
			"would keep vm/100/2026-11-03T10:00:00Z",
		}}
	})
	got := h.invokeAction(t, "pbs_datastore_prune", map[string]any{
		"store": "store1", "ns": "dept1", "keep": map[string]any{"last": 1}, "dry_run": true,
	})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "dry run: PBS would prune 1 backup group: keep 2 backups, remove 1; nothing changed")
}

// A namespace that does not exist fails the task, and the action with the
// end of its log.
func TestDatastorePruneActionTaskFails(t *testing.T) {
	h, _, _ := newPruneHarness(t, func() *fakeTask {
		return &fakeTask{
			log:  []string{"Starting datastore prune on datastore 'store1', namespace 'gone', down to full depth"},
			exit: "ENOENT: No such file or directory",
		}
	})
	got := h.invokeAction(t, "pbs_datastore_prune", map[string]any{
		"store": "store1", "ns": "gone", "keep": map[string]any{"last": 1}, "dry_run": true,
	})
	requireProtocolErrorContaining(t, got.diagnostics, `Dry run of the prune of namespace "gone" of PBS datastore "store1" failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "TASK ERROR: ENOENT: No such file or directory")
	for _, message := range got.progress {
		if strings.Contains(message, "prune 0 backup groups") || strings.Contains(message, "found no backup groups") {
			t.Fatalf("a failed prune reported a summary: %q", got.progress)
		}
	}
}

func TestDatastorePruneActionStartErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ns     string
		status int
		body   string
		want   []string
	}{
		{
			"privileges", "dept1", 400, "missing permissions 'Datastore.Modify|Datastore.Prune' on '/datastore/store1/dept1'",
			[]string{
				`Unable to start the prune of namespace "dept1" of PBS datastore "store1"`,
				`"tfacc@pbs!acc" lacks a privilege this needs: Datastore.Modify on /datastore/store1/dept1, or Datastore.Prune there`,
				"An API token has no privileges of its own",
			},
		},
		{"missing", "", 400, "no such datastore 'store1'", []string{`Unable to start the prune of PBS datastore "store1"`, `PBS has no datastore "store1"`}},
		{"read-only", "", 400, "datastore 'store1' is unavailable: read-only maintenance mode: ", []string{"`read-only` anything that writes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(pruneActionRoute, tc.status, tc.body)
			h := newProtocolHarness(t, fake)
			attrs := map[string]any{"store": "store1", "keep": map[string]any{"last": 1}}
			if tc.ns != "" {
				attrs["ns"] = tc.ns
			}
			got := h.invokeAction(t, "pbs_datastore_prune", attrs)
			for _, want := range tc.want {
				requireProtocolErrorContaining(t, got.diagnostics, want)
			}
			requireProtocolErrorContaining(t, got.diagnostics, strings.TrimSpace(tc.body))
		})
	}
}

// When the action stops waiting, the prune goes on: PBS would not stop it.
func TestDatastorePruneActionTimeout(t *testing.T) {
	h, _, tasks := newPruneHarness(t, func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_datastore_prune", map[string]any{"store": "store1", "keep": map[string]any{"last": 1}, "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, `Prune of PBS datastore "store1" did not finish`)
	requireProtocolErrorContaining(t, got.diagnostics, "The task goes on in PBS")
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the prune was asked to stop")
		}
	}
}

func TestDatastorePruneActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"store": "store1"}, "keep"},
		{map[string]any{"store": "store1", "keep": map[string]any{}}, "must set at least one attribute"},
		{map[string]any{"store": "store1", "keep": map[string]any{"last": 0}}, "keep.last"},
		{map[string]any{"store": "store1", "keep": map[string]any{"last": 1}, "max_depth": 8}, "max_depth"},
		{map[string]any{"store": "store1", "keep": map[string]any{"last": 1}, "ns": "dept1/"}, "must be a namespace"},
		{map[string]any{"store": "-x", "keep": map[string]any{"last": 1}}, "store"},
	} {
		diags := h.validateAction(t, "pbs_datastore_prune", h.actionValue(t, "pbs_datastore_prune", tc.attrs))
		requireProtocolErrorContaining(t, diags, tc.want)
	}
	// Values only known at apply, such as the keep of a prune job created
	// in the same run, are fine while planning.
	for _, keep := range []any{tfUnknown, map[string]any{"last": tfUnknown}} {
		config := h.actionValue(t, "pbs_datastore_prune", map[string]any{
			"store": tfUnknown, "ns": tfUnknown, "max_depth": tfUnknown, "keep": keep, "dry_run": tfUnknown,
		})
		requireNoProtocolErrors(t, h.validateAction(t, "pbs_datastore_prune", config))
		requireNoProtocolErrors(t, h.planAction(t, "pbs_datastore_prune", config))
	}
}
