package provider

import (
	"strings"
	"testing"
)

func TestPruneJobResourceLifecycle(t *testing.T) {
	h, fake, datastores := newDatastoreHarness(t)

	config := h.resourceValue(t, "pbs_prune_job", map[string]any{
		"id":       "daily-store1",
		"store":    "store1",
		"schedule": "daily",
		"keep":     map[string]any{"daily": 7, "weekly": 4},
	})
	inst := h.create(t, "pbs_prune_job", config)

	created := fake.lastCall(t, "POST /config/prune")
	if created.form.Get("keep-daily") != "7" || created.form.Get("keep-weekly") != "4" || created.form.Get("schedule") != "daily" {
		t.Errorf("POST form = %v", created.form)
	}
	for _, name := range []string{"disable", "keep-last", "ns", "max-depth"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s: %v", name, created.form)
		}
	}
	if boolAt(t, inst.state, "disable") || !isNullAt(t, inst.state, "keep", "last") || int64At(t, inst.state, "keep", "daily") != 7 ||
		!isNullAt(t, inst.state, "max_depth") || !isNullAt(t, inst.state, "ns") {
		t.Errorf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_prune_job", inst.identity), "id"); got != "daily-store1" {
		t.Errorf("identity id = %q", got)
	}
	replan := h.plan(t, "pbs_prune_job", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_prune_job", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// Another kind of keep replaces one, and the job moves to a namespace.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_prune_job", map[string]any{
		"id":        "daily-store1",
		"store":     "store1",
		"schedule":  "hourly",
		"ns":        "dept1",
		"max_depth": 2,
		"keep":      map[string]any{"last": 3, "daily": 7},
		"disable":   true,
		"comment":   "Retention",
	}))
	updated := fake.lastCall(t, "PUT /config/prune/daily-store1")
	if got := strings.Join(updated.form["delete"], ","); got != "keep-weekly" {
		t.Errorf("delete = %q, want keep-weekly", got)
	}
	for name, want := range map[string]string{"schedule": "hourly", "ns": "dept1", "max-depth": "2", "keep-last": "3", "disable": "true", "comment": "Retention"} {
		if got := updated.form.Get(name); got != want {
			t.Errorf("PUT %s = %q, want %q", name, got, want)
		}
	}
	if _, sent := updated.form["keep-daily"]; sent {
		t.Error("PUT sent the unchanged keep-daily")
	}

	// Enabling the job again and leaving the namespace delete them.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_prune_job", map[string]any{
		"id":       "daily-store1",
		"store":    "store1",
		"schedule": "hourly",
		"keep":     map[string]any{"last": 3, "daily": 7},
	}))
	updated = fake.lastCall(t, "PUT /config/prune/daily-store1")
	if got := strings.Join(updated.form["delete"], ","); got != "comment,disable,max-depth,ns" {
		t.Errorf("delete = %q", got)
	}
	if job, _ := datastores.pruneJob("daily-store1"); len(job) != 5 {
		t.Errorf("stored job = %v, want id, store, schedule and two keeps", job)
	}

	// A job deleted with its datastore is gone from state, so that the next
	// plan creates it again.
	datastores.mu.Lock()
	delete(datastores.pruneJobs, "daily-store1")
	datastores.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted job: %s", refreshed.state)
	}
	h.destroy(t, inst)
}

func TestPruneJobResourceImportAndValidation(t *testing.T) {
	h, _, datastores := newDatastoreHarness(t)
	datastores.addPruneJob("weekly", fakeProperties{"store": "store1", "schedule": "sun 02:00", "keep-weekly": int64(8), "max-depth": int64(0), "disable": true})

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_prune_job", "weekly"),
		"identity": h.importByIdentity(t, "pbs_prune_job", map[string]any{"id": "weekly"}),
	} {
		if int64At(t, inst.state, "keep", "weekly") != 8 || int64At(t, inst.state, "max_depth") != 0 || !boolAt(t, inst.state, "disable") ||
			stringAt(t, inst.state, "store") != "store1" {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	config := h.resourceValue(t, "pbs_prune_job", map[string]any{"id": "weekly", "store": "store1", "schedule": "daily", "keep": map[string]any{"last": 1}})
	planned := h.plan(t, "pbs_prune_job", nil, config)
	applied := h.apply(t, "pbs_prune_job", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")

	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"empty keep":   {map[string]any{"id": "job1", "store": "store1", "schedule": "daily", "keep": map[string]any{}}, "must set at least one attribute"},
		"zero keep":    {map[string]any{"id": "job1", "store": "store1", "schedule": "daily", "keep": map[string]any{"daily": 0}}, "keep.daily"},
		"no keep":      {map[string]any{"id": "job1", "store": "store1", "schedule": "daily"}, "keep"},
		"bad ns":       {map[string]any{"id": "job1", "store": "store1", "schedule": "daily", "keep": map[string]any{"last": 1}, "ns": "/root"}, "namespace"},
		"deep ns":      {map[string]any{"id": "job1", "store": "store1", "schedule": "daily", "keep": map[string]any{"last": 1}, "ns": "a/b/c/d/e/f/g/h"}, "up to seven names"},
		"deep max":     {map[string]any{"id": "job1", "store": "store1", "schedule": "daily", "keep": map[string]any{"last": 1}, "max_depth": 8}, "max_depth"},
		"bad job id":   {map[string]any{"id": "-job", "store": "store1", "schedule": "daily", "keep": map[string]any{"last": 1}}, "id"},
		"bad store id": {map[string]any{"id": "job1", "store": "s", "schedule": "daily", "keep": map[string]any{"last": 1}}, "store"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_prune_job", h.resourceValue(t, "pbs_prune_job", tc.attrs)), tc.want)
		})
	}
}

func TestVerifyJobResourceLifecycle(t *testing.T) {
	h, fake, datastores := newDatastoreHarness(t)

	// PBS reads a job created with its ID and datastore alone as just that.
	inst := h.create(t, "pbs_verify_job", h.resourceValue(t, "pbs_verify_job", map[string]any{"id": "verify-store1", "store": "store1"}))
	if created := fake.lastCall(t, "POST /config/verify"); len(created.form) != 2 {
		t.Errorf("POST form = %v, want id and store only", created.form)
	}
	if job, _ := datastores.verifyJob("verify-store1"); len(job) != 2 {
		t.Errorf("stored job = %v", job)
	}
	if int64At(t, inst.state, "max_depth") != 7 || !boolAt(t, inst.state, "ignore_verified") || !isNullAt(t, inst.state, "read_threads") ||
		!isNullAt(t, inst.state, "schedule") {
		t.Errorf("state = %s, want PBS's defaults", inst.state)
	}

	inst = h.update(t, inst, h.resourceValue(t, "pbs_verify_job", map[string]any{
		"id":              "verify-store1",
		"store":           "store1",
		"ns":              "dept1",
		"max_depth":       3,
		"schedule":        "sat 03:00",
		"ignore_verified": false,
		"outdated_after":  30,
		"read_threads":    2,
		"verify_threads":  8,
	}))
	updated := fake.lastCall(t, "PUT /config/verify/verify-store1")
	for name, want := range map[string]string{"ns": "dept1", "max-depth": "3", "schedule": "sat 03:00", "ignore-verified": "false",
		"outdated-after": "30", "read-threads": "2", "verify-threads": "8"} {
		if got := updated.form.Get(name); got != want {
			t.Errorf("PUT %s = %q, want %q", name, got, want)
		}
	}

	// Back to the defaults: the properties are deleted, not written. A verify
	// job keeps its namespace when an update sends the root, so ns must be
	// deleted too.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_verify_job", map[string]any{"id": "verify-store1", "store": "store1"}))
	updated = fake.lastCall(t, "PUT /config/verify/verify-store1")
	if got := strings.Join(updated.form["delete"], ","); got != "ignore-verified,max-depth,ns,outdated-after,read-threads,schedule,verify-threads" {
		t.Errorf("delete = %q", got)
	}
	if len(updated.form) != 1 {
		t.Errorf("PUT form = %v, want only deletions", updated.form)
	}
	if job, _ := datastores.verifyJob("verify-store1"); len(job) != 2 {
		t.Errorf("stored job = %v, want id and store only", job)
	}
	if int64At(t, inst.state, "max_depth") != 7 || !isNullAt(t, inst.state, "ns") {
		t.Errorf("state = %s", inst.state)
	}

	inst = h.importByIdentity(t, "pbs_verify_job", map[string]any{"id": "verify-store1"})
	h.destroy(t, inst)
	if _, exists := datastores.verifyJob("verify-store1"); exists {
		t.Error("the job still exists")
	}
	// Destroying a job that is gone is no error.
	h.destroy(t, inst)
}

// The thread counts need PBS 4.1.
func TestVerifyJobResourceThreadsNeedPBS41(t *testing.T) {
	h, _, _ := newDatastoreHarness(t, fakeVersion40)
	for _, attribute := range []string{"read_threads", "verify_threads"} {
		config := h.resourceValue(t, "pbs_verify_job", map[string]any{"id": "verify1", "store": "store1", attribute: 2})
		planned := h.plan(t, "pbs_verify_job", nil, config)
		requireProtocolErrorContaining(t, planned.Diagnostics, attribute+" needs PBS 4.1 or newer")
	}
	planned := h.plan(t, "pbs_verify_job", nil, h.resourceValue(t, "pbs_verify_job", map[string]any{"id": "verify1", "store": "store1"}))
	requireNoProtocolErrors(t, planned.Diagnostics)
}
