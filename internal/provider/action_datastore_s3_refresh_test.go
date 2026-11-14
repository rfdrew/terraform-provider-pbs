package provider

import (
	"net/http"
	"strings"
	"testing"
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
