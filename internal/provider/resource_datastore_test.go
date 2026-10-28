package provider

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestDatastoreAndNotificationResourceSchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, &datastoreResource{})
	requireValidResourceSchema(t, &pruneJobResource{})
	requireValidResourceSchema(t, &verifyJobResource{})
	requireValidResourceSchema(t, &smtpEndpointResource{})
	requireValidResourceSchema(t, &notificationMatcherResource{})
}

// newDatastoreHarness is a fake PBS with the datastore and job API and a
// provider signed in to it. version, when set, is what GET /version answers.
func newDatastoreHarness(t *testing.T, version ...string) (*protocolHarness, *fakePBS, *fakeDatastores) {
	t.Helper()
	fake := newFakePBS()
	if len(version) > 0 {
		fake.reply("GET /version", http.StatusOK, version[0])
	}
	datastores := newFakeDatastores(fake)
	return newProtocolHarness(t, fake), fake, datastores
}

// fakeVersion40 is GET /version of PBS 4.0.22.
const fakeVersion40 = `{"data":{"release":"22","repoid":"0123456789abcdef","version":"4.0"}}`

// countPrefix returns how many requests went to routes starting with prefix.
func countPrefix(fake *fakePBS, prefix string) int {
	n := 0
	for _, route := range fake.routes() {
		if strings.HasPrefix(route, prefix) {
			n++
		}
	}
	return n
}

const taskStatusRoutes = "GET /nodes/" + fakeTaskNode + "/tasks/"

func TestDatastoreResourceLifecycle(t *testing.T) {
	h, fake, datastores := newDatastoreHarness(t)
	datastores.addPruneJob("other", fakeProperties{"store": "store2", "schedule": "daily", "keep-last": int64(1)})

	config := h.resourceValue(t, "pbs_datastore", map[string]any{
		"name":        "store1",
		"path":        "/mnt/datastore/store1",
		"comment":     "Backups",
		"gc_schedule": "daily",
		"tuning":      map[string]any{"sync_level": "file", "gc_atime_safety_check": false},
	})
	inst := h.create(t, "pbs_datastore", config)

	created := fake.lastCall(t, "POST /config/datastore")
	if got := created.form.Get("tuning"); got != "gc-atime-safety-check=false,sync-level=file" {
		t.Errorf("POST tuning = %q", got)
	}
	if created.form.Get("path") != "/mnt/datastore/store1" || created.form.Get("gc-schedule") != "daily" {
		t.Errorf("POST form = %v", created.form)
	}
	for _, name := range []string{"verify-new", "notification-mode", "reuse-datastore", "maintenance-mode", "notify", "keep-last", "prune-schedule"} {
		if _, sent := created.form[name]; sent {
			t.Errorf("POST sent %s: %v", name, created.form)
		}
	}
	if n := countPrefix(fake, taskStatusRoutes); n != 1 {
		t.Errorf("polled the create task %d times, want 1", n)
	}
	if stringAt(t, inst.state, "id") != "store1" || stringAt(t, inst.state, "notification_mode") != "notification-system" ||
		boolAt(t, inst.state, "verify_new") || boolAt(t, inst.state, "destroy_data") || boolAt(t, inst.state, "keep_job_configs") {
		t.Errorf("state = %s, want PBS's defaults for what is left out", inst.state)
	}
	if !isNullAt(t, inst.state, "tuning", "chunk_order") || boolAt(t, inst.state, "tuning", "gc_atime_safety_check") ||
		stringAt(t, inst.state, "tuning", "sync_level") != "file" || !isNullAt(t, inst.state, "maintenance_mode") {
		t.Errorf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_datastore", inst.identity), "name"); got != "store1" {
		t.Errorf("identity name = %q", got)
	}

	// A plan against the unchanged configuration changes nothing.
	replan := h.plan(t, "pbs_datastore", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_datastore", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	// Dropping the comment deletes it; tuning is written as a whole; the
	// legacy mails and a maintenance mode are set.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", map[string]any{
		"name":              "store1",
		"path":              "/mnt/datastore/store1",
		"gc_schedule":       "daily",
		"verify_new":        true,
		"notification_mode": "legacy-sendmail",
		"notify_user":       "admin@pbs",
		"notify":            map[string]any{"gc": "error", "verify": "never"},
		"tuning":            map[string]any{"chunk_order": "none"},
		"maintenance_mode":  map[string]any{"type": "read-only", "message": `moving "disks"`},
	}))
	updated := fake.lastCall(t, "PUT /config/datastore/store1")
	if got := strings.Join(updated.form["delete"], ","); got != "comment" {
		t.Errorf("delete = %q, want comment", got)
	}
	for name, want := range map[string]string{
		"verify-new":        "true",
		"notification-mode": "legacy-sendmail",
		"notify-user":       "admin@pbs",
		"notify":            "gc=error,verify=never",
		"tuning":            "chunk-order=none",
		"maintenance-mode":  `read-only,message="moving \"disks\""`,
	} {
		if got := updated.form.Get(name); got != want {
			t.Errorf("PUT %s = %q, want %q", name, got, want)
		}
	}
	if _, sent := updated.form["gc-schedule"]; sent {
		t.Error("PUT sent the unchanged gc-schedule")
	}
	if got, _ := datastores.datastore("store1"); got["maintenance-mode"] != `read-only,message="moving \"disks\""` {
		t.Errorf("stored maintenance-mode = %q", got["maintenance-mode"])
	}
	if stringAt(t, inst.state, "maintenance_mode", "message") != `moving "disks"` || !isNullAt(t, inst.state, "comment") ||
		stringAt(t, inst.state, "notify", "gc") != "error" || !isNullAt(t, inst.state, "notify", "prune") {
		t.Errorf("state after update = %s", inst.state)
	}

	// A maintenance mode PBS sets itself is not a change.
	datastores.setDatastoreProperty("store1", "maintenance-mode", "unmount")
	refreshed := h.refresh(t, inst)
	if !refreshed.state.Equal(inst.state) {
		diffs, _ := refreshed.state.Diff(inst.state)
		t.Fatalf("refresh during PBS's own maintenance changed %v", diffs)
	}
	datastores.setDatastoreProperty("store1", "maintenance-mode", "read-only,message=moving \"disks\"")

	// Resetting the notification mode and verify-new to their defaults, and
	// dropping the rest, deletes them rather than writing the defaults.
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/datastore/store1", "gc_schedule": "daily",
	}))
	updated = fake.lastCall(t, "PUT /config/datastore/store1")
	if got := strings.Join(updated.form["delete"], ","); got != "maintenance-mode,notification-mode,notify,notify-user,tuning,verify-new" {
		t.Errorf("delete = %q", got)
	}
	if len(updated.form) != 1 {
		t.Errorf("PUT form = %v, want only deletions", updated.form)
	}
	if got, _ := datastores.datastore("store1"); len(got) != 3 {
		t.Errorf("stored datastore = %v, want name, path and gc-schedule only", got)
	}

	// A change of the destroy-time flags alone sends nothing.
	puts := fake.count("PUT /config/datastore/store1")
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/datastore/store1", "gc_schedule": "daily", "destroy_data": true,
	}))
	if fake.count("PUT /config/datastore/store1") != puts || !boolAt(t, inst.state, "destroy_data") {
		t.Error("changing destroy_data called PBS, or was not recorded")
	}

	// Destroying deletes the datastore, its jobs and, with destroy_data, its
	// directory, and waits for the task.
	datastores.addPruneJob("daily", fakeProperties{"store": "store1", "schedule": "daily", "keep-daily": int64(7)})
	h.destroy(t, inst)
	deleted := fake.lastCall(t, "DELETE /config/datastore/store1")
	if deleted.query.Get("destroy-data") != "true" || deleted.query.Has("keep-job-configs") {
		t.Errorf("DELETE query = %v", deleted.query)
	}
	if _, exists := datastores.datastore("store1"); exists {
		t.Error("the datastore still exists")
	}
	if datastores.hasChunkStore("/mnt/datastore/store1") {
		t.Error("destroy_data left the chunk store")
	}
	if _, exists := datastores.pruneJob("daily"); exists {
		t.Error("the datastore's prune job survived without keep_job_configs")
	}
	if _, exists := datastores.pruneJob("other"); !exists {
		t.Error("another datastore's prune job was deleted")
	}
}

// PBS creates a datastore only in an empty directory, unless it reuses the
// chunk store there, and reports the failures only through the task: an
// EEXIST on .chunks for a chunk store without backups, "datastore path not
// empty" for one with them.
func TestDatastoreResourceCreateOnUsedDirectory(t *testing.T) {
	h, _, datastores := newDatastoreHarness(t)
	datastores.addChunkStore("/mnt/old", false)
	datastores.addChunkStore("/mnt/full", true)

	for _, dir := range []string{"/mnt/old", "/mnt/full"} {
		config := h.resourceValue(t, "pbs_datastore", map[string]any{"name": "old", "path": dir})
		planned := h.plan(t, "pbs_datastore", nil, config)
		requireNoProtocolErrors(t, planned.Diagnostics)
		applied := h.apply(t, "pbs_datastore", nil, config, planned)
		requireProtocolErrorContaining(t, applied.Diagnostics, "already holds a chunk store or other files")
		requireProtocolErrorContaining(t, applied.Diagnostics, "reuse_datastore = true")
		if state := h.decodeResource(t, "pbs_datastore", applied.NewState); !state.IsNull() {
			t.Errorf("a failed create left state %s", state)
		}
		if _, exists := datastores.datastore("old"); exists {
			t.Error("the failed task created the datastore")
		}
	}

	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "old", "path": "/mnt/old", "reuse_datastore": true,
	}))
	if !boolAt(t, inst.state, "reuse_datastore") {
		t.Errorf("state = %s", inst.state)
	}

	// reuse_datastore on a directory without a chunk store fails too.
	config := h.resourceValue(t, "pbs_datastore", map[string]any{"name": "new", "path": "/mnt/new", "reuse_datastore": true})
	planned := h.plan(t, "pbs_datastore", nil, config)
	applied := h.apply(t, "pbs_datastore", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "does not hold a chunk store")
}

func TestDatastoreResourceCreateExisting(t *testing.T) {
	h, _, datastores := newDatastoreHarness(t)
	datastores.addDatastore("store1", fakeProperties{"path": "/mnt/datastore/store1"})

	config := h.resourceValue(t, "pbs_datastore", map[string]any{"name": "store1", "path": "/mnt/other"})
	planned := h.plan(t, "pbs_datastore", nil, config)
	applied := h.apply(t, "pbs_datastore", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")
}

// keep_job_configs keeps the jobs, and a failed delete task is reported.
func TestDatastoreResourceDelete(t *testing.T) {
	h, fake, datastores := newDatastoreHarness(t)
	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/datastore/store1", "keep_job_configs": true,
	}))
	datastores.addVerifyJob("verify", fakeProperties{"store": "store1"})

	// A task that fails, and one that ends with warnings without removing
	// the datastore, are both errors; the datastore stays in state.
	null := tftypes.NewValue(h.resourceType(t, "pbs_datastore"), nil)
	for failure, want := range map[string]string{"error": "currently in use", "warnings": "ended with warnings"} {
		datastores.failDelete = failure
		planned := h.plan(t, "pbs_datastore", inst, null)
		applied := h.apply(t, "pbs_datastore", inst, null, planned)
		requireProtocolErrorContaining(t, applied.Diagnostics, want)
		requireProtocolErrorContaining(t, applied.Diagnostics, `"delete" maintenance mode`)
		if got, _ := datastores.datastore("store1"); got["maintenance-mode"] != pbsclient.MaintenanceDelete {
			t.Errorf("maintenance-mode after the failed task = %v", got["maintenance-mode"])
		}
	}

	// The failed deletion left PBS's own maintenance mode, which a refresh
	// does not report, and destroying again succeeds.
	inst = h.refresh(t, inst)
	if !isNullAt(t, inst.state, "maintenance_mode") {
		t.Errorf("state = %s", inst.state)
	}
	h.destroy(t, inst)
	if got := fake.lastCall(t, "DELETE /config/datastore/store1").query; got.Get("keep-job-configs") != "true" || got.Has("destroy-data") {
		t.Errorf("DELETE query = %v", got)
	}
	if _, exists := datastores.verifyJob("verify"); !exists {
		t.Error("keep_job_configs did not keep the verify job")
	}
	if !datastores.hasChunkStore("/mnt/datastore/store1") {
		t.Error("the chunk store went without destroy_data")
	}

	// A datastore deleted outside Terraform is gone from state, and destroying
	// one that is gone is no error.
	inst = h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store2", "path": "/mnt/datastore/store2",
	}))
	datastores.mu.Lock()
	delete(datastores.datastores, "store2")
	datastores.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted datastore: %s", refreshed.state)
	}
	h.destroy(t, inst)
}

// Both import forms read a datastore back in full, with the flags that exist
// only in Terraform at their defaults; datastores of other kinds are refused.
func TestDatastoreResourceImport(t *testing.T) {
	h, _, datastores := newDatastoreHarness(t)
	datastores.addDatastore("store1", fakeProperties{
		"path":              "/mnt/datastore/store1",
		"comment":           "Imported",
		"notification-mode": "legacy-sendmail",
		"maintenance-mode":  "offline",
		"tuning":            "gc-atime-safety-check=0,unknown-option=1",
	})
	datastores.addDatastore("s3", fakeProperties{"path": "/mnt/cache", "backend": "type=s3,client=minio,bucket=pbs"})

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_datastore", "store1"),
		"identity": h.importByIdentity(t, "pbs_datastore", map[string]any{"name": "store1"}),
	} {
		if stringAt(t, inst.state, "comment") != "Imported" || stringAt(t, inst.state, "notification_mode") != "legacy-sendmail" ||
			stringAt(t, inst.state, "maintenance_mode", "type") != "offline" || boolAt(t, inst.state, "tuning", "gc_atime_safety_check") ||
			boolAt(t, inst.state, "reuse_datastore") || boolAt(t, inst.state, "destroy_data") || boolAt(t, inst.state, "keep_job_configs") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	resp := h.importResource(t, "pbs_datastore", "s3", nil)
	requireNoProtocolErrors(t, resp.Diagnostics)
	imported := resp.ImportedResources[0]
	read := h.read(t, &resourceInstance{typeName: "pbs_datastore", state: h.decodeResource(t, "pbs_datastore", imported.State), identity: imported.Identity})
	requireProtocolErrorContaining(t, read.Diagnostics, "is on S3 object storage")

	resp = h.importResource(t, "pbs_datastore", "no/such", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS datastore by its name")
}

func TestDatastoreResourceValidation(t *testing.T) {
	h, _, _ := newDatastoreHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"relative path":       {map[string]any{"name": "store1", "path": "datastore"}, "must be an absolute path"},
		"absolute on device":  {map[string]any{"name": "store1", "path": "/usb", "backing_device": testDeviceUUID}, "relative to the root"},
		"leaving the device":  {map[string]any{"name": "store1", "path": "a/../..", "backing_device": testDeviceUUID}, "relative to the root"},
		"upper-case UUID":     {map[string]any{"name": "store1", "path": "usb", "backing_device": strings.ToUpper(testDeviceUUID)}, "UUID of a file system"},
		"gc without device":   {map[string]any{"name": "store1", "path": "/mnt/s1", "gc_on_unmount": true}, "needs backing_device"},
		"root path":           {map[string]any{"name": "store1", "path": "/"}, "must be an absolute path"},
		"short name":          {map[string]any{"name": "s1", "path": "/mnt/s1"}, "name"},
		"empty tuning":        {map[string]any{"name": "store1", "path": "/mnt/s1", "tuning": map[string]any{}}, "must set at least one attribute"},
		"comma in message":    {map[string]any{"name": "store1", "path": "/mnt/s1", "maintenance_mode": map[string]any{"type": "offline", "message": "a, b"}}, "must not contain commas"},
		"internal type":       {map[string]any{"name": "store1", "path": "/mnt/s1", "maintenance_mode": map[string]any{"type": "unmount"}}, "maintenance_mode.type"},
		"tuning out of range": {map[string]any{"name": "store1", "path": "/mnt/s1", "tuning": map[string]any{"gc_atime_cutoff": 0}}, "gc_atime_cutoff"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", tc.attrs)), tc.want)
		})
	}

	// The mails' settings apply to legacy-sendmail only.
	diags := h.validateResource(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/s1", "notify": map[string]any{"gc": "never"},
	}))
	requireNoProtocolErrors(t, diags)
	requireProtocolWarningContaining(t, diags, "legacy-sendmail")
}

// Options newer than PBS 4.0 fail the plan on an older server, and replacing
// a datastore warns that its jobs go with it.
func TestDatastoreResourcePlanChecks(t *testing.T) {
	h, _, _ := newDatastoreHarness(t, fakeVersion40)
	config := h.resourceValue(t, "pbs_datastore", map[string]any{
		"name": "store1", "path": "/mnt/s1", "tuning": map[string]any{"default_verification_workers": 8},
	})
	planned := h.plan(t, "pbs_datastore", nil, config)
	requireProtocolErrorContaining(t, planned.Diagnostics, "tuning.default_verification_workers needs PBS 4.1 or newer")

	inst := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{"name": "store1", "path": "/mnt/s1"}))
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", map[string]any{"name": "store1", "path": "/mnt/s2"}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	requireProtocolWarningContaining(t, planned.Diagnostics, "deletes its jobs and ACL entries")

	// A new name in the same directory meets the old datastore's chunk
	// store, so it needs reuse_datastore, unless destroy_data removes it.
	renamed := map[string]any{"name": "store2", "path": "/mnt/s1"}
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", renamed))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Set reuse_datastore = true")
	renamed["reuse_datastore"] = true
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", renamed))
	requireNoProtocolErrors(t, planned.Diagnostics)
	inst = h.update(t, inst, h.resourceValue(t, "pbs_datastore", map[string]any{"name": "store1", "path": "/mnt/s1", "destroy_data": true}))
	planned = h.plan(t, "pbs_datastore", inst, h.resourceValue(t, "pbs_datastore", map[string]any{"name": "store2", "path": "/mnt/s1", "destroy_data": true}))
	requireNoProtocolErrors(t, planned.Diagnostics)
}

// Renaming a datastore in the same directory, with reuse_datastore, replaces
// it on its chunk store; PBS deletes the old one's jobs, and the jobs that
// follow the new name are created again in the same apply.
func TestDatastoreResourceRename(t *testing.T) {
	h, fake, datastores := newDatastoreHarness(t)
	store := h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{"name": "store1", "path": "/mnt/s1"}))
	prune := h.create(t, "pbs_prune_job", h.resourceValue(t, "pbs_prune_job", map[string]any{
		"id": "daily", "store": "store1", "schedule": "daily", "keep": map[string]any{"daily": 7},
	}))
	verify := h.create(t, "pbs_verify_job", h.resourceValue(t, "pbs_verify_job", map[string]any{"id": "weekly", "store": "store1", "schedule": "sat 03:00"}))

	// Terraform destroys the old datastore, creates the new one, then
	// updates the jobs.
	h.destroy(t, store)
	h.create(t, "pbs_datastore", h.resourceValue(t, "pbs_datastore", map[string]any{"name": "store2", "path": "/mnt/s1", "reuse_datastore": true}))
	if _, exists := datastores.pruneJob("daily"); exists {
		t.Fatal("PBS kept the old datastore's prune job")
	}
	prune = h.update(t, prune, h.resourceValue(t, "pbs_prune_job", map[string]any{
		"id": "daily", "store": "store2", "schedule": "daily", "keep": map[string]any{"daily": 7},
	}))
	verify = h.update(t, verify, h.resourceValue(t, "pbs_verify_job", map[string]any{"id": "weekly", "store": "store2", "schedule": "sat 03:00"}))
	if job, _ := datastores.pruneJob("daily"); job["store"] != "store2" || job["keep-daily"] != int64(7) {
		t.Errorf("prune job = %v, want it created again on store2", job)
	}
	if job, _ := datastores.verifyJob("weekly"); job["store"] != "store2" || job["schedule"] != "sat 03:00" {
		t.Errorf("verify job = %v, want it created again on store2", job)
	}
	if fake.count("POST /config/prune") != 2 || fake.count("POST /config/verify") != 2 {
		t.Errorf("routes = %v", fake.routes())
	}
	if stringAt(t, prune.state, "store") != "store2" || stringAt(t, verify.state, "store") != "store2" {
		t.Errorf("states = %s, %s", prune.state, verify.state)
	}
}
