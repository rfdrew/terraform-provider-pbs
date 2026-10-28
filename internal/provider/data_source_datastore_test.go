package provider

import (
	"net/http"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestDatastoreDataSourceSchemasAreValid(t *testing.T) {
	requireValidDataSourceSchema(t, &datastoreDataSource{})
	requireValidDataSourceSchema(t, &datastoresDataSource{})
	requireValidDataSourceSchema(t, &namespacesDataSource{})
	requireValidDataSourceSchema(t, &datastoreStatusDataSource{})
	requireValidDataSourceSchema(t, &gcStatusDataSource{})
}

// newDatastoreDataHarness is a fake PBS with a datastore of each kind and the
// lists of datastores.
func newDatastoreDataHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeDatastores, *fakeDatastoreStatus) {
	t.Helper()
	h, fake, datastores := newDatastoreHarness(t)
	status := newFakeDatastoreStatus(datastores)
	datastores.addDatastore("store1", fakeProperties{
		"path":              "/mnt/datastore/store1",
		"comment":           "Backups",
		"gc-schedule":       "daily",
		"verify-new":        true,
		"notification-mode": "legacy-sendmail",
		"notify":            "gc=error",
		"tuning":            "chunk-order=none,gc-cache-capacity=0",
		"maintenance-mode":  "delete",
	})
	datastores.addDatastore("usb", fakeProperties{"path": "pbs/usb", "backing-device": testDeviceUUID, "gc-on-unmount": true})
	datastores.addDatastore("s3store", fakeProperties{"path": "/mnt/cache", "backend": "type=s3,client=minio,bucket=pbs"})
	datastores.setMounted("usb", true)
	return h, fake, datastores, status
}

// A datastore reads in full, a maintenance mode PBS set itself included, and
// one that is not removable without asking whether it is mounted.
func TestDatastoreDataSource(t *testing.T) {
	h, fake, _, _ := newDatastoreDataHarness(t)

	state := h.readDataSource(t, "pbs_datastore", h.dataSourceValue(t, "pbs_datastore", map[string]any{"name": "store1"}))
	want := h.dataSourceValue(t, "pbs_datastore", map[string]any{
		"name":              "store1",
		"path":              "/mnt/datastore/store1",
		"comment":           "Backups",
		"gc_schedule":       "daily",
		"gc_on_unmount":     false,
		"verify_new":        true,
		"notification_mode": "legacy-sendmail",
		"notify":            map[string]any{"gc": "error"},
		"tuning":            map[string]any{"chunk_order": "none", "gc_cache_capacity": 0},
		"maintenance_mode":  map[string]any{"type": "delete"},
		"mount_status":      "nonremovable",
		"backend_type":      "filesystem",
	})
	if !state.Equal(want) {
		diffs, _ := state.Diff(want)
		t.Errorf("state differs: %v", diffs)
	}
	if n := fake.count("GET /admin/datastore"); n != 0 {
		t.Errorf("listed the datastores %d times for one that is not removable", n)
	}

	state = h.readDataSource(t, "pbs_datastore", h.dataSourceValue(t, "pbs_datastore", map[string]any{"name": "usb"}))
	if stringAt(t, state, "backing_device") != testDeviceUUID || stringAt(t, state, "mount_status") != pbsclient.MountStatusMounted ||
		!boolAt(t, state, "gc_on_unmount") || stringAt(t, state, "notification_mode") != "notification-system" ||
		!isNullAt(t, state, "tuning") || !isNullAt(t, state, "maintenance_mode") {
		t.Errorf("usb = %s", state)
	}
	state = h.readDataSource(t, "pbs_datastore", h.dataSourceValue(t, "pbs_datastore", map[string]any{"name": "s3store"}))
	if stringAt(t, state, "backend_type") != "s3" {
		t.Errorf("s3store = %s", state)
	}

	resp := h.readDataSourceResponse(t, "pbs_datastore", h.dataSourceValue(t, "pbs_datastore", map[string]any{"name": "missing"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS has no datastore "missing"`)

	fake.reply("GET /admin/datastore", http.StatusForbidden, "permission check failed")
	resp = h.readDataSourceResponse(t, "pbs_datastore", h.dataSourceValue(t, "pbs_datastore", map[string]any{"name": "usb"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "whether the PBS datastore is mounted")
}

// The list has every datastore, sorted, and asks once whether the removable
// ones are mounted — not at all without one.
func TestDatastoresDataSource(t *testing.T) {
	h, fake, datastores, _ := newDatastoreDataHarness(t)

	state := h.readDataSource(t, "pbs_datastores", h.dataSourceValue(t, "pbs_datastores", map[string]any{}))
	if n := lengthAt(t, state, "datastores"); n != 3 {
		t.Fatalf("listed %d datastores, want 3", n)
	}
	for i, want := range []struct{ name, mountStatus string }{
		{"s3store", "nonremovable"}, {"store1", "nonremovable"}, {"usb", "mounted"},
	} {
		if got := stringAt(t, state, "datastores", i, "name"); got != want.name {
			t.Errorf("datastores[%d].name = %q, want %q", i, got, want.name)
		}
		if got := stringAt(t, state, "datastores", i, "mount_status"); got != want.mountStatus {
			t.Errorf("datastores[%d].mount_status = %q, want %q", i, got, want.mountStatus)
		}
	}
	if n := fake.count("GET /admin/datastore"); n != 1 {
		t.Errorf("listed the datastore states %d times, want once", n)
	}

	datastores.mu.Lock()
	delete(datastores.datastores, "usb")
	datastores.mu.Unlock()
	h.readDataSource(t, "pbs_datastores", h.dataSourceValue(t, "pbs_datastores", map[string]any{}))
	if n := fake.count("GET /admin/datastore"); n != 1 {
		t.Error("listed the datastore states without a removable datastore")
	}

	fake.reply("GET /config/datastore", http.StatusForbidden, "permission check failed")
	resp := h.readDataSourceResponse(t, "pbs_datastores", h.dataSourceValue(t, "pbs_datastores", map[string]any{}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS datastores")
}

// Without datastores, the list is empty rather than null.
func TestDatastoresDataSourceEmpty(t *testing.T) {
	h, _, datastores := newDatastoreHarness(t)
	newFakeDatastoreStatus(datastores)
	state := h.readDataSource(t, "pbs_datastores", h.dataSourceValue(t, "pbs_datastores", map[string]any{}))
	if isNullAt(t, state, "datastores") || lengthAt(t, state, "datastores") != 0 {
		t.Errorf("state = %s, want an empty list", state)
	}
}

// The usage of a datastore PBS can open has figures; one it cannot open has
// the error instead, one that is not mounted neither, and none of that is an
// error of the data source.
func TestDatastoreStatusDataSource(t *testing.T) {
	h, fake, datastores, status := newDatastoreDataHarness(t)
	datastores.setDatastoreProperty("store1", "maintenance-mode", nil)
	status.setUsage("store1", 1000, 400, 600)
	status.setEstimate("store1", 1900000000)

	state := h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "store1"}))
	want := h.dataSourceValue(t, "pbs_datastore_status", map[string]any{
		"store": "store1", "mount_status": "nonremovable", "backend_type": "filesystem",
		"total": 1000, "used": 400, "avail": 600, "estimated_full_date": 1900000000,
	})
	if !state.Equal(want) {
		diffs, _ := state.Diff(want)
		t.Errorf("state differs: %v", diffs)
	}

	datastores.setDatastoreProperty("store1", "maintenance-mode", "offline")
	state = h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "store1"}))
	if got := stringAt(t, state, "error"); got != "datastore 'store1' is unavailable: offline maintenance mode" || !isNullAt(t, state, "total") {
		t.Errorf("offline = %s", state)
	}

	datastores.setMounted("usb", false)
	state = h.readDataSource(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "usb"}))
	if stringAt(t, state, "mount_status") != "notmounted" || !isNullAt(t, state, "used") || !isNullAt(t, state, "error") {
		t.Errorf("unmounted = %s", state)
	}

	resp := h.readDataSourceResponse(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "missing"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, `PBS lists no datastore "missing"`)

	fake.reply("GET /status/datastore-usage", http.StatusInternalServerError, "unable to read rrd")
	resp = h.readDataSourceResponse(t, "pbs_datastore_status", h.dataSourceValue(t, "pbs_datastore_status", map[string]any{"store": "store1"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "unable to read rrd")
}

func TestGCStatusDataSource(t *testing.T) {
	h, _, datastores, status := newDatastoreDataHarness(t)
	datastores.setDatastoreProperty("store1", "maintenance-mode", nil)

	// Before the first run: the schedule, and zeros.
	state := h.readDataSource(t, "pbs_gc_status", h.dataSourceValue(t, "pbs_gc_status", map[string]any{"store": "store1"}))
	if stringAt(t, state, "schedule") != "daily" || !isNullAt(t, state, "last_run_state") || !isNullAt(t, state, "upid") ||
		int64At(t, state, "disk_chunks") != 0 || !isNullAt(t, state, "cache_stats") {
		t.Errorf("before the first run = %s", state)
	}

	status.setGC("store1", map[string]any{
		"next-run": 1900000000, "last-run-endtime": 1899990000, "last-run-state": "OK", "duration": 12,
		"upid":             "UPID:pbs-test:00000001:00000001:00000001:6AE11CDF:garbage_collection:store1:root@pam:",
		"index-file-count": 3, "index-data-bytes": 3000, "disk-bytes": 1000, "disk-chunks": 10, "removed-bytes": 200,
		"removed-chunks": 2, "pending-bytes": 50, "pending-chunks": 1, "removed-bad": 0, "still-bad": 1,
		"cache-stats": map[string]any{"hits": 7, "misses": 3},
	})
	state = h.readDataSource(t, "pbs_gc_status", h.dataSourceValue(t, "pbs_gc_status", map[string]any{"store": "store1"}))
	want := h.dataSourceValue(t, "pbs_gc_status", map[string]any{
		"store": "store1", "schedule": "daily", "next_run": 1900000000, "last_run_endtime": 1899990000,
		"last_run_state": "OK", "duration": 12,
		"upid":             "UPID:pbs-test:00000001:00000001:00000001:6AE11CDF:garbage_collection:store1:root@pam:",
		"index_file_count": 3, "index_data_bytes": 3000, "disk_bytes": 1000, "disk_chunks": 10, "removed_bytes": 200,
		"removed_chunks": 2, "pending_bytes": 50, "pending_chunks": 1, "removed_bad": 0, "still_bad": 1,
		"cache_stats": map[string]any{"hits": 7, "misses": 3},
	})
	if !state.Equal(want) {
		diffs, _ := state.Diff(want)
		t.Errorf("state differs: %v", diffs)
	}

	for store, wantErr := range map[string]string{
		"missing": `PBS has no datastore "missing"`,
		"usb":     "a removable datastore must be mounted",
		"hidden":  "lacks Datastore.Audit or Datastore.Backup on /datastore/hidden",
	} {
		if store == "usb" {
			datastores.setMounted("usb", false)
		}
		if store == "hidden" {
			datastores.addDatastore("hidden", fakeProperties{"path": "/mnt/hidden"})
			status.hideGC("hidden")
		}
		resp := h.readDataSourceResponse(t, "pbs_gc_status", h.dataSourceValue(t, "pbs_gc_status", map[string]any{"store": store}))
		requireProtocolErrorContaining(t, resp.Diagnostics, wantErr)
	}
}
