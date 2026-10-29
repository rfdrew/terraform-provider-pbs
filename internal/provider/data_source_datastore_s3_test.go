package provider

import "testing"

// A datastore on S3 reads with its backend however PBS stores it, the
// thresholds of its request counters and their reset schedule, and the
// maintenance mode of a refresh; one in a directory or on a removable disk
// has none of them, also when PBS stores its default type of backend.
func TestDatastoreDataSourceS3(t *testing.T) {
	h, _, datastores, _ := newDatastoreDataHarness(t)
	datastores.setDatastoreProperty("s3store", "backend", "s3,client=minio,bucket=pbs,max-cache-size=1G")
	datastores.setDatastoreProperty("s3store", "notification-thresholds", "s3-upload=10GiB,s3-put=1000")
	datastores.setDatastoreProperty("s3store", "counter-reset-schedule", "monthly")
	datastores.setDatastoreProperty("s3store", "maintenance-mode", "s3-refresh")
	datastores.addDatastore("plain", fakeProperties{"path": "/mnt/datastore/plain", "backend": "type=filesystem"})

	state := h.readDataSource(t, "pbs_datastore", h.dataSourceValue(t, "pbs_datastore", map[string]any{"name": "s3store"}))
	want := h.dataSourceValue(t, "pbs_datastore", map[string]any{
		"name":                    "s3store",
		"path":                    "/mnt/cache",
		"gc_on_unmount":           false,
		"verify_new":              false,
		"notification_mode":       "notification-system",
		"maintenance_mode":        map[string]any{"type": "s3-refresh"},
		"mount_status":            "nonremovable",
		"backend_type":            "s3",
		"backend":                 map[string]any{"type": "s3", "client": "minio", "bucket": "pbs", "max_cache_size": "1G"},
		"notification_thresholds": map[string]any{"s3_put": 1000, "s3_upload": "10GiB"},
		"counter_reset_schedule":  "monthly",
	})
	if !state.Equal(want) {
		diffs, _ := state.Diff(want)
		t.Errorf("state differs: %v", diffs)
	}

	for _, name := range []string{"store1", "usb", "plain"} {
		state := h.readDataSource(t, "pbs_datastore", h.dataSourceValue(t, "pbs_datastore", map[string]any{"name": name}))
		if stringAt(t, state, "backend_type") != "filesystem" || !isNullAt(t, state, "backend") ||
			!isNullAt(t, state, "notification_thresholds") || !isNullAt(t, state, "counter_reset_schedule") {
			t.Errorf("%s = %s", name, state)
		}
	}

	// The list has the same for each datastore.
	state = h.readDataSource(t, "pbs_datastores", h.dataSourceValue(t, "pbs_datastores", map[string]any{}))
	if n := lengthAt(t, state, "datastores"); n != 4 {
		t.Fatalf("listed %d datastores, want 4", n)
	}
	for i := range 4 {
		switch name := stringAt(t, state, "datastores", i, "name"); name {
		case "s3store":
			if stringAt(t, state, "datastores", i, "backend", "client") != "minio" || stringAt(t, state, "datastores", i, "backend", "bucket") != "pbs" ||
				stringAt(t, state, "datastores", i, "backend", "max_cache_size") != "1G" ||
				int64At(t, state, "datastores", i, "notification_thresholds", "s3_put") != 1000 ||
				!isNullAt(t, state, "datastores", i, "notification_thresholds", "s3_get") ||
				stringAt(t, state, "datastores", i, "counter_reset_schedule") != "monthly" ||
				stringAt(t, state, "datastores", i, "backend_type") != "s3" {
				t.Errorf("datastores[%d] = %s", i, valueAt(t, state, "datastores", i))
			}
		default:
			if !isNullAt(t, state, "datastores", i, "backend") || !isNullAt(t, state, "datastores", i, "notification_thresholds") ||
				!isNullAt(t, state, "datastores", i, "counter_reset_schedule") {
				t.Errorf("datastores[%d], %s = %s", i, name, valueAt(t, state, "datastores", i))
			}
		}
	}
}
