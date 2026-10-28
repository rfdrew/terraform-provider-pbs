package pbsclient

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

func TestListDatastores(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/datastore", http.StatusOK,
		`{"data":[{"name":"store1","path":"/mnt/datastore/store1","gc-schedule":"daily"},`+
			`{"name":"usb","path":"backups","backing-device":"0a1b2c3d-0000-4000-8000-000000000001","gc-on-unmount":true}]}`)

	got, err := fake.client(t).ListDatastores(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gcOnUnmount := true
	want := []Datastore{
		{Name: "store1", Path: "/mnt/datastore/store1", GCSchedule: "daily"},
		{Name: "usb", Path: "backups", BackingDevice: "0a1b2c3d-0000-4000-8000-000000000001", GCOnUnmount: &gcOnUnmount},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListDatastores() = %+v, want %+v", got, want)
	}
}

// A datastore that is not removable is not mounted or unmounted, and PBS
// is not asked; a removable one is looked up in the list of datastores.
func TestDatastoreMountStatus(t *testing.T) {
	const route = "GET /admin/datastore"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":[`+
		`{"store":"store1","mount-status":"nonremovable","backend-type":"filesystem"},`+
		`{"store":"usb","mount-status":"notmounted","maintenance":"unmount","backend-type":"filesystem"}]}`)
	client := fake.client(t)
	ctx := context.Background()

	if got, err := client.DatastoreMountStatus(ctx, Datastore{Name: "store1", Path: "/mnt/datastore/store1"}); got != MountStatusNonRemovable || err != nil {
		t.Errorf("DatastoreMountStatus(store1) = %q, %v", got, err)
	}
	if n := fake.count(route); n != 0 {
		t.Errorf("listed the datastores %d times for one that is not removable", n)
	}
	usb := Datastore{Name: "usb", Path: "backups", BackingDevice: "0a1b2c3d-0000-4000-8000-000000000001"}
	if got, err := client.DatastoreMountStatus(ctx, usb); got != MountStatusNotMounted || err != nil {
		t.Errorf("DatastoreMountStatus(usb) = %q, %v", got, err)
	}
	usb.Name = "gone"
	if got, err := client.DatastoreMountStatus(ctx, usb); got != "" || err != nil {
		t.Errorf("DatastoreMountStatus(gone) = %q, %v, want nothing", got, err)
	}

	fake.reply(route, http.StatusForbidden, "permission check failed")
	if _, err := client.DatastoreMountStatus(ctx, usb); !IsForbidden(err) {
		t.Errorf("DatastoreMountStatus() = %v, want PBS's error", err)
	}
}

// The usage of a datastore PBS can open has figures; one it cannot open has
// the error instead, and one that is not mounted neither.
func TestListDatastoreUsage(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /status/datastore-usage", http.StatusOK, `{"data":[`+
		`{"store":"store1","total":1000,"used":400,"avail":600,"mount-status":"nonremovable","backend-type":"filesystem",`+
		`"estimated-full-date":1900000000,"history":[0.1,null,0.4],"history-start":1,"history-delta":60,`+
		`"gc-status":{"index-file-count":3,"index-data-bytes":30,"disk-bytes":20,"disk-chunks":2,"removed-bytes":0,`+
		`"removed-chunks":0,"pending-bytes":0,"pending-chunks":0,"removed-bad":0,"still-bad":0}},`+
		`{"store":"offline","mount-status":"nonremovable","backend-type":"filesystem","error":"datastore 'offline' is unavailable: offline maintenance mode"},`+
		`{"store":"usb","mount-status":"notmounted","backend-type":"filesystem"}]}`)

	got, err := fake.client(t).ListDatastoreUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	total, used, avail, full := int64(1000), int64(400), int64(600), int64(1900000000)
	want := []DatastoreUsage{
		{
			Store: "store1", Total: &total, Used: &used, Avail: &avail, MountStatus: MountStatusNonRemovable,
			BackendType: BackendFilesystem, EstimatedFullDate: &full,
			GCStatus: &GCStatus{IndexFileCount: 3, IndexDataBytes: 30, DiskBytes: 20, DiskChunks: 2},
		},
		{
			Store: "offline", MountStatus: MountStatusNonRemovable, BackendType: BackendFilesystem,
			Error: "datastore 'offline' is unavailable: offline maintenance mode",
		},
		{Store: "usb", MountStatus: MountStatusNotMounted, BackendType: BackendFilesystem},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListDatastoreUsage() = %+v, want %+v", got, want)
	}
}

// PBS answers the status flattened, schedule and figures side by side, in a
// list of one — or of none, without the privilege to see it.
func TestGCJobStatus(t *testing.T) {
	const route = "GET /admin/gc/store1"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":[{"store":"store1","schedule":"daily","next-run":1900000000,`+
		`"last-run-endtime":1899990000,"last-run-state":"OK","duration":12,`+
		`"upid":"UPID:pbs:0000000B:00001327:00000004:6AE11CE5:garbage_collection:store1:root@pam:",`+
		`"index-file-count":3,"index-data-bytes":3000,"disk-bytes":1000,"disk-chunks":10,"removed-bytes":200,`+
		`"removed-chunks":2,"pending-bytes":50,"pending-chunks":1,"removed-bad":0,"still-bad":1,`+
		`"cache-stats":{"hits":7,"misses":3}}]}`)
	client := fake.client(t)

	got, ok, err := client.GCJobStatus(context.Background(), "store1")
	if err != nil || !ok {
		t.Fatalf("GCJobStatus() = %t, %v", ok, err)
	}
	next, end, duration := int64(1900000000), int64(1899990000), int64(12)
	want := GCJobStatus{
		Store: "store1", Schedule: "daily", NextRun: &next, LastRunEndtime: &end, LastRunState: "OK", Duration: &duration,
		GCStatus: GCStatus{
			UPID:           "UPID:pbs:0000000B:00001327:00000004:6AE11CE5:garbage_collection:store1:root@pam:",
			IndexFileCount: 3, IndexDataBytes: 3000, DiskBytes: 1000, DiskChunks: 10, RemovedBytes: 200,
			RemovedChunks: 2, PendingBytes: 50, PendingChunks: 1, StillBad: 1,
			CacheStats: &GCCacheStats{Hits: 7, Misses: 3},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GCJobStatus() = %+v, want %+v", got, want)
	}

	fake.reply(route, http.StatusOK, `{"data":[]}`)
	if _, ok, err := client.GCJobStatus(context.Background(), "store1"); ok || err != nil {
		t.Errorf("GCJobStatus() without the privilege = %t, %v, want nothing", ok, err)
	}

	fake.reply(route, http.StatusBadRequest, "datastore 'store1' is not mounted")
	if _, _, err := client.GCJobStatus(context.Background(), "store1"); !IsDatastoreUnavailable(err) {
		t.Errorf("GCJobStatus() on an unmounted datastore = %v", err)
	}
}
