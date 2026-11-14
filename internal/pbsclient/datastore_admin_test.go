package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// Mounting and unmounting are POSTs, refreshing from S3 a PUT; each answers
// the task's UPID.
func TestDatastoreAdminTasks(t *testing.T) {
	fake := newFakePBS()
	upidJSON, _ := json.Marshal(map[string]string{"data": sampleUPID})
	for _, route := range []string{
		"POST /admin/datastore/store1/mount",
		"POST /admin/datastore/store1/unmount",
		"PUT /admin/datastore/store1/s3-refresh",
	} {
		fake.reply(route, http.StatusOK, string(upidJSON))
	}
	client := fake.client(t)
	ctx := context.Background()
	for name, start := range map[string]func(context.Context, string) (UPID, error){
		"MountDatastore":         client.MountDatastore,
		"UnmountDatastore":       client.UnmountDatastore,
		"RefreshDatastoreFromS3": client.RefreshDatastoreFromS3,
	} {
		upid, err := start(ctx, "store1")
		if err != nil || upid.Raw != sampleUPID {
			t.Errorf("%s() = %q, %v", name, upid.Raw, err)
		}
	}
	if len(fake.routes()) != 3 {
		t.Fatalf("routes = %v", fake.routes())
	}
}

func TestDatastoreActiveOperations(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /admin/datastore/store1/active-operations", http.StatusOK, `{"data":{"read":2,"write":1}}`)
	ops, err := fake.client(t).DatastoreActiveOperations(context.Background(), "store1")
	if err != nil || ops != (ActiveOperations{Read: 2, Write: 1}) {
		t.Fatalf("DatastoreActiveOperations() = %+v, %v", ops, err)
	}
}

// An unmount answers with a capital D, every call that opens the datastore
// without; the whole message must match, as a maintenance mode's refusal ends
// with the mode's free text.
func TestIsDatastoreNotMounted(t *testing.T) {
	for message, want := range map[string]bool{
		"Datastore 'store1' is not mounted":                           true,
		"datastore 'store1' is not mounted":                           true,
		"datastore 'usb-2.offsite_A' is not mounted":                  true,
		"datastore 'store1' is unavailable: offline maintenance mode": false,
		"datastore 'store1' is not removable":                         false,
		"no such datastore 'store1'":                                  false,
		// A maintenance message that ends like the refusal.
		"datastore 'store1' is unavailable: read-only maintenance mode: disk 'usb2' is not mounted":      false,
		"datastore 'store1' is unavailable: offline maintenance mode: Datastore 'store1' is not mounted": false,
		"datastore 'store1' is not mounted yet":                                                          false,
		"DATASTORE 'store1' IS NOT MOUNTED":                                                              false,
		"unable to start garbage collection before unmount: datastore 'store1' is not mounted":           false,
	} {
		if got := IsDatastoreNotMounted(&Error{StatusCode: http.StatusBadRequest, Message: message}); got != want {
			t.Errorf("IsDatastoreNotMounted(%q) = %t, want %t", message, got, want)
		}
	}
	if IsDatastoreNotMounted(errors.New("Datastore 'x' is not mounted")) {
		t.Error("an error that is not PBS's counts as not mounted")
	}
	if IsDatastoreNotMounted(&Error{StatusCode: http.StatusForbidden, Message: "datastore 'store1' is not mounted"}) {
		t.Error("a 403 counts as not mounted")
	}
}

func TestIsDatastoreNotRemovable(t *testing.T) {
	if !IsDatastoreNotRemovable(&Error{StatusCode: http.StatusBadRequest, Message: "datastore 'store1' is not removable"}) {
		t.Error("PBS's answer is not recognised")
	}
	// The text of PBS's mount worker, which the API's own check comes
	// before, is something else.
	if IsDatastoreNotRemovable(&Error{StatusCode: http.StatusBadRequest, Message: "Datastore 'store1' cannot be mounted because it is not removable."}) {
		t.Error("another text counts as not removable")
	}
	if IsDatastoreNotRemovable(&Error{StatusCode: http.StatusForbidden, Message: "datastore 'store1' is not removable"}) {
		t.Error("a 403 counts as not removable")
	}
	// The whole message must match: a maintenance mode's free text can end
	// the same way.
	if IsDatastoreNotRemovable(&Error{StatusCode: http.StatusBadRequest, Message: "datastore 'store1' is unavailable: offline maintenance mode: datastore 'old' is not removable"}) {
		t.Error("a maintenance refusal counts as not removable")
	}
}
