package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A UPID in the form PBS 4.2 sends for deleting the datastore "probe-b".
const sampleDeleteUPID = "UPID:pbs-acc:0000000B:00001327:00000004:6AE11CE5:delete-datastore:probe\\x2db:tfacc@pbs!acc:"

// The route the fake answers for sampleDeleteUPID's status.
const sampleDeleteStatusRoute = "GET /nodes/pbs-acc/tasks/" + sampleDeleteUPID + "/status"

// taskAnswer is the envelope of a call that started the task upid.
func taskAnswer(upid string) string {
	encoded, _ := json.Marshal(map[string]string{"data": upid})
	return string(encoded)
}

// PBS answers a create with the UPID of a task, and HTTP 200 even when the
// task is going to fail, so the outcome is the task's exit status, read from
// the node the UPID names. A null answer starts no task, and nothing is
// polled.
func TestCreateDatastoreWaitsForTheTask(t *testing.T) {
	tests := map[string]struct {
		answer   string
		statuses []string
		// wantExit is the failed task's exit status, "" for a success.
		wantExit  string
		wantPolls int
	}{
		"task succeeds": {
			answer:    taskAnswer(sampleUPID),
			statuses:  []string{taskStatusJSON("running", ""), taskStatusJSON("stopped", "OK")},
			wantPolls: 2,
		},
		"task fails": {
			answer:    taskAnswer(sampleUPID),
			statuses:  []string{taskStatusJSON("stopped", "datastore path not empty")},
			wantExit:  "datastore path not empty",
			wantPolls: 1,
		},
		"no task": {
			answer:   `{"data":null}`,
			statuses: []string{taskStatusJSON("stopped", "OK")},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("POST /config/datastore", http.StatusOK, tc.answer)
			fake.replies(sampleStatusRoute, http.StatusOK, tc.statuses...)
			params := url.Values{"name": {"probe-b"}, "path": {"/mnt/datastore/probe-b"}, "gc-schedule": {"daily"}}

			err := fake.client(t).CreateDatastore(context.Background(), params)
			var taskErr *TaskError
			if tc.wantExit == "" && err != nil {
				t.Fatalf("CreateDatastore() = %v", err)
			}
			if tc.wantExit != "" && (!errors.As(err, &taskErr) || taskErr.ExitStatus != tc.wantExit || taskErr.UPID.Raw != sampleUPID) {
				t.Fatalf("CreateDatastore() = %v, want the task's error %q", err, tc.wantExit)
			}
			if call := fake.lastCall(t, "POST /config/datastore"); !reflect.DeepEqual(call.form, params) {
				t.Fatalf("form = %v, want %v", call.form, params)
			}
			if n := fake.count(sampleStatusRoute); n != tc.wantPolls {
				t.Fatalf("polled %d times, want %d", n, tc.wantPolls)
			}
		})
	}
}

// A refusal before any task starts is PBS's error as it sent it, which the
// provider recognises.
func TestCreateDatastoreReturnsTheRefusal(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /config/datastore", http.StatusBadRequest, "parameter verification failed - 'name': datastore 'probe-b' already exists.")
	err := fake.client(t).CreateDatastore(context.Background(), url.Values{"name": {"probe-b"}, "path": {"/mnt/datastore/probe-b"}})
	if _, ok := asError(err); !ok || !IsAlreadyExists(err) ||
		err.Error() != "PBS API error: POST /config/datastore: HTTP 400: parameter verification failed - 'name': datastore 'probe-b' already exists." {
		t.Fatalf("CreateDatastore() = %v, want PBS's 400", err)
	}
	if n := fake.count(sampleStatusRoute); n != 0 {
		t.Fatalf("polled a task %d times after a refusal", n)
	}
}

// The task that creates a datastore writes its configuration entry, so the
// entry is read again while PBS answers that there is no such datastore.
func TestWaitForDatastorePollsUntilTheEntryAppears(t *testing.T) {
	const route = "GET /config/datastore/probe-b"
	tests := map[string]struct {
		missing int
	}{
		"there at once":             {0},
		"appears on the third read": {2},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			reads := 0
			fake.handle(route, func(w http.ResponseWriter, _ *http.Request) {
				reads++
				if reads <= tc.missing {
					writeFakeResponse(w, http.StatusBadRequest, "no such datastore 'probe-b'")
					return
				}
				writeFakeResponse(w, http.StatusOK, `{"data":{"name":"probe-b","path":"/mnt/datastore/probe-b"},"digest":"9f86d081884c7d65"}`)
			})

			ds, err := fake.client(t).WaitForDatastore(context.Background(), "probe-b")
			if err != nil || ds.Name != "probe-b" || ds.Path != "/mnt/datastore/probe-b" {
				t.Fatalf("WaitForDatastore() = %+v, %v", ds, err)
			}
			if n := fake.count(route); n != tc.missing+1 {
				t.Fatalf("read %d times, want %d", n, tc.missing+1)
			}
		})
	}
}

// An entry that never appears ends the wait after datastoreEntryPolls reads,
// with PBS's own error inside, so the caller still sees a missing datastore.
func TestWaitForDatastoreGivesUp(t *testing.T) {
	const route = "GET /config/datastore/probe-b"
	fake := newFakePBS()
	fake.reply(route, http.StatusBadRequest, "no such datastore 'probe-b'")
	c := fake.client(t)
	var waits []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return ctx.Err()
	}

	ds, err := c.WaitForDatastore(context.Background(), "probe-b")
	if !IsNotFound(err) || !strings.Contains(err.Error(), `datastore "probe-b" did not appear`) || ds != (Datastore{}) {
		t.Fatalf("WaitForDatastore() = %+v, %v, want a not-found error", ds, err)
	}
	if n := fake.count(route); n != datastoreEntryPolls {
		t.Fatalf("read %d times, want %d", n, datastoreEntryPolls)
	}
	if len(waits) != datastoreEntryPolls-1 || waits[0] != datastoreEntryInterval {
		t.Fatalf("waited %v, want %d waits of %s", waits, datastoreEntryPolls-1, datastoreEntryInterval)
	}
}

// The wait ends with the caller's context.
func TestWaitForDatastoreStopsWithTheContext(t *testing.T) {
	const route = "GET /config/datastore/probe-b"
	fake := newFakePBS()
	fake.reply(route, http.StatusBadRequest, "no such datastore 'probe-b'")
	c := fake.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}

	if _, err := c.WaitForDatastore(ctx, "probe-b"); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForDatastore() = %v, want context.Canceled", err)
	}
	if n := fake.count(route); n != 1 {
		t.Fatalf("read %d times, want once", n)
	}
}

// Any other error is no datastore still being created, and is returned at
// once.
func TestWaitForDatastoreReturnsOtherErrorsAtOnce(t *testing.T) {
	const route = "GET /config/datastore/probe-b"
	fake := newFakePBS()
	fake.reply(route, http.StatusForbidden, "permission check failed")
	if _, err := fake.client(t).WaitForDatastore(context.Background(), "probe-b"); !IsForbidden(err) {
		t.Fatalf("WaitForDatastore() = %v, want PBS's 403", err)
	}
	if n := fake.count(route); n != 1 {
		t.Fatalf("read %d times, want once", n)
	}
}

// A read in the shape PBS 4.2 sends: property strings stay as they are, and a
// boolean PBS leaves out at its default reads as unset rather than false.
func TestGetDatastoreDecodesTheConfiguration(t *testing.T) {
	yes := true
	tests := map[string]struct {
		answer string
		want   Datastore
	}{
		"every property": {
			`{"data":{"name":"probe-b","path":"/mnt/datastore/probe-b","comment":"acc","gc-schedule":"daily",` +
				`"verify-new":true,"notify-user":"root@pam","notification-mode":"legacy-sendmail",` +
				`"notify":"gc=error,prune=never,sync=always,verify=always",` +
				`"tuning":"chunk-order=inode,sync-level=filesystem",` +
				`"maintenance-mode":"type=read-only,message=\"moving disks\""},"digest":"9f86d081884c7d65"}`,
			Datastore{
				Name: "probe-b", Path: "/mnt/datastore/probe-b", Comment: "acc", GCSchedule: "daily",
				VerifyNew: &yes, NotifyUser: "root@pam", NotificationMode: "legacy-sendmail",
				Notify:          "gc=error,prune=never,sync=always,verify=always",
				Tuning:          "chunk-order=inode,sync-level=filesystem",
				MaintenanceMode: `type=read-only,message="moving disks"`,
			},
		},
		"defaults left out": {
			`{"data":{"name":"probe-b","path":"/mnt/datastore/probe-b"},"digest":"9f86d081884c7d65"}`,
			Datastore{Name: "probe-b", Path: "/mnt/datastore/probe-b"},
		},
		"on S3": {
			`{"data":{"name":"probe-s3","path":"/mnt/cache/probe-s3","backend":"bucket=probe,client=s3-probe,type=s3"},"digest":"9f86d081884c7d65"}`,
			Datastore{Name: "probe-s3", Path: "/mnt/cache/probe-s3", Backend: "bucket=probe,client=s3-probe,type=s3"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/datastore/"+tc.want.Name, http.StatusOK, tc.answer)
			ds, err := fake.client(t).GetDatastore(context.Background(), tc.want.Name)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ds, tc.want) {
				t.Fatalf("GetDatastore() = %+v, want %+v", ds, tc.want)
			}
		})
	}
}

// BackendType reads the type from the backend property string; a datastore
// without one, or a backend without a type, is on the filesystem, PBS's
// default.
func TestDatastoreBackendType(t *testing.T) {
	tests := map[string]struct {
		backend string
		want    string
	}{
		"no backend":      {"", BackendFilesystem},
		"s3":              {"type=s3,client=c,bucket=b", BackendS3},
		"filesystem":      {"type=filesystem", BackendFilesystem},
		"no type":         {"client=c,bucket=b", BackendFilesystem},
		"does not parse":  {`type="s3,bucket=b`, `type="s3,bucket=b`},
		"duplicated type": {"type=s3,type=filesystem", "type=s3,type=filesystem"},
	}
	for name, tc := range tests {
		if got := (Datastore{Backend: tc.backend}).BackendType(); got != tc.want {
			t.Errorf("%s: BackendType() of %q = %q, want %q", name, tc.backend, got, tc.want)
		}
	}
}

// A caller sets read-only and offline; PBS sets the others itself.
func TestIsInternalMaintenance(t *testing.T) {
	tests := map[string]bool{
		"read-only":  false,
		"offline":    false,
		"delete":     true,
		"unmount":    true,
		"s3-refresh": true,
		"":           false,
	}
	for maintenanceType, want := range tests {
		if got := IsInternalMaintenance(maintenanceType); got != want {
			t.Errorf("IsInternalMaintenance(%q) = %v, want %v", maintenanceType, got, want)
		}
	}
}

func TestUpdateDatastoreSendsTheParams(t *testing.T) {
	const route = "PUT /config/datastore/probe-b"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":null}`)
	params := url.Values{"comment": {"acc"}, "delete": {"gc-schedule", "tuning"}, "digest": {"9f86d081884c7d65"}}
	if err := fake.client(t).UpdateDatastore(context.Background(), "probe-b", params); err != nil {
		t.Fatal(err)
	}
	if call := fake.lastCall(t, route); !reflect.DeepEqual(call.form, params) {
		t.Fatalf("form = %v, want %v", call.form, params)
	}
}

// DELETE carries its parameters in the query, and each flag only when it is
// set: PBS's defaults keep the data and delete the jobs. The answer is the
// UPID of a task, which is waited for.
func TestDeleteDatastoreSendsOnlyWhatIsSet(t *testing.T) {
	const route = "DELETE /config/datastore/probe-b"
	tests := map[string]struct {
		deletion  DatastoreDeletion
		wantQuery url.Values
	}{
		"configuration only": {DatastoreDeletion{}, url.Values{}},
		"destroy data":       {DatastoreDeletion{DestroyData: true}, url.Values{"destroy-data": {"true"}}},
		"keep jobs":          {DatastoreDeletion{KeepJobConfigs: true}, url.Values{"keep-job-configs": {"true"}}},
		"both": {
			DatastoreDeletion{DestroyData: true, KeepJobConfigs: true},
			url.Values{"destroy-data": {"true"}, "keep-job-configs": {"true"}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(route, http.StatusOK, taskAnswer(sampleDeleteUPID))
			fake.reply(sampleDeleteStatusRoute, http.StatusOK, taskStatusJSON("stopped", "OK"))
			if err := fake.client(t).DeleteDatastore(context.Background(), "probe-b", tc.deletion); err != nil {
				t.Fatal(err)
			}
			if call := fake.lastCall(t, route); !reflect.DeepEqual(call.query, tc.wantQuery) || len(call.form) != 0 {
				t.Fatalf("query = %v, form = %v, want query %v", call.query, call.form, tc.wantQuery)
			}
			if n := fake.count(sampleDeleteStatusRoute); n != 1 {
				t.Fatalf("polled %d times, want once", n)
			}
		})
	}
}

// DELETE answers a missing datastore with a 404 of its own text, which the
// provider recognises; there is no task to wait for.
func TestDeleteDatastoreReportsAMissingDatastore(t *testing.T) {
	fake := newFakePBS()
	fake.reply("DELETE /config/datastore/probe-b", http.StatusNotFound, "datastore 'probe-b' does not exist.")
	if err := fake.client(t).DeleteDatastore(context.Background(), "probe-b", DatastoreDeletion{}); !IsNotFound(err) {
		t.Fatalf("DeleteDatastore() = %v, want a not-found error", err)
	}
	if n := fake.count(sampleDeleteStatusRoute); n != 0 {
		t.Fatalf("polled a task %d times", n)
	}
}
