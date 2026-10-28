package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// PBS leaves out every property at its default, a pull job's direction
// among them.
func TestGetSyncJobDecodesTheJob(t *testing.T) {
	zero, two, three := int64(0), int64(2), int64(3)
	yes := true
	tests := map[string]struct {
		answer        string
		want          SyncJob
		wantDirection string
	}{
		"pull with defaults left out": {
			`{"data":{"id":"pull1","store":"store1","remote":"offsite","remote-store":"store2"},"digest":"9f86d081884c7d65"}`,
			SyncJob{ID: "pull1", Store: "store1", Remote: "offsite", RemoteStore: "store2"},
			SyncDirectionPull,
		},
		"local pull": {
			`{"data":{"id":"local1","store":"store1","remote-store":"store2","max-depth":0},"digest":"9f86d081884c7d65"}`,
			SyncJob{ID: "local1", Store: "store1", RemoteStore: "store2", MaxDepth: &zero},
			SyncDirectionPull,
		},
		"push with every property": {
			`{"data":{"id":"push1","store":"store1","ns":"dept1","remote":"offsite","remote-store":"store2","remote-ns":"site-a",` +
				`"sync-direction":"push","max-depth":2,"schedule":"hourly","owner":"sync@pbs!push","remove-vanished":true,` +
				`"group-filter":["type:vm","exclude:group:vm/100"],"transfer-last":3,"encrypted-only":true,"verified-only":true,` +
				`"run-on-mount":true,"unmount-on-done":true,"worker-threads":2,"rate-in":"10 MiB","burst-in":"20 MiB",` +
				`"rate-out":"1 GB","burst-out":"2 GB","comment":"acc"},"digest":"9f86d081884c7d65"}`,
			SyncJob{
				ID: "push1", Store: "store1", NS: "dept1", Remote: "offsite", RemoteStore: "store2", RemoteNS: "site-a",
				SyncDirection: SyncDirectionPush, MaxDepth: &two, Schedule: "hourly", Owner: "sync@pbs!push",
				RemoveVanished: &yes, GroupFilter: []string{"type:vm", "exclude:group:vm/100"}, TransferLast: &three,
				EncryptedOnly: &yes, VerifiedOnly: &yes, RunOnMount: &yes, UnmountOnDone: &yes, WorkerThreads: &two,
				RateIn: "10 MiB", BurstIn: "20 MiB", RateOut: "1 GB", BurstOut: "2 GB", Comment: "acc",
			},
			SyncDirectionPush,
		},
		"pull with resync-corrupt": {
			`{"data":{"id":"pull1","store":"store1","remote":"offsite","remote-store":"store2","resync-corrupt":true},"digest":"9f86d081884c7d65"}`,
			SyncJob{ID: "pull1", Store: "store1", Remote: "offsite", RemoteStore: "store2", ResyncCorrupt: &yes},
			SyncDirectionPull,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/sync/"+tc.want.ID, http.StatusOK, tc.answer)
			job, err := fake.client(t).GetSyncJob(context.Background(), tc.want.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(job, tc.want) {
				t.Fatalf("GetSyncJob() = %+v, want %+v", job, tc.want)
			}
			if got := job.Direction(); got != tc.wantDirection {
				t.Errorf("Direction() = %q, want %q", got, tc.wantDirection)
			}
		})
	}
}

// Without sync-direction, PBS lists pull jobs only, so the list always asks
// for both directions. The writes send the caller's params as the form.
func TestSyncJobCallsHitTheirRoutes(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/sync", http.StatusOK, `{"data":[{"id":"pull1","store":"store1","remote":"offsite","remote-store":"store2"},`+
		`{"id":"push1","store":"store1","remote":"offsite","remote-store":"store3","sync-direction":"push"}],"digest":"9f86d081884c7d65"}`)
	fake.reply("POST /config/sync", http.StatusOK, `{"data":null}`)
	fake.reply("PUT /config/sync/push1", http.StatusOK, `{"data":null}`)
	fake.reply("DELETE /config/sync/push1", http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	jobs, err := c.ListSyncJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[1].Direction() != SyncDirectionPush {
		t.Fatalf("ListSyncJobs() = %+v", jobs)
	}
	if got := fake.lastCall(t, "GET /config/sync").query; !reflect.DeepEqual(got, url.Values{"sync-direction": {"all"}}) {
		t.Errorf("ListSyncJobs query = %v, want sync-direction=all", got)
	}

	create := url.Values{"id": {"push1"}, "store": {"store1"}, "remote": {"offsite"}, "remote-store": {"store3"}, "sync-direction": {"push"}}
	if err := c.CreateSyncJob(ctx, create); err != nil {
		t.Fatalf("CreateSyncJob() = %v", err)
	}
	update := url.Values{"rate-out": {"10MiB"}, "delete": {"comment", "schedule"}}
	if err := c.UpdateSyncJob(ctx, "push1", update); err != nil {
		t.Fatalf("UpdateSyncJob() = %v", err)
	}
	if err := c.DeleteSyncJob(ctx, "push1"); err != nil {
		t.Fatalf("DeleteSyncJob() = %v", err)
	}

	want := []string{"GET /config/sync", "POST /config/sync", "PUT /config/sync/push1", "DELETE /config/sync/push1"}
	if got := fake.routes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if call := fake.lastCall(t, "POST /config/sync"); !reflect.DeepEqual(call.form, create) {
		t.Errorf("CreateSyncJob form = %v, want %v", call.form, create)
	}
	if call := fake.lastCall(t, "PUT /config/sync/push1"); !reflect.DeepEqual(call.form, update) {
		t.Errorf("UpdateSyncJob form = %v, want %v", call.form, update)
	}
	if call := fake.lastCall(t, "DELETE /config/sync/push1"); len(call.query) != 0 || len(call.form) != 0 {
		t.Errorf("DeleteSyncJob query = %v, form = %v, want neither", call.query, call.form)
	}
}

// A missing job is a 400 on read and a 404 on delete.
func TestSyncJobErrorsAreRecognised(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/sync/missing", http.StatusBadRequest, "no such sync 'missing'")
	fake.reply("DELETE /config/sync/missing", http.StatusNotFound, "job 'missing' does not exist.")
	fake.reply("POST /config/sync", http.StatusBadRequest, "parameter verification failed - 'id': job 'taken' already exists.")
	c := fake.client(t)
	ctx := context.Background()

	if _, err := c.GetSyncJob(ctx, "missing"); !IsNotFound(err) {
		t.Errorf("GetSyncJob() = %v, want a not-found error", err)
	}
	if err := c.DeleteSyncJob(ctx, "missing"); !IsNotFound(err) {
		t.Errorf("DeleteSyncJob() = %v, want a not-found error", err)
	}
	if err := c.CreateSyncJob(ctx, url.Values{"id": {"taken"}}); !IsAlreadyExists(err) || IsNotFound(err) {
		t.Errorf("CreateSyncJob() = %v, want an already-exists error", err)
	}
}

// The prune and verify job lists answer every job the caller may audit.
func TestListPruneAndVerifyJobs(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/prune", http.StatusOK, `{"data":[{"id":"daily","store":"store1","schedule":"daily","keep-last":3}],"digest":"9f86d081884c7d65"}`)
	fake.reply("GET /config/verify", http.StatusOK, `{"data":[{"id":"verify1","store":"store1"},{"id":"verify2","store":"store2","schedule":"weekly"}],"digest":"9f86d081884c7d65"}`)
	c := fake.client(t)
	ctx := context.Background()

	three := int64(3)
	prune, err := c.ListPruneJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []PruneJob{{ID: "daily", Store: "store1", Schedule: "daily", KeepOptions: KeepOptions{KeepLast: &three}}}; !reflect.DeepEqual(prune, want) {
		t.Errorf("ListPruneJobs() = %+v, want %+v", prune, want)
	}
	verify, err := c.ListVerifyJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []VerifyJob{{ID: "verify1", Store: "store1"}, {ID: "verify2", Store: "store2", Schedule: "weekly"}}; !reflect.DeepEqual(verify, want) {
		t.Errorf("ListVerifyJobs() = %+v, want %+v", verify, want)
	}
}
