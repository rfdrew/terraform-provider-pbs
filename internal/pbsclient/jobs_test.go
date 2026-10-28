package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// PBS leaves out every property at its default, so an absent keep-* or
// max-depth reads as unset, and a 0 as 0: for max-depth the two differ, all
// namespaces below against none.
func TestGetPruneJobDecodesTheJob(t *testing.T) {
	zero, one, three, four, seven := int64(0), int64(1), int64(3), int64(4), int64(7)
	yes := true
	tests := map[string]struct {
		answer string
		want   PruneJob
	}{
		"defaults left out": {
			`{"data":{"id":"probe-prune","store":"probe-b","schedule":"daily"},"digest":"9f86d081884c7d65"}`,
			PruneJob{ID: "probe-prune", Store: "probe-b", Schedule: "daily"},
		},
		"zero": {
			`{"data":{"id":"probe-prune","store":"probe-b","schedule":"daily","max-depth":0,"keep-last":0},"digest":"9f86d081884c7d65"}`,
			PruneJob{ID: "probe-prune", Store: "probe-b", Schedule: "daily", MaxDepth: &zero, KeepOptions: KeepOptions{KeepLast: &zero}},
		},
		"every property": {
			`{"data":{"id":"probe-prune","store":"probe-b","schedule":"daily","ns":"team-a","max-depth":1,"disable":true,"comment":"acc",` +
				`"keep-last":3,"keep-daily":7,"keep-weekly":4,"keep-monthly":3,"keep-yearly":1},"digest":"9f86d081884c7d65"}`,
			PruneJob{
				ID: "probe-prune", Store: "probe-b", Schedule: "daily", NS: "team-a", MaxDepth: &one, Disable: &yes, Comment: "acc",
				KeepOptions: KeepOptions{KeepLast: &three, KeepDaily: &seven, KeepWeekly: &four, KeepMonthly: &three, KeepYearly: &one},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/prune/probe-prune", http.StatusOK, tc.answer)
			job, err := fake.client(t).GetPruneJob(context.Background(), "probe-prune")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(job, tc.want) {
				t.Fatalf("GetPruneJob() = %+v, want %+v", job, tc.want)
			}
		})
	}
}

// A verify job created with only its ID and datastore reads as just those.
func TestGetVerifyJobDecodesTheJob(t *testing.T) {
	zero, two, four, thirty := int64(0), int64(2), int64(4), int64(30)
	yes := true
	tests := map[string]struct {
		answer string
		want   VerifyJob
	}{
		"defaults left out": {
			`{"data":{"id":"probe-verify","store":"probe-b"},"digest":"9f86d081884c7d65"}`,
			VerifyJob{ID: "probe-verify", Store: "probe-b"},
		},
		"zero max-depth": {
			`{"data":{"id":"probe-verify","store":"probe-b","ns":"team-a","max-depth":0},"digest":"9f86d081884c7d65"}`,
			VerifyJob{ID: "probe-verify", Store: "probe-b", NS: "team-a", MaxDepth: &zero},
		},
		"every property": {
			`{"data":{"id":"probe-verify","store":"probe-b","ns":"team-a","max-depth":2,"schedule":"daily","ignore-verified":true,` +
				`"outdated-after":30,"read-threads":2,"verify-threads":4,"comment":"acc"},"digest":"9f86d081884c7d65"}`,
			VerifyJob{
				ID: "probe-verify", Store: "probe-b", NS: "team-a", MaxDepth: &two, Schedule: "daily", IgnoreVerified: &yes,
				OutdatedAfter: &thirty, ReadThreads: &two, VerifyThreads: &four, Comment: "acc",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/verify/probe-verify", http.StatusOK, tc.answer)
			job, err := fake.client(t).GetVerifyJob(context.Background(), "probe-verify")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(job, tc.want) {
				t.Fatalf("GetVerifyJob() = %+v, want %+v", job, tc.want)
			}
		})
	}
}

// The writes send the caller's params as the form; the delete names the job
// in its path and sends nothing else.
func TestPruneJobCallsHitTheirRoutes(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /config/prune", http.StatusOK, `{"data":null}`)
	fake.reply("PUT /config/prune/probe-prune", http.StatusOK, `{"data":null}`)
	fake.reply("DELETE /config/prune/probe-prune", http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	create := url.Values{"id": {"probe-prune"}, "store": {"probe-b"}, "schedule": {"daily"}, "ns": {"team-a"}, "keep-last": {"3"}}
	if err := c.CreatePruneJob(ctx, create); err != nil {
		t.Fatalf("CreatePruneJob() = %v", err)
	}
	update := url.Values{"keep-daily": {"7"}, "delete": {"comment", "keep-last"}, "digest": {"9f86d081884c7d65"}}
	if err := c.UpdatePruneJob(ctx, "probe-prune", update); err != nil {
		t.Fatalf("UpdatePruneJob() = %v", err)
	}
	if err := c.DeletePruneJob(ctx, "probe-prune"); err != nil {
		t.Fatalf("DeletePruneJob() = %v", err)
	}

	want := []string{"POST /config/prune", "PUT /config/prune/probe-prune", "DELETE /config/prune/probe-prune"}
	if got := fake.routes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if call := fake.lastCall(t, "POST /config/prune"); !reflect.DeepEqual(call.form, create) {
		t.Errorf("CreatePruneJob form = %v, want %v", call.form, create)
	}
	if call := fake.lastCall(t, "PUT /config/prune/probe-prune"); !reflect.DeepEqual(call.form, update) {
		t.Errorf("UpdatePruneJob form = %v, want %v", call.form, update)
	}
	if call := fake.lastCall(t, "DELETE /config/prune/probe-prune"); len(call.query) != 0 || len(call.form) != 0 {
		t.Errorf("DeletePruneJob query = %v, form = %v, want neither", call.query, call.form)
	}
}

func TestVerifyJobCallsHitTheirRoutes(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /config/verify", http.StatusOK, `{"data":null}`)
	fake.reply("PUT /config/verify/probe-verify", http.StatusOK, `{"data":null}`)
	fake.reply("DELETE /config/verify/probe-verify", http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	create := url.Values{"id": {"probe-verify"}, "store": {"probe-b"}, "ignore-verified": {"true"}, "outdated-after": {"30"}}
	if err := c.CreateVerifyJob(ctx, create); err != nil {
		t.Fatalf("CreateVerifyJob() = %v", err)
	}
	update := url.Values{"schedule": {"weekly"}, "delete": {"max-depth", "ns"}}
	if err := c.UpdateVerifyJob(ctx, "probe-verify", update); err != nil {
		t.Fatalf("UpdateVerifyJob() = %v", err)
	}
	if err := c.DeleteVerifyJob(ctx, "probe-verify"); err != nil {
		t.Fatalf("DeleteVerifyJob() = %v", err)
	}

	want := []string{"POST /config/verify", "PUT /config/verify/probe-verify", "DELETE /config/verify/probe-verify"}
	if got := fake.routes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if call := fake.lastCall(t, "POST /config/verify"); !reflect.DeepEqual(call.form, create) {
		t.Errorf("CreateVerifyJob form = %v, want %v", call.form, create)
	}
	if call := fake.lastCall(t, "PUT /config/verify/probe-verify"); !reflect.DeepEqual(call.form, update) {
		t.Errorf("UpdateVerifyJob form = %v, want %v", call.form, update)
	}
	if call := fake.lastCall(t, "DELETE /config/verify/probe-verify"); len(call.query) != 0 || len(call.form) != 0 {
		t.Errorf("DeleteVerifyJob query = %v, form = %v, want neither", call.query, call.form)
	}
}

// A missing job is a 400 on read and delete alike, and a taken ID a 400 on
// create; the provider tells them apart.
func TestJobErrorsAreRecognised(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/prune/probe-missing", http.StatusBadRequest, "no such prune 'probe-missing'")
	fake.reply("DELETE /config/prune/probe-missing", http.StatusBadRequest, "no such prune 'probe-missing'")
	fake.reply("GET /config/verify/probe-missing", http.StatusBadRequest, "no such verification 'probe-missing'")
	fake.reply("DELETE /config/verify/probe-missing", http.StatusBadRequest, "no such verification 'probe-missing'")
	fake.reply("POST /config/prune", http.StatusBadRequest, "parameter verification failed - 'id': job 'probe-prune' already exists.")
	fake.reply("POST /config/verify", http.StatusBadRequest, "parameter verification failed - 'id': job 'probe-verify' already exists.")
	c := fake.client(t)
	ctx := context.Background()

	if job, err := c.GetPruneJob(ctx, "probe-missing"); !IsNotFound(err) || IsAlreadyExists(err) || job != (PruneJob{}) {
		t.Errorf("GetPruneJob() = %+v, %v, want only a not-found error", job, err)
	}
	if err := c.DeletePruneJob(ctx, "probe-missing"); !IsNotFound(err) {
		t.Errorf("DeletePruneJob() = %v, want a not-found error", err)
	}
	if job, err := c.GetVerifyJob(ctx, "probe-missing"); !IsNotFound(err) || IsAlreadyExists(err) || job != (VerifyJob{}) {
		t.Errorf("GetVerifyJob() = %+v, %v, want only a not-found error", job, err)
	}
	if err := c.DeleteVerifyJob(ctx, "probe-missing"); !IsNotFound(err) {
		t.Errorf("DeleteVerifyJob() = %v, want a not-found error", err)
	}

	err := c.CreatePruneJob(ctx, url.Values{"id": {"probe-prune"}, "store": {"probe-b"}, "schedule": {"daily"}})
	if !IsAlreadyExists(err) || IsNotFound(err) {
		t.Errorf("CreatePruneJob() = %v, want an already-exists error", err)
	}
	err = c.CreateVerifyJob(ctx, url.Values{"id": {"probe-verify"}, "store": {"probe-b"}})
	if !IsAlreadyExists(err) || IsNotFound(err) {
		t.Errorf("CreateVerifyJob() = %v, want an already-exists error", err)
	}
}
