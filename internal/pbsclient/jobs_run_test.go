package pbsclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// Each kind of job runs through POST /admin/<kind>/<id>/run, which answers
// the UPID of the run's task.
func TestRunJobs(t *testing.T) {
	for _, tc := range []struct {
		route, upid string
		run         func(*Client, context.Context, string) (UPID, error)
	}{
		{"POST /admin/sync/pull-offsite/run", `UPID:pbs-acc:00000A1B:00001327:00000004:6AE11CDF:syncjob:remote1\x3astore2\x3astore1\x3a\x3apull\x2doffsite:tfacc@pbs!acc:`, (*Client).RunSyncJob},
		{"POST /admin/verify/pull-offsite/run", `UPID:pbs-acc:00000A1B:00001327:00000005:6AE11CDF:verificationjob:store1\x3apull\x2doffsite:tfacc@pbs!acc:`, (*Client).RunVerifyJob},
		{"POST /admin/prune/pull-offsite/run", `UPID:pbs-acc:00000A1B:00001327:00000006:6AE11CDF:prunejob:store1:tfacc@pbs!acc:`, (*Client).RunPruneJob},
	} {
		t.Run(tc.route, func(t *testing.T) {
			f := newFakePBS()
			encoded, _ := json.Marshal(map[string]string{"data": tc.upid})
			f.reply(tc.route, http.StatusOK, string(encoded))
			upid, err := tc.run(f.client(t), context.Background(), "pull-offsite")
			if err != nil {
				t.Fatal(err)
			}
			if upid.Raw != tc.upid {
				t.Fatalf("UPID = %q", upid.Raw)
			}
			if call := f.lastCall(t, tc.route); len(call.form) != 0 {
				t.Fatalf("the run sent parameters: %v", call.form)
			}
		})
	}
}

// PBS answers a run of a job that is running only after waiting 10 s for its
// lock, so the call may take longer than a short request timeout allows.
func TestJobRunRequestTimeout(t *testing.T) {
	for _, tc := range []struct {
		configured, want time.Duration
	}{
		{5 * time.Second, jobRunRequestTimeout},
		{DefaultTimeout, DefaultTimeout},
		{2 * time.Minute, 2 * time.Minute},
		// No limit stays no limit.
		{0, 0},
	} {
		c, err := New(Options{Endpoint: "https://pbs.test:8007", APIToken: fakeAPIToken, Transport: newFakePBS()})
		if err != nil {
			t.Fatal(err)
		}
		c.httpClient.Timeout = tc.configured
		if got := c.httpClientFor(c.jobRunContext(context.Background())).Timeout; got != tc.want {
			t.Errorf("request timeout %s: a run may take %s, want %s", tc.configured, got, tc.want)
		}
	}
}

func TestRunJobErrors(t *testing.T) {
	for _, tc := range []struct {
		status          int
		body            string
		notFound        bool
		privilege       bool
		alreadyRunning  bool
		datastoreClosed bool
	}{
		{status: 400, body: "no such sync 'pull-offsite'", notFound: true},
		{status: 400, body: "no such verification 'pull-offsite'", notFound: true},
		{status: 400, body: "no such prune 'pull-offsite'", notFound: true},
		{status: 400, body: "missing permissions 'Datastore.Verify' on '/datastore/store1/dept1'", privilege: true},
		{status: 400, body: "permission check failed, 'tfacc@pbs!acc' is missing access", privilege: true},
		{status: 400, body: `Unable to acquire lock "/var/lib/proxmox-backup/jobstates/syncjob-pull-offsite.lck" - Interrupted system call (os error 4)`, alreadyRunning: true},
		{status: 400, body: "datastore 'store1' is not mounted", datastoreClosed: true},
		{status: 400, body: "datastore 'store1' is unavailable: offline maintenance mode: disk swap", datastoreClosed: true},
		{status: 400, body: "datastore 'store1' is unavailable: read-only maintenance mode: ", datastoreClosed: true},
		// The router's own check is a 403, which IsForbidden reports.
		{status: 403, body: "permission check failed"},
		{status: 400, body: "can't sync to same datastore"},
	} {
		f := newFakePBS()
		f.reply("POST /admin/sync/pull-offsite/run", tc.status, tc.body)
		_, err := f.client(t).RunSyncJob(context.Background(), "pull-offsite")
		if err == nil {
			t.Fatalf("%q: no error", tc.body)
		}
		if IsNotFound(err) != tc.notFound || IsPrivilegeMissing(err) != tc.privilege ||
			IsTaskAlreadyRunning(err) != tc.alreadyRunning || IsDatastoreUnavailable(err) != tc.datastoreClosed {
			t.Errorf("%d %q: not found %v, privilege missing %v, already running %v, datastore unavailable %v",
				tc.status, tc.body, IsNotFound(err), IsPrivilegeMissing(err), IsTaskAlreadyRunning(err), IsDatastoreUnavailable(err))
		}
	}
	if IsPrivilegeMissing(errors.New("missing permissions 'Datastore.Verify'")) {
		t.Error("an error that is not PBS's counts as a missing privilege")
	}
}

// The sync job list holds pull jobs only unless asked for all; the others
// take no parameters.
func TestListJobRunStatuses(t *testing.T) {
	f := newFakePBS()
	f.reply("GET /admin/sync", http.StatusOK, `{"data":[
		{"id":"pull-offsite","store":"store1","remote-store":"store2","schedule":"daily","next-run":1900000000,
		 "last-run-upid":"UPID:pbs-acc:00000A1B:00001327:00000004:6AE11CDF:syncjob:x:root@pam:",
		 "last-run-state":"OK","last-run-endtime":1899990000},
		{"id":"push-offsite","store":"store1","remote-store":"store2","sync-direction":"push",
		 "last-run-upid":"UPID:pbs-acc:00000A1B:00001327:00000005:6AE11CDF:syncjob:y:root@pam:"},
		{"id":"never","store":"store1","remote-store":"store2"}]}`)
	f.reply("GET /admin/verify", http.StatusOK, `{"data":[]}`)

	c := f.client(t)
	jobs, err := c.ListJobRunStatuses(context.Background(), JobKindSync)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.lastCall(t, "GET /admin/sync").query.Get("sync-direction"); got != "all" {
		t.Fatalf("sync-direction = %q", got)
	}
	if len(jobs) != 3 || jobs[0].ID != "pull-offsite" || jobs[0].LastRunState != "OK" ||
		jobs[0].NextRun == nil || *jobs[0].NextRun != 1900000000 || jobs[0].LastRunEndtime == nil {
		t.Fatalf("jobs = %+v", jobs)
	}
	if jobs[0].Running() || !jobs[1].Running() || jobs[2].Running() {
		t.Fatalf("running: %v %v %v", jobs[0].Running(), jobs[1].Running(), jobs[2].Running())
	}

	if _, err := c.ListJobRunStatuses(context.Background(), JobKindVerify); err != nil {
		t.Fatal(err)
	}
	if query := f.lastCall(t, "GET /admin/verify").query; len(query) != 0 {
		t.Fatalf("the verify job list sent %v", query)
	}
}
