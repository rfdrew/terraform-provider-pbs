package provider

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// newJobRunHarness serves POST /admin/<kind>/<id>/run, whose task is what
// next returns, with the worker type and ID PBS gives a run of that kind.
func newJobRunHarness(t *testing.T, kind, id string, next func() *fakeTask, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeTasks) {
	t.Helper()
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	fake.handle("POST /admin/"+kind+"/"+id+"/run", tasks.starter(func(*http.Request) *fakeTask {
		task := next()
		switch kind {
		case "sync":
			task.workerType, task.workerID = "syncjob", `remote1\x3astore2\x3astore1\x3a\x3a`+strings.ReplaceAll(id, "-", `\x2d`)
		case "verify":
			task.workerType, task.workerID = "verificationjob", `store1\x3a`+strings.ReplaceAll(id, "-", `\x2d`)
		case "prune":
			task.workerType, task.workerID = "prunejob", "store1"
		}
		return task
	}))
	return newProtocolHarness(t, fake, opts...), fake, tasks
}

// Each action runs its job through the run route of its kind, once, and
// reports progress from the task's log.
func TestJobRunActionsRunTheirJob(t *testing.T) {
	for _, tc := range []struct{ action, kind, logLine string }{
		{"pbs_sync_job_run", "sync", "percentage done: 100.00% (1/1 groups)"},
		{"pbs_verify_job_run", "verify", "percentage done: 100.00% (2/2 snapshots)"},
		{"pbs_prune_job_run", "prune", "retention options: --keep-daily 7"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			h, fake, tasks := newJobRunHarness(t, tc.kind, "nightly-1", func() *fakeTask {
				return &fakeTask{running: 1, log: []string{"starting", tc.logLine}}
			})
			got := h.invokeAction(t, tc.action, map[string]any{"id": "nightly-1"})
			requireNoProtocolErrors(t, got.diagnostics)
			requireProgressContaining(t, got, "PBS started task UPID:pbs-tasks:")
			requireProgressContaining(t, got, tc.logLine)
			route := "POST /admin/" + tc.kind + "/nightly-1/run"
			if fake.count(route) != 1 || len(tasks.all()) != 1 {
				t.Fatalf("routes: %v", fake.routes())
			}
			// The action waited for the task it started to end.
			upid := strings.TrimPrefix(got.progress[0], "PBS started task ")
			if task := tasks.task(upid); task == nil || !task.stopped {
				t.Fatalf("task %s: %+v", upid, task)
			}
			if call := fake.lastCall(t, route); len(call.form) != 0 {
				t.Fatalf("the run sent parameters: %v", call.form)
			}
			for _, r := range fake.routes() {
				if strings.HasPrefix(r, "POST ") && r != route {
					t.Fatalf("unexpected call %s; routes: %v", r, fake.routes())
				}
			}
		})
	}
}

// A sync's summary lines come at the end of its log, after the latest line
// the progress forwards; the action forwards them once the task has ended.
func TestSyncJobRunActionReportsSummary(t *testing.T) {
	h, _, _ := newJobRunHarness(t, "sync", "pull-offsite", func() *fakeTask {
		return &fakeTask{log: []string{
			"Starting datastore sync job 'remote1:store2:store1::pull-offsite'",
			"sync datastore 'store1' from 'remote1/store2'",
			"percentage done: 100.00% (3/3 groups)",
			"Summary: sync job pulled 1.5 GiB in 312 chunks (average rate: 52.3 MiB/s)",
			"Summary: removed vanished: snapshots: 2, groups: 1, namespaces: 0",
			"sync job 'remote1:store2:store1::pull-offsite' end",
		}}
	})
	got := h.invokeAction(t, "pbs_sync_job_run", map[string]any{"id": "pull-offsite"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "Summary: sync job pulled 1.5 GiB in 312 chunks")
	requireProgressContaining(t, got, "Summary: removed vanished: snapshots: 2, groups: 1, namespaces: 0")
}

// A sync that fails in its task — here because the target datastore is not
// mounted, which PBS checks only there — fails the action with the end of
// the log, and reports no summary.
func TestSyncJobRunActionTaskFails(t *testing.T) {
	h, _, _ := newJobRunHarness(t, "sync", "pull-offsite", func() *fakeTask {
		return &fakeTask{
			log:  []string{"Starting datastore sync job 'remote1:store2:store1::pull-offsite'"},
			exit: "datastore 'store1' is not mounted",
		}
	})
	got := h.invokeAction(t, "pbs_sync_job_run", map[string]any{"id": "pull-offsite"})
	requireProtocolErrorContaining(t, got.diagnostics, `PBS sync job "pull-offsite" failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "TASK ERROR: datastore 'store1' is not mounted")
	for _, message := range got.progress {
		if strings.HasPrefix(message, "Summary:") {
			t.Fatalf("a failed sync reported a summary: %q", got.progress)
		}
	}
}

// A verification that finds damaged backups fails, and the end of its log
// names them.
func TestVerifyJobRunActionFailedBackups(t *testing.T) {
	h, _, _ := newJobRunHarness(t, "verify", "weekly", func() *fakeTask {
		return &fakeTask{
			log: []string{
				"Starting datastore verify job 'store1:weekly'",
				"verify store1:vm/100/2026-11-01T10:00:00Z",
				"  check drive-scsi0.img.fidx",
				"chunk 0123abcd was marked as corrupt",
				"Failed to verify the following snapshots/groups:",
				"\tvm/100/2026-11-01T10:00:00Z",
			},
			exit: "verification failed - please check the log for details",
		}
	})
	got := h.invokeAction(t, "pbs_verify_job_run", map[string]any{"id": "weekly"})
	requireProtocolErrorContaining(t, got.diagnostics, `PBS verify job "weekly" failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "verification failed - please check the log for details")
	requireProtocolErrorContaining(t, got.diagnostics, "vm/100/2026-11-01T10:00:00Z")
}

func TestVerifyJobRunActionWarnings(t *testing.T) {
	h, _, _ := newJobRunHarness(t, "verify", "weekly", func() *fakeTask {
		return &fakeTask{log: []string{"verify store1:vm/100/2026-11-01T10:00:00Z", "could not read the manifest's owner"}, exit: "WARNINGS: 1"}
	})
	got := h.invokeAction(t, "pbs_verify_job_run", map[string]any{"id": "weekly"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, `PBS verify job "weekly" ended with warnings`)
	requireProtocolWarningContaining(t, got.diagnostics, "TASK WARNINGS: 1")
}

// The prune's summary counts the lines of its log, as PBS 4.2 writes them.
func TestPruneJobRunActionReportsSummary(t *testing.T) {
	h, _, _ := newJobRunHarness(t, "prune", "daily", func() *fakeTask {
		return &fakeTask{running: 1, exit: "WARNINGS: 1", log: []string{
			"prune job 'daily'",
			"Starting datastore prune on datastore 'store1', root namespace, down to full depth",
			"retention options: --keep-last 2",
			`Pruning group :"vm/100"`,
			"remove vm/100/2026-11-01T10:00:00Z",
			"remove vm/100/2026-11-02T10:00:00Z",
			"keep protected vm/100/2026-11-03T10:00:00Z",
			"keep vm/100/2026-11-04T10:00:00Z",
			"keep vm/100/2026-11-05T10:00:00Z",
			`Pruning group dept1:"ct/200"`,
			"remove ct/200/2026-11-01T10:00:00Z",
			`failed to remove dir "ct/200/2026-11-01T10:00:00Z": Device or resource busy`,
			"keep ct/200/2026-11-04T10:00:00Z",
		}}
	})
	got := h.invokeAction(t, "pbs_prune_job_run", map[string]any{"id": "daily"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "Device or resource busy")
	requireProgressContaining(t, got, "pruned 2 backup groups: kept 5 backups, removed 2, failed to remove 1")
}

// A prune whose log is longer than one read is read to its end.
func TestPruneJobRunActionReadsLongLogs(t *testing.T) {
	log := []string{"prune job 'daily'", "retention options: --keep-last 1", `Pruning group :"host/web"`}
	for i := range pruneLogPage + 10 {
		mark := "remove"
		if i == 0 {
			mark = "keep"
		}
		log = append(log, fmt.Sprintf("%s host/web/2026-%02d-%02dT%02d:%02d:00Z", mark, 1+i/(28*24*60)%12, 1+i/(24*60)%28, i/60%24, i%60))
	}
	h, fake, _ := newJobRunHarness(t, "prune", "daily", func() *fakeTask { return &fakeTask{log: log} })
	got := h.invokeAction(t, "pbs_prune_job_run", map[string]any{"id": "daily"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, fmt.Sprintf("pruned 1 backup group: kept 1 backup, removed %d", pruneLogPage+9))
	// The last read is the second page.
	var logRoute string
	for _, route := range fake.routes() {
		if strings.HasSuffix(route, "/log") {
			logRoute = route
		}
	}
	query := fake.lastCall(t, logRoute).query
	if query.Get("start") != fmt.Sprint(pruneLogPage+1) || query.Get("limit") != fmt.Sprint(pruneLogPage) {
		t.Fatalf("last log read: %v", query)
	}
}

func TestPruneSummary(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  []string
		want string
	}{
		{"nothing to prune", []string{"prune job 'daily'", "retention options: --keep-last 2"}, "found no backup groups to prune"},
		{
			// PBS 4.0 marks protected and partial backups otherwise.
			"PBS 4.0", []string{
				`Pruning group :"vm/100"`, "protected vm/100/2026-11-01T10:00:00Z", "keep-partial vm/100/2026-11-02T10:00:00Z",
				"remove vm/100/2026-11-03T10:00:00Z", "keep vm/100/2026-11-04T10:00:00Z",
			},
			"pruned 1 backup group: kept 3 backups, removed 1",
		},
		{
			"newer marks", []string{
				`Pruning group :"vm/100"`, "keep partial vm/100/2026-11-01T10:00:00Z",
				"keep since timestamp in future vm/100/2099-01-01T10:00:00Z", "remove vm/100/2026-11-03T10:00:00Z",
			},
			"pruned 1 backup group: kept 2 backups, removed 1",
		},
		{
			// Without retention options, PBS marks every backup for removal
			// and keeps them all.
			"keep all", []string{
				"No prune selection - keeping all files.", `Pruning group :"vm/100"`, "remove vm/100/2026-11-01T10:00:00Z",
				"remove vm/100/2026-11-02T10:00:00Z", `Pruning group :"vm/101"`, "remove vm/101/2026-11-02T10:00:00Z",
			},
			"pruned 2 backup groups: kept 3 backups, removed 0",
		},
		{
			// Lines that merely look alike are not counted.
			"other lines", []string{
				`Pruning group :"vm/100"`, "remove the lock", "keep going", "remove vm/100/2026-11-01T10:00:00Z",
			},
			"pruned 1 backup group: kept 0 backups, removed 1",
		},
	} {
		var summary pruneSummary
		for _, message := range tc.log {
			summary.count(message)
		}
		if got := summary.String(); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// With wait = false the action ends once the task has started, without
// polling it or reporting on it.
func TestJobRunActionWithoutWaiting(t *testing.T) {
	h, fake, _ := newJobRunHarness(t, "prune", "daily", func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_prune_job_run", map[string]any{"id": "daily", "wait": false})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "not waiting for it")
	for _, route := range fake.routes() {
		if strings.Contains(route, "/tasks/") {
			t.Fatalf("followed the task: %v", fake.routes())
		}
	}
}

// A timeout ends the wait, not the task: a verification goes on in PBS.
func TestJobRunActionTimeout(t *testing.T) {
	h, _, tasks := newJobRunHarness(t, "verify", "weekly", func() *fakeTask { return &fakeTask{running: -1} })
	got := h.invokeAction(t, "pbs_verify_job_run", map[string]any{"id": "weekly", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, `PBS verify job "weekly" did not finish`)
	requireProtocolErrorContaining(t, got.diagnostics, "The task goes on in PBS")
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the task was asked to stop")
		}
	}
}

func TestJobRunActionStartErrors(t *testing.T) {
	const lockError = `Unable to acquire lock "/var/lib/proxmox-backup/jobstates/%s-%s.lck" - Interrupted system call (os error 4)`
	for _, tc := range []struct {
		name, action, kind, id string
		status                 int
		body, want             string
	}{
		{"sync missing", "pbs_sync_job_run", "sync", "pull-offsite", 400, "no such sync 'pull-offsite'", `PBS has no sync job "pull-offsite"`},
		{"verify missing", "pbs_verify_job_run", "verify", "weekly", 400, "no such verification 'weekly'", `PBS has no verify job "weekly"`},
		{"prune missing", "pbs_prune_job_run", "prune", "daily", 400, "no such prune 'daily'", `PBS has no prune job "daily"`},
		{"datastore gone", "pbs_verify_job_run", "verify", "weekly", 400, "no such datastore 'store1'", "PBS keeps the jobs of a datastore deleted with `keep_job_configs`"},
		{"unmounted", "pbs_verify_job_run", "verify", "weekly", 400, "datastore 'store1' is not mounted", "a removable datastore must be mounted"},
		{"maintenance", "pbs_prune_job_run", "prune", "daily", 400, "datastore 'store1' is unavailable: read-only maintenance mode: ", "`read-only` a prune"},
		{"sync running", "pbs_sync_job_run", "sync", "pull-offsite", 400, fmt.Sprintf(lockError, "syncjob", "pull-offsite"), `PBS sync job "pull-offsite" is running already`},
		{"prune running", "pbs_prune_job_run", "prune", "daily", 400, fmt.Sprintf(lockError, "prunejob", "daily"), "PBS runs one instance of a job at a time"},
		{"verify privilege", "pbs_verify_job_run", "verify", "weekly", 400, "missing permissions 'Datastore.Verify' on '/datastore/store1'", "lacks a privilege that running the job needs: Datastore.Verify on /datastore/<store>[/<ns>]"},
		{"prune privilege", "pbs_prune_job_run", "prune", "daily", 400, "missing permissions 'Datastore.Modify' on '/datastore/store1/dept1'", "Datastore.Modify on /datastore/<store>[/<ns>]"},
		{"forbidden", "pbs_prune_job_run", "prune", "daily", 403, "permission check failed", "Datastore.Modify on /datastore/<store>[/<ns>]"},
		{"same datastore", "pbs_sync_job_run", "sync", "pull-offsite", 400, "can't sync to same datastore", "can't sync to same datastore"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("POST /admin/"+tc.kind+"/"+tc.id+"/run", tc.status, tc.body)
			h := newProtocolHarness(t, fake)
			got := h.invokeAction(t, tc.action, map[string]any{"id": tc.id})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to run PBS ")
			requireProtocolErrorContaining(t, got.diagnostics, tc.want)
			// PBS's own words come last; the client trims them.
			requireProtocolErrorContaining(t, got.diagnostics, strings.TrimSpace(tc.body))
			if tc.status == 403 || strings.HasPrefix(tc.body, "missing permissions") {
				requireProtocolErrorContaining(t, got.diagnostics, "An API token has no privileges of its own")
			}
		})
	}
}

// PBS's error names no privilege of a sync job, whose privileges depend on
// its direction: the action reads the job to name them, and names both
// directions' when it may not read the job either.
func TestSyncJobRunActionPrivileges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		job    string
		want   []string
	}{
		{"pull", 200, `{"data":{"id":"pull-offsite","store":"store1","remote":"remote1","remote-store":"store2"}}`,
			[]string{"Datastore.Audit and Datastore.Backup on /datastore/store1", "Remote.Read on /remote/remote1/store2"}},
		{"local pull", 200, `{"data":{"id":"pull-offsite","store":"store1","ns":"dept1","remote-store":"store2","remote-ns":"site-a"}}`,
			[]string{"on /datastore/store1/dept1", "Datastore.Read on /datastore/store2/site-a"}},
		{"push", 200, `{"data":{"id":"pull-offsite","sync-direction":"push","store":"store1","remote":"offsite","remote-store":"store2","remote-ns":"site-a"}}`,
			[]string{"on /remote/offsite/store2/site-a", "Datastore.Read on /datastore/store1"}},
		{"unreadable", 403, "permission check failed",
			[]string{"to pull, Datastore.Audit and Datastore.Backup", "to push, Remote.DatastoreBackup"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("POST /admin/sync/pull-offsite/run", 400, "permission check failed, 'tfacc@pbs!acc' is missing access")
			fake.reply("GET /config/sync/pull-offsite", tc.status, tc.job)
			h := newProtocolHarness(t, fake)
			got := h.invokeAction(t, "pbs_sync_job_run", map[string]any{"id": "pull-offsite"})
			requireProtocolErrorContaining(t, got.diagnostics, `"tfacc@pbs!acc" lacks a privilege that running the job needs`)
			requireProtocolErrorContaining(t, got.diagnostics, "is missing access")
			for _, want := range tc.want {
				requireProtocolErrorContaining(t, got.diagnostics, want)
			}
		})
	}
}

func TestJobRunActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, action := range []string{"pbs_sync_job_run", "pbs_verify_job_run", "pbs_prune_job_run"} {
		for _, tc := range []struct {
			attrs map[string]any
			want  string
		}{
			{map[string]any{"id": "x"}, "id"},
			{map[string]any{"id": "-daily"}, "id"},
			{map[string]any{"id": "daily", "timeout": "0s"}, "positive duration"},
		} {
			diags := h.validateAction(t, action, h.actionValue(t, action, tc.attrs))
			requireProtocolErrorContaining(t, diags, tc.want)
		}
		// Values only known at apply, such as the ID of a job created in
		// the same run, are fine while planning, which calls no PBS.
		config := h.actionValue(t, action, map[string]any{"id": tfUnknown, "wait": tfUnknown, "timeout": tfUnknown})
		requireNoProtocolErrors(t, h.validateAction(t, action, config))
		requireNoProtocolErrors(t, h.planAction(t, action, config))
	}
}
