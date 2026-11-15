package provider

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const verifyActionRoute = "POST /admin/datastore/store1/verify"

// newVerifyHarness serves verifications of datastore store1 whose task is
// what next returns, with the worker type and ID PBS gives the task of what
// the form asks for.
func newVerifyHarness(t *testing.T, next func() *fakeTask, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeTasks) {
	t.Helper()
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	fake.handle(verifyActionRoute, tasks.starter(func(req *http.Request) *fakeTask {
		_ = req.ParseForm()
		task := next()
		task.workerType, task.workerID = "verify", "store1"
		if ns := req.PostForm.Get("ns"); ns != "" {
			task.workerID += `\x3a` + strings.ReplaceAll(ns, "/", `\x2f`)
		}
		switch {
		case req.PostForm.Has("backup-time"):
			task.workerType = "verify_snapshot"
		case req.PostForm.Has("backup-id"):
			task.workerType = "verify_group"
		}
		return task
	}))
	return newProtocolHarness(t, fake, opts...), fake, tasks
}

// verifyLog is a task's log: the messages, as PBS writes them.
func verifyLog(messages ...string) func() *fakeTask {
	return func() *fakeTask { return &fakeTask{log: messages} }
}

// The action sends what is set, under PBS's names, and nothing else, so that
// PBS's defaults apply; a single backup is verified again unless
// ignore_verified or outdated_after says otherwise.
func TestDatastoreVerifyActionParameters(t *testing.T) {
	backupTime := time.Date(2026, 11, 14, 2, 0, 5, 0, time.UTC).Unix()
	for _, tc := range []struct {
		name  string
		attrs map[string]any
		want  url.Values
	}{
		{"datastore", map[string]any{}, url.Values{}},
		{"namespace", map[string]any{"ns": "dept1/hosts", "max_depth": 0}, url.Values{"ns": {"dept1/hosts"}, "max-depth": {"0"}}},
		{"group", map[string]any{"group": "vm/100"}, url.Values{"backup-type": {"vm"}, "backup-id": {"100"}}},
		{
			"snapshot", map[string]any{"ns": "dept1", "snapshot": "ct/web.1/2026-11-14T02:00:05Z"},
			url.Values{
				"ns": {"dept1"}, "backup-type": {"ct"}, "backup-id": {"web.1"}, "backup-time": {fmt.Sprint(backupTime)},
				"ignore-verified": {"false"},
			},
		},
		{
			"snapshot, ignoring verified", map[string]any{"snapshot": "vm/100/2026-11-14T02:00:05Z", "ignore_verified": true, "outdated_after": 7},
			url.Values{
				"backup-type": {"vm"}, "backup-id": {"100"}, "backup-time": {fmt.Sprint(backupTime)},
				"ignore-verified": {"true"}, "outdated-after": {"7"},
			},
		},
		{
			// outdated_after alone keeps PBS's default ignore-verified,
			// without which PBS would ignore it.
			"snapshot, outdated after", map[string]any{"snapshot": "vm/100/2026-11-14T02:00:05Z", "outdated_after": 7},
			url.Values{
				"backup-type": {"vm"}, "backup-id": {"100"}, "backup-time": {fmt.Sprint(backupTime)},
				"outdated-after": {"7"},
			},
		},
		{
			"options", map[string]any{"ignore_verified": false, "outdated_after": 30, "read_threads": 2, "verify_threads": 8},
			url.Values{"ignore-verified": {"false"}, "outdated-after": {"30"}, "read-threads": {"2"}, "verify-threads": {"8"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, fake, _ := newVerifyHarness(t, verifyLog())
			tc.attrs["store"] = "store1"
			got := h.invokeAction(t, "pbs_datastore_verify", tc.attrs)
			requireNoProtocolErrors(t, got.diagnostics)
			if form := fake.lastCall(t, verifyActionRoute).form; !reflect.DeepEqual(form, tc.want) {
				t.Fatalf("form = %v, want %v", form, tc.want)
			}
			if fake.count(verifyActionRoute) != 1 {
				t.Fatalf("routes: %v", fake.routes())
			}
		})
	}
}

// The summary depends on what the action verifies, and counts the lines of
// the log as PBS writes them.
func TestDatastoreVerifyActionSummaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]any
		log   []string
		want  string
	}{
		{
			"datastore", map[string]any{}, []string{
				"verify datastore store1", "found 2 groups",
				"verify group store1:ct/200 (1 snapshots)",
				"SKIPPED: verify store1:ct/200/2026-11-01T10:00:00Z (recently verified)",
				"percentage done: 50.00% (1/2 groups)",
				"verify group store1:vm/100 (2 snapshots)",
				"verify store1:vm/100/2026-11-02T10:00:00Z", "  check index.json.blob", "  check drive-scsi0.img.fidx",
				"  verified 1024.00/2048.00 MiB in 3.20 seconds, speed 320.00/640.00 MiB/s (0 errors)",
				"percentage done: 75.00% (1/2 groups, 1/2 snapshots in group #2)",
				"verify store1:vm/100/2026-11-01T10:00:00Z", "  check index.json.blob",
				"percentage done: 100.00% (2/2 groups)",
			},
			"verified 2 backups in 2 backup groups; skipped 1 verified before",
		},
		{
			// With Datastore.Backup only, PBS says whose backups it
			// verified; a group and a backup that vanished during the run
			// are counted.
			"owner", map[string]any{"ns": "dept1"}, []string{
				"verify datastore store1", "limiting to backups owned by tfacc@pbs!acc", "found 3 groups",
				"verify datastore 'store1', namespace 'dept1', group ct/200 - unable to list backups: ENOENT: No such file or directory",
				"verify group store1:vm/100 (2 snapshots)",
				"SKIPPED: verify store1:vm/100/2026-11-01T10:00:00Z - snapshot does not exist (anymore).",
				"verify store1:vm/100/2026-11-02T10:00:00Z",
				"verify group store1:vm/101 (1 snapshots)",
				"SKIPPED: verify store1:vm/101/2026-11-02T10:00:00Z - could not acquire snapshot lock: unable to acquire lock",
			},
			"verified 1 backup in 3 backup groups; skipped 1 in use; 1 backup group and 1 backup vanished during the run" +
				" (only the backups owned by tfacc@pbs!acc, where it lacks Datastore.Verify)",
		},
		{"nothing", map[string]any{"ns": "dept1"}, []string{"verify datastore store1", "found 0 groups"}, "found no backup groups to verify"},
		{
			// A group logs no "found" line.
			"group", map[string]any{"group": "vm/100"}, []string{
				"verify group store1:vm/100 (3 snapshots)",
				"verify store1:vm/100/2026-11-03T10:00:00Z", "percentage done: 33.33% (0/1 groups, 1/3 snapshots in group #1)",
				"SKIPPED: verify store1:vm/100/2026-11-02T10:00:00Z (recently verified)",
				"SKIPPED: verify store1:vm/100/2026-11-01T10:00:00Z - snapshot does not exist (anymore).",
			},
			"verified 1 backup of backup group vm/100; skipped 1 verified before; 1 backup vanished during the run",
		},
		{
			// A single backup logs neither a "found" nor a "verify group"
			// line.
			"snapshot", map[string]any{"snapshot": "vm/100/2026-11-03T10:00:00Z"}, []string{
				"verify store1:vm/100/2026-11-03T10:00:00Z", "  check index.json.blob", "  check drive-scsi0.img.fidx",
				"  verified 10.00/20.00 MiB in 0.20 seconds, speed 50.00/100.00 MiB/s (0 errors)",
			},
			"verified backup vm/100/2026-11-03T10:00:00Z",
		},
		{
			"snapshot verified before", map[string]any{"snapshot": "vm/100/2026-11-03T10:00:00Z", "ignore_verified": true},
			[]string{"SKIPPED: verify store1:vm/100/2026-11-03T10:00:00Z (recently verified)"},
			"skipped backup vm/100/2026-11-03T10:00:00Z: verified before, and ignore_verified is true",
		},
		{
			"snapshot verified lately", map[string]any{"snapshot": "vm/100/2026-11-03T10:00:00Z", "outdated_after": 7},
			[]string{"SKIPPED: verify store1:vm/100/2026-11-03T10:00:00Z (recently verified)"},
			"skipped backup vm/100/2026-11-03T10:00:00Z: verified before, and outdated_after has not passed since",
		},
		{
			"snapshot in use", map[string]any{"snapshot": "vm/100/2026-11-03T10:00:00Z"},
			[]string{"SKIPPED: verify store1:vm/100/2026-11-03T10:00:00Z - could not acquire snapshot lock: unable to acquire lock"},
			"skipped backup vm/100/2026-11-03T10:00:00Z: it is in use, and PBS could not lock it",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := newVerifyHarness(t, func() *fakeTask { return &fakeTask{running: 1, log: tc.log} })
			tc.attrs["store"] = "store1"
			got := h.invokeAction(t, "pbs_datastore_verify", tc.attrs)
			requireNoProtocolErrors(t, got.diagnostics)
			for _, d := range got.diagnostics {
				t.Errorf("unexpected diagnostic: %s: %s", d.Summary, d.Detail)
			}
			if last := got.progress[len(got.progress)-1]; last != tc.want {
				t.Fatalf("summary %q, want %q; progress: %q", last, tc.want, got.progress)
			}
			for _, message := range got.progress {
				if strings.Contains(message, "TASK OK") {
					t.Fatalf("the result line was forwarded: %q", got.progress)
				}
			}
		})
	}
}

// Lines that merely look like those the summary counts are not counted.
func TestVerifySummaryIgnoresOtherLines(t *testing.T) {
	summary := &verifySummary{mode: verifyAll, found: -1}
	for _, message := range []string{
		"verify datastore store1",
		"verify store1:vm/100/2026-11-03T10:00:00Z - manifest load error: ENOENT",
		"verify store1:vm/100/2026-11-03T10:00:00Z/drive-scsi0.img.fidx failed: chunk 0123 was marked as corrupt",
		"verify group store1:vm/100",
		"found some groups",
		"SKIPPED: verify something else",
		"using 1 read and 4 verify thread(s)",
	} {
		summary.count(message)
	}
	if got := summary.String(); got != "found no backup groups to verify" {
		t.Fatalf("summary %q", got)
	}
}

// A group or a backup that does not exist ends PBS's task OK; the action
// warns, since saying nothing would look like a verification.
func TestDatastoreVerifyActionMissingBackups(t *testing.T) {
	t.Run("group", func(t *testing.T) {
		h, _, _ := newVerifyHarness(t, verifyLog(
			"verify datastore 'store1', namespace 'dept1', group vm/999 - unable to list backups: ENOENT: No such file or directory"))
		got := h.invokeAction(t, "pbs_datastore_verify", map[string]any{"store": "store1", "ns": "dept1", "group": "vm/999"})
		requireNoProtocolErrors(t, got.diagnostics)
		requireProtocolWarningContaining(t, got.diagnostics, "PBS found no backup group to verify")
		requireProtocolWarningContaining(t, got.diagnostics, `backup group "vm/999" in namespace "dept1" of PBS datastore "store1"`)
		requireProtocolWarningContaining(t, got.diagnostics, "unable to list backups")
		requireProgressContaining(t, got, "found no backup group vm/999 to verify")
	})
	t.Run("snapshot", func(t *testing.T) {
		h, _, _ := newVerifyHarness(t, verifyLog(
			"SKIPPED: verify store1:vm/100/2026-11-14T02:00:05Z - snapshot does not exist (anymore)."))
		got := h.invokeAction(t, "pbs_datastore_verify", map[string]any{"store": "store1", "snapshot": "vm/100/2026-11-14T02:00:05Z"})
		requireNoProtocolErrors(t, got.diagnostics)
		requireProtocolWarningContaining(t, got.diagnostics, "PBS found no backup to verify")
		requireProtocolWarningContaining(t, got.diagnostics, "the backup's time in UTC")
		requireProgressContaining(t, got, "found no backup vm/100/2026-11-14T02:00:05Z to verify")
	})
	// In a verification of a datastore, the same lines are about groups and
	// backups that vanished during the run: no warning.
	t.Run("vanished", func(t *testing.T) {
		h, _, _ := newVerifyHarness(t, verifyLog(
			"verify datastore store1", "found 1 groups",
			"verify datastore 'store1', root namespace, group vm/999 - unable to list backups: ENOENT: No such file or directory"))
		got := h.invokeAction(t, "pbs_datastore_verify", map[string]any{"store": "store1"})
		requireNoProtocolErrors(t, got.diagnostics)
		if len(got.diagnostics) != 0 {
			t.Fatalf("diagnostics: %v", got.diagnostics)
		}
		requireProgressContaining(t, got, "verified 0 backups in 1 backup group; 1 backup group vanished during the run")
	})
}

// A backup that fails verification fails the action, with the end of the
// log, where PBS names it; no summary follows.
func TestDatastoreVerifyActionFails(t *testing.T) {
	h, _, _ := newVerifyHarness(t, func() *fakeTask {
		return &fakeTask{
			log: []string{
				"verify datastore store1", "found 1 groups", "verify group store1:vm/100 (1 snapshots)",
				"verify store1:vm/100/2026-11-01T10:00:00Z", "  check drive-scsi0.img.fidx",
				"verify store1:vm/100/2026-11-01T10:00:00Z/drive-scsi0.img.fidx failed: chunk 0123abcd was marked as corrupt",
				"Failed to verify the following snapshots/groups:", "\tvm/100/2026-11-01T10:00:00Z",
			},
			exit: "verification failed - please check the log for details",
		}
	})
	got := h.invokeAction(t, "pbs_datastore_verify", map[string]any{"store": "store1"})
	requireProtocolErrorContaining(t, got.diagnostics, `Verification of PBS datastore "store1" failed`)
	requireProtocolErrorContaining(t, got.diagnostics, "verification failed - please check the log for details")
	requireProtocolErrorContaining(t, got.diagnostics, "\tvm/100/2026-11-01T10:00:00Z")
	for _, message := range got.progress {
		if strings.HasPrefix(message, "verified ") {
			t.Fatalf("a failed verification reported a summary: %q", got.progress)
		}
	}
}

func TestDatastoreVerifyActionStartErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		attrs  map[string]any
		status int
		body   string
		want   []string
	}{
		{
			"forbidden", map[string]any{"ns": "dept1"}, 403,
			"permission check failed - missing Datastore.Verify|Datastore.Backup on /datastore/store1/dept1",
			[]string{
				`Unable to start the verification of namespace "dept1" of PBS datastore "store1"`,
				`"tfacc@pbs!acc" lacks a privilege this needs: Datastore.Verify on /datastore/store1/dept1, or Datastore.Backup there`,
				"An API token has no privileges of its own",
			},
		},
		{"missing", map[string]any{}, 400, "no such datastore 'store1'", []string{`PBS has no datastore "store1"`}},
		{"unmounted", map[string]any{}, 400, "datastore 'store1' is not mounted", []string{"a removable datastore must be mounted"}},
		{"offline", map[string]any{}, 400, "datastore 'store1' is unavailable: offline maintenance mode: ", []string{"maintenance mode may forbid it"}},
		{
			"owner", map[string]any{"group": "vm/100"}, 400, "backup owner check failed (tfacc@pbs!acc != root@pam)",
			[]string{
				`Unable to start the verification of backup group "vm/100" in PBS datastore "store1"`,
				`"tfacc@pbs!acc" may verify only the backups it owns`, "Datastore.Verify there verifies any backup",
			},
		},
		{
			"no group", map[string]any{"ns": "dept1", "snapshot": "vm/999/2026-11-14T02:00:05Z"}, 400,
			`unable to read "/datastore/store1/ns/dept1/vm/999/owner" - No such file or directory (os error 2)`,
			[]string{`There is no backup group "vm/999" in namespace "dept1" of PBS datastore "store1"`, "Check `group` or `snapshot`, and `ns`"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(verifyActionRoute, tc.status, tc.body)
			h := newProtocolHarness(t, fake)
			tc.attrs["store"] = "store1"
			got := h.invokeAction(t, "pbs_datastore_verify", tc.attrs)
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to start the verification of ")
			for _, want := range tc.want {
				requireProtocolErrorContaining(t, got.diagnostics, want)
			}
			requireProtocolErrorContaining(t, got.diagnostics, strings.TrimSpace(tc.body))
		})
	}
}

// The thread counts need PBS 4.1, as those of a verify job do; an unknown
// count is checked as one that is set.
func TestDatastoreVerifyActionThreadsNeedPBS41(t *testing.T) {
	for _, tc := range []struct {
		version string
		attrs   map[string]any
		want    string
	}{
		{fakeVersion40, map[string]any{"read_threads": 2}, "read_threads needs PBS 4.1 or newer"},
		{fakeVersion40, map[string]any{"verify_threads": 8}, "verify_threads needs PBS 4.1 or newer"},
		{fakeVersion40, map[string]any{"read_threads": tfUnknown}, "read_threads needs PBS 4.1 or newer"},
		{fakeVersion40, map[string]any{"ignore_verified": false}, ""},
		{fakeVersion420JSON, map[string]any{"read_threads": 2, "verify_threads": tfUnknown}, ""},
	} {
		fake := newFakePBS()
		fake.reply("GET /version", http.StatusOK, tc.version)
		h := newProtocolHarness(t, fake)
		tc.attrs["store"] = "store1"
		config := h.actionValue(t, "pbs_datastore_verify", tc.attrs)
		requireNoProtocolErrors(t, h.validateAction(t, "pbs_datastore_verify", config))
		diags := h.planAction(t, "pbs_datastore_verify", config)
		if tc.want == "" {
			requireNoProtocolErrors(t, diags)
		} else {
			requireProtocolErrorContaining(t, diags, tc.want)
		}
		for _, route := range fake.routes() {
			if strings.HasPrefix(route, "POST ") {
				t.Fatalf("planning called PBS: %v", fake.routes())
			}
		}
	}
}

func TestDatastoreVerifyActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"store": "x"}, "store"},
		{map[string]any{"store": "store1", "ns": "/dept1"}, "must be a namespace"},
		{map[string]any{"store": "store1", "group": "vm100"}, "must be a backup group"},
		{map[string]any{"store": "store1", "group": "vz/100"}, "must be a backup group"},
		{map[string]any{"store": "store1", "group": "vm/-x"}, "must be a backup group"},
		{map[string]any{"store": "store1", "snapshot": "vm/100/2026-11-14T02:00:05"}, "must be a backup such as"},
		{map[string]any{"store": "store1", "snapshot": "vm/100/2026-13-40T00:00:00Z"}, "must be a backup such as"},
		{map[string]any{"store": "store1", "snapshot": "vm/100/1970-01-01T00:00:00Z"}, "must be a backup such as"},
		{map[string]any{"store": "store1", "snapshot": "vm/100"}, "must be a backup such as"},
		{map[string]any{"store": "store1", "group": "vm/100", "snapshot": "vm/100/2026-11-14T02:00:05Z"}, "snapshot"},
		{map[string]any{"store": "store1", "group": "vm/100", "max_depth": 1}, "max_depth"},
		{map[string]any{"store": "store1", "snapshot": "vm/100/2026-11-14T02:00:05Z", "max_depth": 0}, "max_depth"},
		{map[string]any{"store": "store1", "max_depth": 8}, "max_depth"},
		{map[string]any{"store": "store1", "read_threads": 0}, "read_threads"},
		{map[string]any{"store": "store1", "verify_threads": 33}, "verify_threads"},
		{map[string]any{"store": "store1", "outdated_after": 0}, "outdated_after"},
		{map[string]any{"store": "store1", "timeout": "0s"}, "positive duration"},
	} {
		diags := h.validateAction(t, "pbs_datastore_verify", h.actionValue(t, "pbs_datastore_verify", tc.attrs))
		requireProtocolErrorContaining(t, diags, tc.want)
	}
	// Values only known at apply are fine while planning, against PBS 4.2.
	config := h.actionValue(t, "pbs_datastore_verify", map[string]any{
		"store": tfUnknown, "ns": tfUnknown, "group": tfUnknown, "ignore_verified": tfUnknown,
		"outdated_after": tfUnknown, "read_threads": tfUnknown, "verify_threads": tfUnknown, "wait": tfUnknown, "timeout": tfUnknown,
	})
	requireNoProtocolErrors(t, h.validateAction(t, "pbs_datastore_verify", config))
	requireNoProtocolErrors(t, h.planAction(t, "pbs_datastore_verify", config))
}

// With wait = false the action ends once the task has started; a timeout
// ends the wait, not the verification.
func TestDatastoreVerifyActionWaiting(t *testing.T) {
	t.Run("without waiting", func(t *testing.T) {
		h, fake, _ := newVerifyHarness(t, func() *fakeTask { return &fakeTask{running: -1} })
		got := h.invokeAction(t, "pbs_datastore_verify", map[string]any{"store": "store1", "wait": false})
		requireNoProtocolErrors(t, got.diagnostics)
		requireProgressContaining(t, got, "not waiting for it")
		for _, route := range fake.routes() {
			if strings.Contains(route, "/tasks/") {
				t.Fatalf("followed the task: %v", fake.routes())
			}
		}
	})
	t.Run("timeout", func(t *testing.T) {
		h, _, tasks := newVerifyHarness(t, func() *fakeTask { return &fakeTask{running: -1} })
		got := h.invokeAction(t, "pbs_datastore_verify", map[string]any{"store": "store1", "group": "vm/100", "timeout": "1s"})
		requireProtocolErrorContaining(t, got.diagnostics, `Verification of backup group "vm/100" in PBS datastore "store1" did not finish`)
		requireProtocolErrorContaining(t, got.diagnostics, "The task goes on in PBS")
		for _, task := range tasks.all() {
			if task.aborted {
				t.Fatal("the verification was asked to stop")
			}
		}
	})
}

func TestParseBackupSnapshot(t *testing.T) {
	backupType, backupID, epoch, ok := parseBackupSnapshot("host/web-1.example/2026-11-14T02:00:05Z")
	if !ok || backupType != "host" || backupID != "web-1.example" || epoch != 1794621605 {
		t.Fatalf("parseBackupSnapshot = %q, %q, %d, %t", backupType, backupID, epoch, ok)
	}
	for _, s := range []string{"", "vm/100", "vm/100/2026-11-14", "vm/100/2026-11-14T02:00:05+01:00", "vm/100/2026-02-30T02:00:05Z"} {
		if _, _, _, ok := parseBackupSnapshot(s); ok {
			t.Errorf("parseBackupSnapshot(%q) accepted it", s)
		}
	}
}
