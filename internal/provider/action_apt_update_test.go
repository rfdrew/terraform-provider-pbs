package provider

import (
	"net/http"
	"strings"
	"testing"
)

// newAPTUpdateHarness serves the APT update of node localhost, whose task is
// what next returns, and the updates PBS lists afterwards.
func newAPTUpdateHarness(t *testing.T, next func() *fakeTask, updates []string, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeTasks) {
	t.Helper()
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	fake.handle("POST /nodes/localhost/apt/update", tasks.starter(func(*http.Request) *fakeTask {
		task := next()
		task.workerType = "aptupdate"
		return task
	}))
	fake.handle("GET /nodes/localhost/apt/update", func(w http.ResponseWriter, _ *http.Request) {
		list := []map[string]any{}
		for _, name := range updates {
			list = append(list, map[string]any{"Package": name, "Title": name, "Arch": "amd64", "Description": "",
				"Version": "2.0", "OldVersion": "1.0", "Origin": "Proxmox", "Priority": "optional", "Section": "admin"})
		}
		writeData(w, list, "")
	})
	return newProtocolHarness(t, fake, opts...), fake, tasks
}

func TestAPTUpdateActionWaitsAndReports(t *testing.T) {
	h, fake, _ := newAPTUpdateHarness(t, func() *fakeTask {
		return &fakeTask{running: 1, log: []string{"starting apt-get update", "Hit:1 http://deb.debian.org/debian trixie InRelease"}}
	}, []string{"proxmox-backup-server", "libc6", "zfsutils-linux", "libc6", "base-files", "openssl", "bash"})

	got := h.invokeAction(t, "pbs_apt_update", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	if len(got.diagnostics) != 0 {
		t.Fatalf("diagnostics: %v", got.diagnostics)
	}
	requireProgressContaining(t, got, "PBS started task UPID:pbs-tasks:")
	requireProgressContaining(t, got, "Hit:1 http://deb.debian.org/debian trixie InRelease")
	// Names sorted, each package once.
	requireProgressContaining(t, got, "PBS lists 6 package updates: base-files, bash, libc6, openssl, proxmox-backup-server and 1 more")
	// notify is PBS's default, false, unless set.
	if form := fake.lastCall(t, "POST /nodes/localhost/apt/update").form; len(form) != 0 {
		t.Fatalf("form = %v", form)
	}
}

func TestAPTUpdateActionNotifiesAndNode(t *testing.T) {
	fake := newFakePBS()
	tasks := newFakeTasks(fake)
	fake.handle("POST /nodes/pbs1/apt/update", tasks.starter(func(*http.Request) *fakeTask { return &fakeTask{workerType: "aptupdate"} }))
	fake.handle("GET /nodes/pbs1/apt/update", func(w http.ResponseWriter, _ *http.Request) { writeData(w, []any{}, "") })
	h := newProtocolHarness(t, fake)

	got := h.invokeAction(t, "pbs_apt_update", map[string]any{"node": "pbs1", "notify": true})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "PBS lists no package updates")
	if form := fake.lastCall(t, "POST /nodes/pbs1/apt/update").form; form.Get("notify") != "true" {
		t.Fatalf("form = %v", form)
	}
}

// apt-get failing for a repository ends the task with warnings, not an
// error: the action warns, says the lists may be stale, and still reports
// the updates PBS lists.
func TestAPTUpdateActionAptFails(t *testing.T) {
	h, _, _ := newAPTUpdateHarness(t, func() *fakeTask {
		return &fakeTask{exit: "WARNINGS: 1", log: []string{
			"starting apt-get update",
			"Err:3 https://enterprise.proxmox.com/debian/pbs trixie InRelease",
			"E: Failed to fetch https://enterprise.proxmox.com/debian/pbs/dists/trixie/InRelease  401  Unauthorized [IP: 203.0.113.7 443]",
			"E: The repository 'https://enterprise.proxmox.com/debian/pbs trixie InRelease' is not signed.",
		}}
	}, []string{"libc6"})

	got := h.invokeAction(t, "pbs_apt_update", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "APT update of PBS node localhost ended with warnings")
	requireProtocolWarningContaining(t, got.diagnostics, "401  Unauthorized")
	requireProtocolWarningContaining(t, got.diagnostics, "PBS package lists may be stale")
	requireProtocolWarningContaining(t, got.diagnostics, "enterprise repository without a subscription")
	requireProgressContaining(t, got, "PBS lists 1 package update: libc6")
}

// Network trouble apt takes for a passing failure: it only warns and exits
// 0, PBS drops its warnings and ends the task OK, and only apt's "Err:"
// lines, with the reasons below them, show it — which the action quotes.
func TestAPTUpdateActionNetworkTrouble(t *testing.T) {
	h, _, _ := newAPTUpdateHarness(t, func() *fakeTask {
		return &fakeTask{log: []string{
			"starting apt-get update",
			"Hit:1 http://download.proxmox.com/debian/pbs trixie InRelease",
			"Ign:2 http://deb.debian.org/debian trixie InRelease",
			"Err:2 http://deb.debian.org/debian trixie InRelease",
			"  Temporary failure resolving 'deb.debian.org'",
			"Err:3 http://security.debian.org/debian-security trixie-security InRelease",
			"  Could not connect to proxy.example.com:3128 (192.0.2.1), connection timed out",
			"Reading package lists...",
		}}
	}, []string{"libc6"})

	got := h.invokeAction(t, "pbs_apt_update", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "PBS package lists may be stale")
	requireProtocolWarningContaining(t, got.diagnostics, "ends the task OK")
	requireProtocolWarningContaining(t, got.diagnostics, "    Err:2 http://deb.debian.org/debian trixie InRelease\n"+
		"      Temporary failure resolving 'deb.debian.org'\n"+
		"    Err:3 http://security.debian.org/debian-security trixie-security InRelease\n"+
		"      Could not connect to proxy.example.com:3128")
	requireProtocolWarningContaining(t, got.diagnostics, "proxmox-backup-manager task log 'UPID:pbs-tasks:")
	for _, d := range got.diagnostics {
		if strings.Contains(d.Summary, "ended with warnings") || strings.Contains(d.Detail, "Hit:1") || strings.Contains(d.Detail, "Ign:2") {
			t.Fatalf("diagnostics: %v", got.diagnostics)
		}
	}
	requireProgressContaining(t, got, "PBS lists 1 package update: libc6")
}

// Warnings that are not apt's — a notification target that did not take
// the notification — say nothing about the package lists.
func TestAPTUpdateActionOtherWarnings(t *testing.T) {
	h, _, _ := newAPTUpdateHarness(t, func() *fakeTask {
		return &fakeTask{exit: "WARNINGS: 1", log: []string{"starting apt-get update", "Hit:1 http://deb.debian.org/debian trixie InRelease",
			"could not notify via target `gotify1`: connection refused"}}
	}, nil)
	got := h.invokeAction(t, "pbs_apt_update", map[string]any{"notify": true})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "could not notify via target")
	for _, d := range got.diagnostics {
		if strings.Contains(d.Summary, "stale") {
			t.Fatalf("warned about stale lists: %v", got.diagnostics)
		}
	}
}

func TestAPTUpdateActionTaskFails(t *testing.T) {
	h, fake, _ := newAPTUpdateHarness(t, func() *fakeTask {
		return &fakeTask{log: []string{"starting apt-get update"}, exit: "terminated by signal"}
	}, nil)
	got := h.invokeAction(t, "pbs_apt_update", map[string]any{})
	requireProtocolErrorContaining(t, got.diagnostics, "APT update of PBS node localhost failed")
	requireProtocolErrorContaining(t, got.diagnostics, "TASK ERROR: terminated by signal")
	if fake.count("GET /nodes/localhost/apt/update") != 0 {
		t.Fatalf("listed the updates after a failure: %v", fake.routes())
	}
}

func TestAPTUpdateActionWithoutWaiting(t *testing.T) {
	h, fake, _ := newAPTUpdateHarness(t, func() *fakeTask { return &fakeTask{running: -1} }, nil)
	got := h.invokeAction(t, "pbs_apt_update", map[string]any{"wait": false})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "not waiting for it")
	for _, route := range fake.routes() {
		if strings.Contains(route, "/status") || route == "GET /nodes/localhost/apt/update" {
			t.Fatalf("waited: %v", fake.routes())
		}
	}
}

func TestAPTUpdateActionTimeout(t *testing.T) {
	h, _, tasks := newAPTUpdateHarness(t, func() *fakeTask { return &fakeTask{running: -1} }, nil)
	got := h.invokeAction(t, "pbs_apt_update", map[string]any{"timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "APT update of PBS node localhost did not finish")
	requireProtocolErrorContaining(t, got.diagnostics, "The task goes on in PBS")
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the task was asked to stop")
		}
	}
}

func TestAPTUpdateActionErrors(t *testing.T) {
	fake := newFakePBS()
	fake.reply("POST /nodes/localhost/apt/update", http.StatusForbidden, "permission check failed")
	h := newProtocolHarness(t, fake)
	got := h.invokeAction(t, "pbs_apt_update", map[string]any{})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to refresh the package lists of PBS node localhost")
	requireProtocolErrorContaining(t, got.diagnostics, "Sys.Modify on /")

	// Listing the updates needs Sys.Audit as well; without it, the refresh
	// still succeeds.
	h, fake, _ = newAPTUpdateHarness(t, func() *fakeTask { return &fakeTask{} }, nil)
	fake.reply("GET /nodes/localhost/apt/update", http.StatusForbidden, "permission check failed")
	got = h.invokeAction(t, "pbs_apt_update", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "listing the available updates failed")
}

func TestAPTUpdateActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"node": "not a node"}, "node name"},
		{map[string]any{"timeout": "soon"}, "positive duration"},
	} {
		requireProtocolErrorContaining(t, h.validateAction(t, "pbs_apt_update", h.actionValue(t, "pbs_apt_update", tc.attrs)), tc.want)
	}
	unknown := h.actionValue(t, "pbs_apt_update", map[string]any{"node": tfUnknown, "notify": tfUnknown, "wait": tfUnknown})
	requireNoProtocolErrors(t, h.validateAction(t, "pbs_apt_update", unknown))
	requireNoProtocolErrors(t, h.planAction(t, "pbs_apt_update", unknown))
}
