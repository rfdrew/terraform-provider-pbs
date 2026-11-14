package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const renewRoute = "PUT /nodes/localhost/certificates/acme/certificate"

// fakeRenewal is the renewal of the ACME fake's certificate, PUT
// /nodes/localhost/certificates/acme/certificate, which serveRenewal serves
// as PBS does: without force, a certificate that is not due is refused at
// once, with PBS's 400; otherwise the ACME fake runs the task it runs for an
// order, as an acme-renew-cert task — which, like every task of the ACME
// fake, serves no log. Whether the certificate is due is due's, not the
// clock's.
type fakeRenewal struct {
	due atomic.Bool
}

// newRenewHarness is the ACME fake with a node ready to order, serving an
// ACME certificate, and its renewal.
func newRenewHarness(t *testing.T, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeACME, *fakeRenewal) {
	t.Helper()
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	acme.install("pbs.example.org", "backup.example.org")
	renewal := serveRenewal(t, fake, acme)
	return newProtocolHarness(t, fake, opts...), fake, acme, renewal
}

// serveRenewal serves the renewal of acme's certificate from fake.
func serveRenewal(t *testing.T, fake *fakePBS, acme *fakeACME) *fakeRenewal {
	t.Helper()
	renewal := &fakeRenewal{}
	fake.handle(renewRoute, func(w http.ResponseWriter, req *http.Request) {
		if !fakeBool(form(req).Get("force")) && !renewal.due.Load() {
			writeError(w, "Certificate does not expire within the next 30 days and 'force' is not set.")
			return
		}
		ordered := httptest.NewRecorder()
		acme.order(ordered, req)
		var started struct {
			Data string `json:"data"`
		}
		if err := json.Unmarshal(ordered.Body.Bytes(), &started); err != nil {
			t.Errorf("the fake's order answered %q: %v", ordered.Body.String(), err)
		}
		upid := strings.Replace(started.Data, ":acme-new-cert:", ":acme-renew-cert:", 1)
		acme.mu.Lock()
		acme.tasks[upid] = acme.tasks[started.Data]
		delete(acme.tasks, started.Data)
		acme.mu.Unlock()
		writeData(w, upid, "")
	})
	return renewal
}

// renewWithTasks routes the renewal to tasks instead, which log lines and
// may run for a while; the task the test makes installs a certificate with
// onStop, as PBS's would.
func renewWithTasks(fake *fakePBS, tasks *fakeTasks, next func() *fakeTask) {
	fake.handle(renewRoute, tasks.starter(func(*http.Request) *fakeTask {
		task := next()
		task.workerType = "acme-renew-cert"
		return task
	}))
}

// A certificate that is not due is no error: the action says so, and that
// force renews it anyway, and PBS starts no task.
func TestNodeCertificateRenewActionNotDue(t *testing.T) {
	h, fake, acme, _ := newRenewHarness(t)
	before := acme.certificate()

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	if len(got.diagnostics) != 0 {
		t.Fatalf("diagnostics: %v", got.diagnostics)
	}
	requireProgressContaining(t, got, "Not renewed: the certificate of node localhost, valid until 2026-12-20, is not due yet")
	requireProgressContaining(t, got, "within 30 days of its expiry")
	requireProgressContaining(t, got, "force = true renews it anyway")
	if acme.certificate().Fingerprint != before.Fingerprint || fake.count(renewRoute) != 1 || fake.lastCall(t, renewRoute).form.Has("force") {
		t.Fatalf("routes: %v", fake.routes())
	}
	for _, message := range got.progress {
		if strings.Contains(message, "PBS started task") {
			t.Fatalf("progress: %q", got.progress)
		}
	}
}

// PBS's own self-signed certificate, valid for a thousand years, is never
// due, and PBS's daily update does not replace it: the action says so,
// rather than when PBS would renew it.
func TestNodeCertificateRenewActionGeneratedCertificate(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	serveRenewal(t, fake, acme)
	before := acme.certificate()
	if !before.Generated() {
		t.Fatalf("the fake serves %q, not PBS's own certificate", before.Subject)
	}
	h := newProtocolHarness(t, fake)

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	if len(got.diagnostics) != 0 {
		t.Fatalf("diagnostics: %v", got.diagnostics)
	}
	requireProgressContaining(t, got, "Not renewed: node localhost serves PBS's own self-signed certificate, "+
		"which is never due; force = true orders an ACME one.")
	for _, message := range got.progress {
		if strings.Contains(message, "days of its expiry") {
			t.Fatalf("progress: %q", got.progress)
		}
	}
	if acme.certificate().Fingerprint != before.Fingerprint {
		t.Fatal("the certificate changed")
	}
}

// A certificate that is due is renewed without force, as PBS's daily update
// renews it; the provider reads the new certificate and says how to trust
// it from the next run on.
func TestNodeCertificateRenewActionDue(t *testing.T) {
	h, fake, acme, renewal := newRenewHarness(t)
	renewal.due.Store(true)
	before := acme.certificate()

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{})
	requireNoProtocolErrors(t, got.diagnostics)
	after := acme.certificate()
	if after.Fingerprint == before.Fingerprint || fake.lastCall(t, renewRoute).form.Has("force") {
		t.Fatalf("the certificate was not renewed: routes %v", fake.routes())
	}
	requireProgressContaining(t, got, "PBS started task UPID:pbs-acme:")
	requireProgressContaining(t, got, ":acme-renew-cert:")
	requireProgressContaining(t, got, "PBS renewed the certificate of node localhost; the new one is valid until 2026-12-20")
	requireProgressContaining(t, got, "New SHA-256 fingerprint: "+after.Fingerprint)
	// The system's roots do not know the fake CA, as they do not know
	// Let's Encrypt's staging CAs: the new certificate is to be pinned.
	requireProtocolWarningContaining(t, got.diagnostics, "Pin the new PBS certificate by its fingerprint")
	requireProtocolWarningContaining(t, got.diagnostics, after.Fingerprint)
}

// With force, PBS renews a certificate that is not due. A provider that
// pins the old certificate trusts the new one for the rest of the run, and
// warns that its configuration must change, as pbs_node_certificate does.
func TestNodeCertificateRenewActionForce(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	acme.install("pbs.example.org")
	tasks := newFakeTasks(fake)
	renewWithTasks(fake, tasks, func() *fakeTask {
		return &fakeTask{
			running: 1,
			log:     []string{"Placing ACME order", "The validation for pbs.example.org is pending", "All domains validated"},
			onStop:  acme.renew,
		}
	})
	before := acme.certificate()
	h := newProtocolHarness(t, fake, withCertFingerprint(before.Fingerprint))

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true, "node": "localhost", "timeout": "5m"})
	requireNoProtocolErrors(t, got.diagnostics)
	after := acme.certificate()
	if after.Fingerprint == before.Fingerprint || fake.lastCall(t, renewRoute).form.Get("force") != "true" {
		t.Fatalf("the certificate was not renewed: routes %v", fake.routes())
	}
	// The task's lines are forwarded while it runs.
	requireProgressContaining(t, got, "All domains validated")
	requireProgressContaining(t, got, "New SHA-256 fingerprint: "+after.Fingerprint)
	requireProtocolWarningContaining(t, got.diagnostics, "Pin the new PBS certificate by its fingerprint")
	requireProtocolWarningContaining(t, got.diagnostics, "for the rest of this run only")
	requireProtocolWarningContaining(t, got.diagnostics, "Proxmox VE's PBS storage")
}

// A new certificate the provider cannot read over the connection it trusted
// before is not trusted, and the action says how to check it, as
// pbs_node_certificate does.
func TestNodeCertificateRenewActionUnconfirmed(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	acme.install("pbs.example.org")
	serveRenewal(t, fake, acme)
	h := newProtocolHarness(t, fake, withTransport(&untrustedAfterChange{fake: fake, acme: acme, initial: acme.certificate().Fingerprint}))

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "Unable to confirm the new PBS certificate")
	requireProtocolWarningContaining(t, got.diagnostics, "proxmox-backup-manager cert info")
	requireProtocolWarningContaining(t, got.diagnostics, acme.certificate().Fingerprint)
	for _, message := range got.progress {
		if strings.Contains(message, "New SHA-256 fingerprint") {
			t.Fatalf("progress reports an unconfirmed certificate: %q", got.progress)
		}
	}
}

// The node's ACME settings are checked before PBS is asked: a renewal
// without domains does nothing, and one without the account fails, which
// sends PBS's ACME error notification.
func TestNodeCertificateRenewActionChecksTheACMESettings(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	fake.reply(renewRoute, http.StatusInternalServerError, "the renewal must not be asked for")
	h := newProtocolHarness(t, fake)
	invoke := func() []*tfprotov6.Diagnostic {
		t.Helper()
		return h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true}).diagnostics
	}

	requireProtocolErrorContaining(t, invoke(), "has no ACME domains")
	requireProtocolErrorContaining(t, invoke(), "invoke the action once Terraform has set them")
	acme.setNodeProperty("acmedomain1", "pbs.example.org")
	requireProtocolErrorContaining(t, invoke(), `ACME account "default"`)
	if fake.count(renewRoute) != 0 {
		t.Fatalf("routes: %v", fake.routes())
	}

	fake.reply("GET /nodes/localhost/config", http.StatusForbidden, "permission check failed")
	requireProtocolErrorContaining(t, invoke(), "Sys.Audit on /system")
}

// A failed renewal leaves the certificate as it was. The ACME fake's tasks
// serve no log, so the error points to it instead of quoting its end.
func TestNodeCertificateRenewActionTaskFails(t *testing.T) {
	h, fake, acme, _ := newRenewHarness(t)
	before := acme.certificate()
	acme.orderFailure = "validation for pbs.example.org failed: connection refused"

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireProtocolErrorContaining(t, got.diagnostics, "Renewal of the certificate of PBS node localhost failed")
	requireProtocolErrorContaining(t, got.diagnostics, "The CA did not issue a certificate")
	requireProtocolErrorContaining(t, got.diagnostics, "connection refused")
	requireProtocolErrorContaining(t, got.diagnostics, "The task's log: Administration → Tasks in the web interface, "+
		"or `proxmox-backup-manager task log 'UPID:pbs-acme:")
	for _, d := range got.diagnostics {
		if strings.Contains(d.Detail, "The end of the task's log") {
			t.Fatalf("detail quotes a log the fake does not serve: %s", d.Detail)
		}
	}
	if acme.certificate().Fingerprint != before.Fingerprint || fake.count(renewRoute) != 1 {
		t.Fatalf("routes: %v", fake.routes())
	}
}

// A task that logs has the end of its log in the error.
func TestNodeCertificateRenewActionTaskFailsWithLog(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	acme.install("pbs.example.org")
	tasks := newFakeTasks(fake)
	renewWithTasks(fake, tasks, func() *fakeTask {
		return &fakeTask{
			log:  []string{"Placing ACME order", "The validation for pbs.example.org is pending", "Setting up validation plugin"},
			exit: "TXT record _acme-challenge.pbs.example.org not found",
		}
	})
	h := newProtocolHarness(t, fake)

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireProtocolErrorContaining(t, got.diagnostics, "Renewal of the certificate of PBS node localhost failed")
	requireProtocolErrorContaining(t, got.diagnostics, "The end of the task's log:\n\n    Placing ACME order")
	requireProtocolErrorContaining(t, got.diagnostics, "    TASK ERROR: TXT record _acme-challenge.pbs.example.org not found")
}

// A task that fails after it wrote the certificate — PBS could not reach
// the proxy to have it load the certificate — leaves it in place: the action
// warns, as pbs_node_certificate does, and says how to trust the new
// certificate, which nothing else will: an action runs once.
func TestNodeCertificateRenewActionTaskFailsAfterInstalling(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	acme.install("pbs.example.org")
	serveRenewal(t, fake, acme)
	before := acme.certificate()
	h := newProtocolHarness(t, fake, withCertFingerprint(before.Fingerprint))
	acme.orderFailureAfterInstall = "unable to open pid file '/run/proxmox-backup/proxy.pid' - No such file or directory"

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireNoProtocolErrors(t, got.diagnostics)
	after := acme.certificate()
	if after.Fingerprint == before.Fingerprint {
		t.Fatal("the fake installed no certificate")
	}
	requireProtocolWarningContaining(t, got.diagnostics, "The PBS certificate task ended with an error")
	requireProtocolWarningContaining(t, got.diagnostics, "systemctl reload proxmox-backup-proxy")
	requireProtocolWarningContaining(t, got.diagnostics, "proxy.pid")
	requireProtocolWarningContaining(t, got.diagnostics, "Pin the new PBS certificate by its fingerprint")
	requireProtocolWarningContaining(t, got.diagnostics, "set tls_cert_fingerprint (or PBS_TLS_FINGERPRINT) to "+after.Fingerprint)
	for _, d := range got.diagnostics {
		if strings.Contains(d.Detail, "next apply warns") {
			t.Fatalf("detail promises a warning nothing gives: %s", d.Detail)
		}
	}
}

// A task that ends well with the certificate unchanged installed nothing:
// the node's domains went away meanwhile.
func TestNodeCertificateRenewActionInstallsNothing(t *testing.T) {
	h, _, acme, _ := newRenewHarness(t)
	acme.orderNothing = true
	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS installed no new certificate")
}

// A task that ends with warnings renewed the certificate, and the action
// warns with the end of its log.
func TestNodeCertificateRenewActionWarnings(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	acme.install("pbs.example.org")
	tasks := newFakeTasks(fake)
	renewWithTasks(fake, tasks, func() *fakeTask {
		return &fakeTask{log: []string{"Placing ACME order", "could not remove the TXT record"}, exit: "WARNINGS: 1", onStop: acme.renew}
	})
	h := newProtocolHarness(t, fake)

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "Renewal of the certificate of PBS node localhost ended with warnings")
	requireProtocolWarningContaining(t, got.diagnostics, "could not remove the TXT record")
	requireProgressContaining(t, got, "New SHA-256 fingerprint: "+acme.certificate().Fingerprint)
}

// The action waits within its timeout; the task goes on, since PBS cannot
// stop an order, and the error does not offer a `wait` the action lacks.
func TestNodeCertificateRenewActionTimeout(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	tasks := newFakeTasks(fake)
	renewWithTasks(fake, tasks, func() *fakeTask { return &fakeTask{running: -1, log: []string{"Placing ACME order"}} })
	h := newProtocolHarness(t, fake)

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true, "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "Renewal of the certificate of PBS node localhost did not finish")
	requireProtocolErrorContaining(t, got.diagnostics, "which cannot stop an ACME order")
	requireProtocolErrorContaining(t, got.diagnostics, "Raise the action's `timeout`")
	for _, d := range got.diagnostics {
		if strings.Contains(d.Detail, "wait = false") {
			t.Fatalf("detail offers wait: %s", d.Detail)
		}
	}
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the task was asked to stop")
		}
	}

	// When Terraform stops the action, it stops waiting at once.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	h.invokeActionWith(ctx, t, "pbs_node_certificate_renew", h.actionValue(t, "pbs_node_certificate_renew", map[string]any{"force": true}))
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the action went on for %s after it was cancelled", elapsed)
	}
}

func TestNodeCertificateRenewActionStartErrors(t *testing.T) {
	h, fake, _, _ := newRenewHarness(t)
	fake.reply(renewRoute, http.StatusForbidden, "permission check failed")
	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to renew the certificate of the PBS node")
	requireProtocolErrorContaining(t, got.diagnostics, "Sys.Modify on /system/certificates")

	fake.reply("GET /nodes/localhost/certificates/info", http.StatusForbidden, "permission check failed")
	got = h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireProtocolErrorContaining(t, got.diagnostics, "reading the certificate before changing it")
}

// Nothing is asked of PBS while planning, and values known only at apply
// are fine then.
func TestNodeCertificateRenewActionValidation(t *testing.T) {
	h, fake, _, _ := newRenewHarness(t)
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"node": "pbs_1"}, "node name"},
		{map[string]any{"timeout": "0s"}, "positive duration"},
		{map[string]any{"timeout": "soon"}, "positive duration"},
	} {
		requireProtocolErrorContaining(t, h.validateAction(t, "pbs_node_certificate_renew", h.actionValue(t, "pbs_node_certificate_renew", tc.attrs)), tc.want)
	}
	calls := len(fake.routes())
	unknown := h.actionValue(t, "pbs_node_certificate_renew", map[string]any{"node": tfUnknown, "force": tfUnknown, "timeout": tfUnknown})
	requireNoProtocolErrors(t, h.validateAction(t, "pbs_node_certificate_renew", unknown))
	requireNoProtocolErrors(t, h.planAction(t, "pbs_node_certificate_renew", unknown))
	if len(fake.routes()) != calls {
		t.Fatalf("planning called PBS: %v", fake.routes()[calls:])
	}
}
