package provider

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Failures after a write took effect: the resource is recorded all the same,
// so that Terraform does not lose track of it.

func TestACMEAccountResourceReadBackFailures(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	forbidden := func(w http.ResponseWriter, _ *http.Request) {
		writeFakeResponse(w, http.StatusForbidden, "permission check failed")
	}

	// Registered, but not read back: recorded, with a warning.
	fake.handle("GET /config/acme/account/le", forbidden)
	config := accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos"})
	applied := h.apply(t, "pbs_acme_account", nil, config, h.plan(t, "pbs_acme_account", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "registered ACME account")
	inst := &resourceInstance{typeName: "pbs_acme_account", state: h.decodeResource(t, "pbs_acme_account", applied.NewState), identity: applied.NewIdentity}
	if stringAt(t, inst.state, "id") != "le" || !isNullAt(t, inst.state, "location") {
		t.Fatalf("state = %s", inst.state)
	}
	requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, certificatesPrivilege)

	// Updated, but not read back: recorded, with an error.
	config = accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos", "contact": "new@example.org"})
	updated := h.apply(t, "pbs_acme_account", inst, config, h.plan(t, "pbs_acme_account", inst, config))
	requireProtocolErrorContaining(t, updated.Diagnostics, "updated ACME account")
	if got := stringAt(t, h.decodeResource(t, "pbs_acme_account", updated.NewState), "contact"); got != "new@example.org" {
		t.Fatalf("contact = %q", got)
	}

	// The update itself fails.
	acme.fake.handle("GET /config/acme/account/le", nil)
	fake.reply("PUT /config/acme/account/le", http.StatusForbidden, "permission check failed")
	config = accountConfig(t, h, map[string]any{"tos_url": "https://ca.test/tos", "contact": "other@example.org"})
	updated = h.apply(t, "pbs_acme_account", inst, config, h.plan(t, "pbs_acme_account", inst, config))
	requireProtocolErrorContaining(t, updated.Diagnostics, "Unable to update PBS ACME account")

	// Deactivation fails before a task.
	fake.reply("DELETE /config/acme/account/le", http.StatusForbidden, "permission check failed")
	null := tftypes.NewValue(h.resourceType(t, "pbs_acme_account"), nil)
	destroyed := h.apply(t, "pbs_acme_account", inst, null, h.plan(t, "pbs_acme_account", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, certificatesPrivilege)
}

func TestACMEPluginResourceFailures(t *testing.T) {
	h, fake, _ := newACMEHarness(t)
	config := pluginConfig(t, h, nil)

	fake.reply("POST /config/acme/plugins", http.StatusForbidden, "permission check failed")
	applied := h.apply(t, "pbs_acme_plugin", nil, config, h.plan(t, "pbs_acme_plugin", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to create PBS ACME plugin")
	fake.handle("POST /config/acme/plugins", nil)

	// Created, but not read back: recorded and tainted.
	h2, fake2, _ := newACMEHarness(t)
	fake2.reply("GET /config/acme/plugins/cloudflare", http.StatusForbidden, "permission check failed")
	config = pluginConfig(t, h2, nil)
	applied = h2.apply(t, "pbs_acme_plugin", nil, config, h2.plan(t, "pbs_acme_plugin", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "marked tainted")
	inst := &resourceInstance{typeName: "pbs_acme_plugin", state: h2.decodeResource(t, "pbs_acme_plugin", applied.NewState), identity: applied.NewIdentity}
	if stringAt(t, inst.state, "type") != "dns" {
		t.Fatalf("state = %s", inst.state)
	}
	requireProtocolErrorContaining(t, h2.read(t, inst).Diagnostics, certificatesPrivilege)

	// The update reads the digest first, and fails with it.
	config = pluginConfig(t, h2, map[string]any{"validation_delay": 60})
	updated := h2.apply(t, "pbs_acme_plugin", inst, config, h2.plan(t, "pbs_acme_plugin", inst, config))
	requireProtocolErrorContaining(t, updated.Diagnostics, "Unable to update PBS ACME plugin")

	// Updated, but not read back.
	reads := atomic.Int32{}
	fake2.handle("GET /config/acme/plugins/cloudflare", func(w http.ResponseWriter, _ *http.Request) {
		if reads.Add(1) == 1 {
			writeData(w, map[string]any{"plugin": "cloudflare", "type": "dns", "api": "cf", "data": "CF_Token=token-1\nCF_Zone_ID=zone"}, "d")
			return
		}
		writeFakeResponse(w, http.StatusForbidden, "permission check failed")
	})
	fake2.reply("PUT /config/acme/plugins/cloudflare", http.StatusOK, `{"data":null}`)
	updated = h2.apply(t, "pbs_acme_plugin", inst, config, h2.plan(t, "pbs_acme_plugin", inst, config))
	requireProtocolErrorContaining(t, updated.Diagnostics, "updated ACME plugin")

	fake2.reply("DELETE /config/acme/plugins/cloudflare", http.StatusForbidden, "permission check failed")
	null := tftypes.NewValue(h2.resourceType(t, "pbs_acme_plugin"), nil)
	destroyed := h2.apply(t, "pbs_acme_plugin", inst, null, h2.plan(t, "pbs_acme_plugin", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "Unable to delete PBS ACME plugin")

	resp := h2.importResource(t, "pbs_acme_plugin", "bad id", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "by its id")
}

func TestNodeACMEResourceFailures(t *testing.T) {
	h, fake, _ := newACMEHarness(t)
	config := nodeACMEConfig(t, h, "le", map[string]any{"domain": "pbs.example.org"})

	fake.reply("PUT /nodes/localhost/config", http.StatusForbidden, "permission check failed")
	applied := h.apply(t, "pbs_node_acme", nil, config, h.plan(t, "pbs_node_acme", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, nodeConfigModifyPrivilege)
	fake.handle("PUT /nodes/localhost/config", nil)

	// Changed, but not read back: recorded, with a warning.
	h2, fake2, acme2 := newACMEHarness(t)
	reads := atomic.Int32{}
	fake2.handle("GET /nodes/localhost/config", func(w http.ResponseWriter, req *http.Request) {
		if reads.Add(1) == 1 {
			acme2.getNode(w, req)
			return
		}
		writeFakeResponse(w, http.StatusForbidden, "permission check failed")
	})
	config = nodeACMEConfig(t, h2, "le", map[string]any{"domain": "pbs.example.org"})
	applied = h2.apply(t, "pbs_node_acme", nil, config, h2.plan(t, "pbs_node_acme", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "reading them back failed")
	inst := &resourceInstance{typeName: "pbs_node_acme", state: h2.decodeResource(t, "pbs_node_acme", applied.NewState), identity: applied.NewIdentity}
	if got, _ := acme2.nodeProperty("acmedomain0"); got != "pbs.example.org" || stringAt(t, inst.state, "id") != "localhost" {
		t.Fatalf("slot 0 = %q, state %s", got, inst.state)
	}
	requireProtocolErrorContaining(t, h2.read(t, inst).Diagnostics, nodeConfigReadPrivilege)

	config = nodeACMEConfig(t, h2, "le", map[string]any{"domain": "www.example.org"})
	updated := h2.apply(t, "pbs_node_acme", inst, config, h2.plan(t, "pbs_node_acme", inst, config))
	requireProtocolErrorContaining(t, updated.Diagnostics, nodeConfigModifyPrivilege)
	null := tftypes.NewValue(h2.resourceType(t, "pbs_node_acme"), nil)
	destroyed := h2.apply(t, "pbs_node_acme", inst, null, h2.plan(t, "pbs_node_acme", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "Unable to remove the ACME settings")
}

func TestNodeCertificateResourceOrderOutcomes(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	readyForACME(acme)
	config := certificateConfig(t, h, nil)

	// The domains went away before the task ran: nothing installed.
	acme.orderNothing = true
	applied := h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "PBS installed no new certificate")

	// The task failed after it wrote the certificate, while having the proxy
	// load it: recorded, with a warning that the proxy may still serve the
	// previous one.
	acme.orderFailureAfterInstall = "unable to open pid file '/run/proxmox-backup/proxy.pid' - No such file or directory"
	applied = h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "systemctl reload proxmox-backup-proxy")
	if got := stringAt(t, h.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != acme.certificate().Fingerprint {
		t.Fatalf("fingerprint = %q", got)
	}
}

// A certificate PBS wrote before its task failed is one the provider now
// trusts for this run only: with a pinned fingerprint, the warning says
// what to pin, rather than promising that a later apply will.
func TestNodeCertificateResourceOrderFailsAfterInstallPinned(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	h := newProtocolHarness(t, fake, withCertFingerprint(acme.certificate().Fingerprint))
	config := certificateConfig(t, h, nil)

	acme.orderFailureAfterInstall = "unable to open pid file '/run/proxmox-backup/proxy.pid' - No such file or directory"
	applied := h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "systemctl reload proxmox-backup-proxy")
	requireProtocolWarningContaining(t, applied.Diagnostics, "Pin the new PBS certificate by its fingerprint")
	requireProtocolWarningContaining(t, applied.Diagnostics, acme.certificate().Fingerprint)
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Detail, "next apply warns") {
			t.Fatalf("detail promises a warning nothing gives: %s", d.Detail)
		}
	}
}

// untrustedAfterChange answers the certificate's info with a certificate the
// client does not trust once the proxy changed it, as a new connection does
// after the connection of the change closed.
type untrustedAfterChange struct {
	fake    *fakePBS
	acme    *fakeACME
	initial string
}

func (u *untrustedAfterChange) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/certificates/info") {
		if current := u.acme.certificate().Fingerprint; current != u.initial {
			normalised, _ := pbsclient.NormaliseFingerprint(current)
			return nil, &pbsclient.UntrustedCertificateError{Fingerprints: []string{normalised}, Pinned: strings.Repeat("00", 32)}
		}
	}
	return u.fake.RoundTrip(req)
}

func TestNodeCertificateResourceUnconfirmed(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	u := &untrustedAfterChange{fake: fake, acme: acme, initial: acme.certificate().Fingerprint}
	h := newProtocolHarness(t, fake, withTransport(u))

	config := certificateConfig(t, h, nil)
	applied := h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "Unable to confirm the new PBS certificate")
	requireProtocolWarningContaining(t, applied.Diagnostics, "proxmox-backup-manager cert info")
	state := h.decodeResource(t, "pbs_node_certificate", applied.NewState)
	if !isNullAt(t, state, "fingerprint") || !isNullAt(t, state, "issuer") || !isNullAt(t, state, "san") {
		t.Fatalf("state = %s, want nothing of a certificate the provider could not confirm", state)
	}

	// The same when destroying it.
	inst := &resourceInstance{typeName: "pbs_node_certificate", state: state, identity: applied.NewIdentity}
	u.initial = acme.certificate().Fingerprint
	null := tftypes.NewValue(h.resourceType(t, "pbs_node_certificate"), nil)
	destroyed := h.apply(t, "pbs_node_certificate", inst, null, h.plan(t, "pbs_node_certificate", inst, null))
	requireNoProtocolErrors(t, destroyed.Diagnostics)
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "could not confirm to be PBS's")
	requireProtocolWarningContaining(t, destroyed.Diagnostics, acme.certificate().Fingerprint)
}

// A failed order names the cause from the task's exit status — the texts
// PBS writes (see internal/pbsclient/acme_order.go) — and points to the
// task's log, which the ACME fake does not serve; it never says that the CA
// issued nothing when that is not known.
func TestNodeCertificateResourceOrderFailures(t *testing.T) {
	for _, tc := range []struct {
		exit string
		want []string
	}{
		{"Address already in use (os error 98)", []string{"could not listen on port 80", "PBS's daily update"}},
		{"'/usr/share/proxmox-acme/proxmox-acme setup' exited with error (1)",
			[]string{"DNS plugin could not set the TXT record", "The script's output, in the task log"}},
		{"validating challenge 'https://acme-v02.api.letsencrypt.org/acme/chall/1/2/abc' failed - status: Invalid",
			[]string{"could not validate a domain of the node — its challenge ended invalid", "most often the CA did not find the TXT record"}},
		{"urn:ietf:params:acme:error:rateLimited: too many certificates (5) already issued for this exact set of identifiers",
			[]string{"for its rate limits", "staging directory"}},
		{"client error (Connect)", []string{"could not talk to the CA at " + pbsclient.DefaultACMEDirectory,
			"does not use the node's http_proxy"}},
		{"error writing certificate file - No space left on device (os error 28)",
			[]string{"PBS could not write it", "proxy.key", "no longer matches", "counts the certificate against its rate limits"}},
		{"error writing certificate private key - No space left on device (os error 28)",
			[]string{"could not write its key", "still serves its previous certificate"}},
		{"configuration directory '/etc/proxmox-backup' permission problem - wrong permission (755 != 700)",
			[]string{"backup:backup, with mode 700", "still serves its previous certificate"}},
		{"acme account 'le' does not exist", []string{"PBS could not load the node's ACME account", "deleted or replaced"}},
		{"unknown", []string{"stopped without a result", "how far it got is unknown", `ended with exit status "unknown".`}},
		{"urn:ietf:params:acme:error:caa: CAA record for pbs.example.org prevents issuance",
			[]string{"The CA refused the order (caa)", "A CAA record of one of the domains"}},
		{"urn:ietf:params:acme:error:userActionRequired: please agree to the new terms of service",
			[]string{"(userActionRequired)", "tos_url"}},
		{"urn:ietf:params:acme:error:accountDoesNotExist: unable to find existing account for only-return-existing request",
			[]string{"does not know the node's ACME account (accountDoesNotExist)", "no account at the URL", "Pebble", "pbs_acme_account"}},
		{`urn:ietf:params:acme:error:unauthorized: Account is not valid, has status "deactivated"`,
			[]string{"refused the node's ACME account (unauthorized)", "deactivated", "or the CA revoked it", "pbs_acme_account"}},
		{"urn:ietf:params:acme:error:unauthorized: Account that authenticated the request does not own the specified order",
			[]string{"The CA refused the order (unauthorized)"}},
		{"no supported challenge type (http-01) found", []string{"offers no HTTP challenge"}},
		{"order status: Invalid", []string{"turned the order invalid after PBS had validated the domains"}},
		{"kept getting a badNonce error!", []string{"in a way PBS could not use"}},
		{"Could not instantiate notification bus: x", []string{"PBS's task failed", "Common causes"}},
	} {
		t.Run(tc.exit, func(t *testing.T) {
			h, fake, acme := newACMEHarness(t)
			readyForACME(acme)
			before := acme.certificate()
			acme.orderFailure = tc.exit
			config := certificateConfig(t, h, nil)
			applied := h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
			requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to order an ACME certificate for the PBS node")
			for _, want := range append(tc.want, tc.exit, "The task's log: Administration → Tasks") {
				requireProtocolErrorContaining(t, applied.Diagnostics, want)
			}
			for _, d := range applied.Diagnostics {
				if strings.Contains(d.Detail, "The CA did not issue a certificate") || strings.Contains(d.Detail, "does not know task") {
					t.Fatalf("detail = %s", d.Detail)
				}
			}
			if acme.certificate().Fingerprint != before.Fingerprint || fake.count("DELETE /nodes/localhost/certificates/custom") != 0 ||
				!h.decodeResource(t, "pbs_node_certificate", applied.NewState).IsNull() {
				t.Fatal("a failed order changed something")
			}
		})
	}
}

// applyWith is protocolHarness.apply with ctx, which a test may cancel as
// Terraform does on its first Ctrl-C.
func applyWith(ctx context.Context, t *testing.T, h *protocolHarness, typeName string, config tftypes.Value, planned *tfprotov6.PlanResourceChangeResponse) *tfprotov6.ApplyResourceChangeResponse {
	t.Helper()
	resp, err := h.server.ApplyResourceChange(ctx, &tfprotov6.ApplyResourceChangeRequest{
		TypeName:        typeName,
		PriorState:      dynamicValue(t, tftypes.NewValue(h.resourceType(t, typeName), nil)),
		PlannedState:    planned.PlannedState,
		Config:          dynamicValue(t, config),
		PlannedPrivate:  planned.PlannedPrivate,
		PlannedIdentity: planned.PlannedIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// The order waits within the provider's task_timeout. When the wait ends
// first, the task goes on in PBS, which cannot stop an order: the error
// says that the next apply orders another certificate.
func TestNodeCertificateResourceOrderTimeout(t *testing.T) {
	h, fake, acme := newACMEHarness(t, withTaskTimeout("1s"))
	readyForACME(acme)
	tasks := newFakeTasks(fake)
	fake.handle(orderRoute, tasks.starter(func(*http.Request) *fakeTask {
		return &fakeTask{workerType: "acme-new-cert", running: -1, log: []string{"Placing ACME order"}}
	}))
	config := certificateConfig(t, h, nil)

	applied := h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to order an ACME certificate for the PBS node")
	requireProtocolErrorContaining(t, applied.Diagnostics, "which was still running, after its task_timeout")
	requireProtocolErrorContaining(t, applied.Diagnostics, "The task goes on in PBS, which cannot stop an ACME order")
	requireProtocolErrorContaining(t, applied.Diagnostics, "the next one orders another, which counts against the CA's rate limits")
	requireProtocolErrorContaining(t, applied.Diagnostics, "Raise the provider's task_timeout")
	if !h.decodeResource(t, "pbs_node_certificate", applied.NewState).IsNull() {
		t.Fatal("an order that did not finish recorded state")
	}
	for _, task := range tasks.all() {
		if task.aborted {
			t.Fatal("the task was asked to stop")
		}
	}

	// When Terraform stops the apply, it stops waiting at once.
	h2, fake2, acme2 := newACMEHarness(t)
	readyForACME(acme2)
	tasks2 := newFakeTasks(fake2)
	fake2.handle(orderRoute, tasks2.starter(func(*http.Request) *fakeTask {
		return &fakeTask{workerType: "acme-new-cert", running: -1}
	}))
	config = certificateConfig(t, h2, nil)
	planned := h2.plan(t, "pbs_node_certificate", nil, config)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	applied = applyWith(ctx, t, h2, "pbs_node_certificate", config, planned)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the apply went on for %s after it was cancelled", elapsed)
	}
	requireProtocolErrorContaining(t, applied.Diagnostics, "Terraform stopped the apply while PBS task")
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Detail, "Raise the provider's task_timeout") {
			t.Fatalf("detail offers a longer wait for a cancelled apply: %s", d.Detail)
		}
	}
}

// A status poll PBS answers with an error loses the task, which goes on.
func TestNodeCertificateResourceOrderLosesTheTask(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	readyForACME(acme)
	tasks := newFakeTasks(fake)
	fake.handle(orderRoute, tasks.starter(func(*http.Request) *fakeTask {
		return &fakeTask{workerType: "acme-new-cert", running: -1}
	}))
	fake.handlePrefix("GET /nodes/"+fakeTasksNode+"/tasks/", func(w http.ResponseWriter, _ *http.Request) {
		writeFakeResponse(w, http.StatusForbidden, "permission check failed")
	})
	config := certificateConfig(t, h, nil)

	applied := h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "the provider could not follow it")
	requireProtocolErrorContaining(t, applied.Diagnostics, "The task goes on in PBS")
	requireProtocolErrorContaining(t, applied.Diagnostics, "the next one orders another")
	requireProtocolErrorContaining(t, applied.Diagnostics, "permission check failed")
}

// A certificate that cannot be read after the order leaves the provider
// unable to tell whether PBS installed one: after a task that ended well,
// and after one that failed, whose cause the error still names.
func TestNodeCertificateResourceOrderCannotReadTheNewCertificate(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	readyForACME(acme)
	var reads atomic.Int32
	fake.handle("GET /nodes/localhost/certificates/info", func(w http.ResponseWriter, req *http.Request) {
		if reads.Add(1)%2 == 1 {
			acme.certificateInfo(w, req)
			return
		}
		writeFakeResponse(w, http.StatusForbidden, "permission check failed")
	})
	config := certificateConfig(t, h, nil)

	applied := h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "Unable to order an ACME certificate for the PBS node")
	requireProtocolErrorContaining(t, applied.Diagnostics, "ended well, but reading the node's certificate afterwards failed")
	requireProtocolErrorContaining(t, applied.Diagnostics, "does not know whether PBS installed a new one")
	requireProtocolErrorContaining(t, applied.Diagnostics, "`terraform import` records the installed certificate")
	requireProtocolErrorContaining(t, applied.Diagnostics, certificatesPrivilege)
	if !h.decodeResource(t, "pbs_node_certificate", applied.NewState).IsNull() {
		t.Fatal("an order whose certificate could not be read recorded state")
	}

	acme.orderFailure = "Address already in use (os error 98)"
	applied = h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "could not listen on port 80")
	requireProtocolErrorContaining(t, applied.Diagnostics, "Reading the node's certificate afterwards failed too")
	requireProtocolErrorContaining(t, applied.Diagnostics, "reading the certificate after changing it")
}
