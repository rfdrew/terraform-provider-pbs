package provider

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

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
