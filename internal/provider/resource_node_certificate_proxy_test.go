package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// pbs_node_certificate behind the in-process TLS proxy of
// action_node_certificate_renew_proxy_test.go: after an order, an upload or
// a deletion, the provider looks at the certificate a new connection gets
// (checkProxyLoad).

// An ordered certificate the proxy presents is recorded, with the advice
// about the provider's TLS settings.
func TestNodeCertificateResourceOrderProxyLoadsTheOrderedCertificate(t *testing.T) {
	p := newCertificateProxyHarness(t, true)
	config := certificateConfig(t, p.protocolHarness, nil)

	applied := p.apply(t, "pbs_node_certificate", nil, config, p.plan(t, "pbs_node_certificate", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	p.requireLooked(t, 1)
	ordered := p.acme.certificate()
	if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != ordered.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got, ordered.Fingerprint)
	}
	requireProtocolWarningContaining(t, applied.Diagnostics, "Pin the new PBS certificate by its fingerprint")
}

// A proxy that keeps presenting the certificate it presented before the
// order, which PBS reported then, could not load the ordered one: the apply
// fails, records nothing — and says nothing of trusting a certificate the
// node does not serve, even with a pinned fingerprint. Ordering again,
// while the proxy still has not loaded anything, does not pass silently: the
// proxy now presents what PBS no longer reports, which is only a warning.
func TestNodeCertificateResourceOrderProxyKeepsThePreviousCertificate(t *testing.T) {
	// The proxy's transport verifies nothing (see certificateProxy), so the
	// fingerprint only has the provider pin one, as it would pin PBS's.
	p := newCertificateProxyHarness(t, false, withCertFingerprint(pbsclient.FormatFingerprint(strings.Repeat("ab", 32))))
	previous := p.acme.certificate()
	config := certificateConfig(t, p.protocolHarness, nil)

	planned := p.plan(t, "pbs_node_certificate", nil, config)
	requireProtocolWarningContaining(t, planned.Diagnostics, "replaces the one the provider pins")
	applied := p.apply(t, "pbs_node_certificate", nil, config, planned)
	first := p.acme.certificate()
	requireProtocolErrorContaining(t, applied.Diagnostics, "The PBS proxy did not load the ordered certificate")
	requireProtocolErrorContaining(t, applied.Diagnostics, "with SHA-256 fingerprint "+first.Fingerprint)
	requireProtocolErrorContaining(t, applied.Diagnostics, "journalctl -u proxmox-backup-proxy")
	requireProtocolErrorContaining(t, applied.Diagnostics, "This apply records no certificate")
	requireProtocolErrorContaining(t, applied.Diagnostics, "counts against the CA's rate limits")
	requireProtocolErrorContaining(t, applied.Diagnostics, "`terraform import` after the reload")
	requireNoTrustAdvice(t, applied.Diagnostics)
	p.requireLooked(t, proxyLoadAttempts)
	if !p.decodeResource(t, "pbs_node_certificate", applied.NewState).IsNull() {
		t.Fatal("an order the proxy did not load recorded state")
	}

	// The proxy still presents the first certificate, while PBS reports the
	// one it wrote.
	applied = p.apply(t, "pbs_node_certificate", nil, config, p.plan(t, "pbs_node_certificate", nil, config))
	second := p.acme.certificate()
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "The PBS proxy may not serve the new certificate")
	requireProtocolWarningContaining(t, applied.Diagnostics, "with SHA-256 fingerprint "+second.Fingerprint)
	requireProtocolWarningContaining(t, applied.Diagnostics, "with SHA-256 fingerprint "+previous.Fingerprint)
	requireProtocolWarningContaining(t, applied.Diagnostics, "although PBS reported another one then, with "+first.Fingerprint)
	requireNoTrustAdvice(t, applied.Diagnostics)
	if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != second.Fingerprint {
		t.Fatalf("fingerprint = %q, want the certificate PBS wrote, %q", got, second.Fingerprint)
	}
}

// An update whose certificate the proxy does not load keeps the prior
// state, triggers included, so that the next plan orders again.
func TestNodeCertificateResourceOrderProxyKeepsThePreviousCertificateOnUpdate(t *testing.T) {
	p := newCertificateProxyHarness(t, true)
	inst := p.create(t, "pbs_node_certificate", certificateConfig(t, p.protocolHarness, map[string]any{"x": "1"}))
	prior := stringAt(t, inst.state, "fingerprint")
	if prior != p.acme.certificate().Fingerprint {
		t.Fatalf("fingerprint = %q after the order", prior)
	}

	p.loads.Store(false)
	config := certificateConfig(t, p.protocolHarness, map[string]any{"x": "2"})
	applied := p.apply(t, "pbs_node_certificate", inst, config, p.plan(t, "pbs_node_certificate", inst, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "The PBS proxy did not load the ordered certificate")
	requireNoTrustAdvice(t, applied.Diagnostics)
	kept := p.decodeResource(t, "pbs_node_certificate", applied.NewState)
	if stringAt(t, kept, "fingerprint") != prior || stringAt(t, kept, "triggers", "x") != "1" {
		t.Fatalf("state after the failed update = %s, want the prior one", kept)
	}
	keptInst := &resourceInstance{typeName: "pbs_node_certificate", state: kept, identity: inst.identity}

	// A refresh keeps the certificate the proxy serves, which state
	// recorded, rather than the one PBS wrote, and says so.
	read := p.read(t, keptInst)
	requireProtocolWarningContaining(t, read.Diagnostics, "The PBS proxy has not loaded the node's certificate")
	requireProtocolWarningContaining(t, read.Diagnostics, "with SHA-256 fingerprint "+p.acme.certificate().Fingerprint)
	if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", read.NewState), "fingerprint"); got != prior {
		t.Fatalf("the refresh recorded %q, want the certificate the proxy serves, %q", got, prior)
	}
	replan := p.plan(t, "pbs_node_certificate", keptInst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if !isUnknownAt(t, p.decodeResource(t, "pbs_node_certificate", replan.PlannedState), "fingerprint") {
		t.Fatal("the next plan orders nothing")
	}

	// Ordering again while the proxy still serves the recorded certificate
	// fails again: the proxy served it before, though PBS reported another.
	applied = p.apply(t, "pbs_node_certificate", keptInst, config, replan)
	requireProtocolErrorContaining(t, applied.Diagnostics, "The PBS proxy did not load the ordered certificate")
	requireNoTrustAdvice(t, applied.Diagnostics)

	// Once the proxy loads certificates again, the order goes through.
	p.loads.Store(true)
	applied = p.apply(t, "pbs_node_certificate", keptInst, config, p.plan(t, "pbs_node_certificate", keptInst, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != p.acme.certificate().Fingerprint {
		t.Fatalf("fingerprint = %q, want the ordered certificate, %q", got, p.acme.certificate().Fingerprint)
	}
}

// A node whose proxy presented, before the order, a certificate PBS did not
// report — the proxy could not load the one of PBS's daily update — and
// still does gets the ordered certificate recorded, with a warning naming
// both instead of the advice about the provider's TLS settings.
func TestNodeCertificateResourceOrderProxyServesAnUnreportedCertificate(t *testing.T) {
	p := newCertificateProxyHarness(t, false)
	presented := p.acme.certificate()
	unserved := p.writeUnserved()
	config := certificateConfig(t, p.protocolHarness, nil)

	applied := p.apply(t, "pbs_node_certificate", nil, config, p.plan(t, "pbs_node_certificate", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	ordered := p.acme.certificate()
	requireProtocolWarningContaining(t, applied.Diagnostics, "The PBS proxy may not serve the new certificate")
	requireProtocolWarningContaining(t, applied.Diagnostics, "with SHA-256 fingerprint "+presented.Fingerprint)
	requireProtocolWarningContaining(t, applied.Diagnostics, "although PBS reported another one then, with "+unserved.Fingerprint)
	requireProtocolWarningContaining(t, applied.Diagnostics, "TLS front end")
	requireProtocolWarningContaining(t, applied.Diagnostics, "Pin the new fingerprint nowhere")
	requireNoTrustAdvice(t, applied.Diagnostics)
	if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != ordered.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got, ordered.Fingerprint)
	}
}

// Destroying the resource while the proxy does not load the new self-signed
// certificate fails, and keeps the resource, which a refresh keeps too while
// the proxy serves its certificate; destroying it again fails the same way.
// Once the proxy is reloaded, a refresh finds PBS's own certificate and
// removes the resource.
func TestNodeCertificateResourceDeleteProxyKeepsThePreviousCertificate(t *testing.T) {
	p := newCertificateProxyHarness(t, true)
	inst := p.create(t, "pbs_node_certificate", certificateConfig(t, p.protocolHarness, nil))

	p.loads.Store(false)
	null := tftypes.NewValue(p.resourceType(t, "pbs_node_certificate"), nil)
	destroyed := p.apply(t, "pbs_node_certificate", inst, null, p.plan(t, "pbs_node_certificate", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "The PBS proxy did not load the self-signed certificate")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "with SHA-256 fingerprint "+p.acme.certificate().Fingerprint)
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "stays in state")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "4096 bits")
	p.requireLooked(t, proxyLoadAttempts)
	for _, d := range destroyed.Diagnostics {
		if d.Summary == "The PBS node serves a new self-signed certificate" {
			t.Fatalf("advice to pin a certificate the proxy does not serve: %s", d.Detail)
		}
	}
	kept := p.decodeResource(t, "pbs_node_certificate", destroyed.NewState)
	if kept.IsNull() || stringAt(t, kept, "fingerprint") != stringAt(t, inst.state, "fingerprint") {
		t.Fatalf("state after the failed destroy = %s, want the resource kept", kept)
	}

	read := p.read(t, inst)
	requireProtocolWarningContaining(t, read.Diagnostics, "The PBS proxy has not loaded the node's certificate")
	refreshed := p.decodeResource(t, "pbs_node_certificate", read.NewState)
	if refreshed.IsNull() || stringAt(t, refreshed, "fingerprint") != stringAt(t, inst.state, "fingerprint") {
		t.Fatalf("state after the refresh = %s, want the resource kept", refreshed)
	}

	destroyed = p.apply(t, "pbs_node_certificate", inst, null, p.plan(t, "pbs_node_certificate", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "The PBS proxy did not load the self-signed certificate")
	if p.decodeResource(t, "pbs_node_certificate", destroyed.NewState).IsNull() {
		t.Fatal("the second failed destroy dropped the resource")
	}

	p.reload()
	read = p.read(t, inst)
	requireProtocolWarningContaining(t, read.Diagnostics, "The PBS node serves its own self-signed certificate")
	if !p.decodeResource(t, "pbs_node_certificate", read.NewState).IsNull() {
		t.Fatal("a refresh after the reload kept the resource")
	}
}

// An uploaded certificate the proxy does not load fails the apply, with the
// advice of its own, and records nothing: on Create, nothing a destroy would
// delete, so the advice is to reload the proxy, after which the next apply
// uploads and records the certificate.
func TestNodeCertificateResourceUploadProxyKeepsThePreviousCertificate(t *testing.T) {
	p := newCertificateProxyHarness(t, false)
	custom := newCustomChain(t, "pbs.example.org")
	config := customCertificateConfig(t, p.protocolHarness, custom.chain, custom.key, 1)

	applied := p.apply(t, "pbs_node_certificate", nil, config, p.plan(t, "pbs_node_certificate", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "The PBS proxy did not load the uploaded certificate")
	requireProtocolErrorContaining(t, applied.Diagnostics, "the next apply uploads the certificate again")
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Detail, "destroy pbs_node_certificate") {
			t.Fatalf("advice to destroy a resource that is not in state: %s", d.Detail)
		}
	}
	requireNoTrustAdvice(t, applied.Diagnostics)
	p.requireLooked(t, proxyLoadAttempts)
	if p.acme.certificate().Fingerprint != custom.fingerprint || !p.decodeResource(t, "pbs_node_certificate", applied.NewState).IsNull() {
		t.Fatal("an upload the proxy did not load recorded state")
	}

	p.reload()
	applied = p.apply(t, "pbs_node_certificate", nil, config, p.plan(t, "pbs_node_certificate", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != custom.fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got, custom.fingerprint)
	}
}

// A new custom chain the proxy does not load fails the update, which keeps
// the prior state, with the advice to destroy among others; a refresh keeps
// the certificate the proxy serves, so the next plan uploads again, and so
// does the next apply although the node's file already holds the chain —
// failing again until the proxy loads it, and then recording it with the
// advice about the provider's TLS settings, as for any new certificate.
func TestNodeCertificateResourceUploadProxyKeepsThePreviousCertificateOnUpdate(t *testing.T) {
	// The proxy's transport verifies nothing (see certificateProxy), so the
	// fingerprint only has the provider pin one, as it would pin PBS's.
	p := newCertificateProxyHarness(t, true, withCertFingerprint(pbsclient.FormatFingerprint(strings.Repeat("ab", 32))))
	first := newCustomChain(t, "pbs.example.org")
	inst := p.create(t, "pbs_node_certificate", customCertificateConfig(t, p.protocolHarness, first.chain, first.key, 1))
	if got := stringAt(t, inst.state, "fingerprint"); got != first.fingerprint {
		t.Fatalf("fingerprint = %q after the upload", got)
	}

	p.loads.Store(false)
	second := newCustomChain(t, "pbs.example.org")
	config := customCertificateConfig(t, p.protocolHarness, second.chain, second.key, 1)
	applied := p.apply(t, "pbs_node_certificate", inst, config, p.plan(t, "pbs_node_certificate", inst, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "The PBS proxy did not load the uploaded certificate")
	requireProtocolErrorContaining(t, applied.Diagnostics, "destroy pbs_node_certificate")
	kept := p.decodeResource(t, "pbs_node_certificate", applied.NewState)
	if stringAt(t, kept, "fingerprint") != first.fingerprint {
		t.Fatalf("state after the failed update = %s, want the prior one", kept)
	}
	keptInst := &resourceInstance{typeName: "pbs_node_certificate", state: kept, identity: inst.identity}

	read := p.read(t, keptInst)
	requireProtocolWarningContaining(t, read.Diagnostics, "The PBS proxy has not loaded the node's certificate")
	refreshed := p.decodeResource(t, "pbs_node_certificate", read.NewState)
	if stringAt(t, refreshed, "fingerprint") != first.fingerprint {
		t.Fatalf("the refresh recorded %s, want the certificate the proxy serves", refreshed)
	}
	refreshedInst := &resourceInstance{typeName: "pbs_node_certificate", state: refreshed, identity: inst.identity}
	planned := p.plan(t, "pbs_node_certificate", refreshedInst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if got := p.decodeResource(t, "pbs_node_certificate", planned.PlannedState); got.Equal(refreshed) {
		t.Fatal("the next plan uploads nothing")
	}
	applied = p.apply(t, "pbs_node_certificate", refreshedInst, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "The PBS proxy did not load the uploaded certificate")

	p.loads.Store(true)
	applied = p.apply(t, "pbs_node_certificate", refreshedInst, config, p.plan(t, "pbs_node_certificate", refreshedInst, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != second.fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got, second.fingerprint)
	}
	requireProtocolWarningContaining(t, applied.Diagnostics, "Pin the new PBS certificate by its fingerprint")
	requireProtocolWarningContaining(t, applied.Diagnostics, "fingerprint "+second.fingerprint)
}

// Destroying a custom certificate while the proxy does not load PBS's new
// self-signed one fails, with advice of its own: after the reload, a refresh
// keeps a custom resource, recording what the node serves, rather than
// remove it.
func TestNodeCertificateResourceDeleteCustomProxyKeepsThePreviousCertificate(t *testing.T) {
	p := newCertificateProxyHarness(t, true)
	custom := newCustomChain(t, "pbs.example.org")
	inst := p.create(t, "pbs_node_certificate", customCertificateConfig(t, p.protocolHarness, custom.chain, custom.key, 1))

	p.loads.Store(false)
	null := tftypes.NewValue(p.resourceType(t, "pbs_node_certificate"), nil)
	destroyed := p.apply(t, "pbs_node_certificate", inst, null, p.plan(t, "pbs_node_certificate", inst, null))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "The PBS proxy did not load the self-signed certificate")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "the next refresh keeps the resource")
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "finish with `terraform state rm`")
	selfSigned := p.acme.certificate()

	p.reload()
	read := p.read(t, inst)
	refreshed := p.decodeResource(t, "pbs_node_certificate", read.NewState)
	if refreshed.IsNull() || stringAt(t, refreshed, "fingerprint") != selfSigned.Fingerprint {
		t.Fatalf("state after the reload = %s, want the resource kept with PBS's own certificate %s", refreshed, selfSigned.Fingerprint)
	}
}

// An upload that PBS answered with an error after it wrote the certificate
// — it could not reach the proxy, which never heard of the new certificate
// and presents the old one — is recorded with the advice to reload the
// proxy, not as a certificate the proxy could not load.
func TestNodeCertificateResourceUploadFailsAfterWriting(t *testing.T) {
	p := newCertificateProxyHarness(t, true)
	failure := "unable to open pid file '/run/proxmox-backup/proxy.pid' - No such file or directory"
	p.uploadFailure.Store(&failure)
	custom := newCustomChain(t, "pbs.example.org")
	config := customCertificateConfig(t, p.protocolHarness, custom.chain, custom.key, 1)

	applied := p.apply(t, "pbs_node_certificate", nil, config, p.plan(t, "pbs_node_certificate", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "The PBS certificate upload ended with an error")
	requireProtocolWarningContaining(t, applied.Diagnostics, "systemctl reload proxmox-backup-proxy")
	requireProtocolWarningContaining(t, applied.Diagnostics, "proxy.pid")
	for _, d := range applied.Diagnostics {
		if d.Summary == "The PBS proxy did not load the uploaded certificate" {
			t.Fatalf("an upload PBS never had the proxy load is reported as one the proxy could not load: %s", d.Detail)
		}
	}
	if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != custom.fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got, custom.fingerprint)
	}
}
