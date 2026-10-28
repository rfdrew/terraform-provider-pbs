package provider

import (
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// readyForACME gives the fake an account and domains to order for.
func readyForACME(acme *fakeACME) {
	acme.addAccount("le", fakeProperties{"directory": pbsclient.DefaultACMEDirectory, "location": "https://ca/1", "status": "valid"})
	acme.addPlugin("cloudflare", fakeProperties{"api": "cf", "data": "CF_Token=x"})
	acme.setNodeProperty("acme", "account=le")
	acme.setNodeProperty("acmedomain0", "PBS.example.org,plugin=cloudflare")
	acme.setNodeProperty("acmedomain2", "backup.example.org")
}

func certificateConfig(t *testing.T, h *protocolHarness, triggers map[string]any) tftypes.Value {
	t.Helper()
	config := map[string]any{"source": "acme"}
	if triggers != nil {
		config["triggers"] = triggers
	}
	return h.resourceValue(t, "pbs_node_certificate", config)
}

func TestNodeCertificateResourceLifecycle(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	readyForACME(acme)
	selfSigned := acme.certificate().Fingerprint

	config := certificateConfig(t, h, map[string]any{"domains": "backup.example.org,pbs.example.org"})
	planned := h.plan(t, "pbs_node_certificate", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.Diagnostics) != 0 {
		t.Fatalf("plan diagnostics without a pinned fingerprint: %v", planned.Diagnostics)
	}
	applied := h.apply(t, "pbs_node_certificate", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	// The provider verifies against the system's roots, which do not know
	// the fake CA: the certificate is to be pinned.
	requireProtocolWarningContaining(t, applied.Diagnostics, "Pin the new PBS certificate by its fingerprint")
	requireProtocolWarningContaining(t, applied.Diagnostics, "the system's CAs do not trust it")
	inst := &resourceInstance{typeName: "pbs_node_certificate", state: h.decodeResource(t, "pbs_node_certificate", applied.NewState), identity: applied.NewIdentity}

	ordered := acme.certificate()
	if ordered.Fingerprint == selfSigned || fake.count("POST /nodes/localhost/certificates/acme/certificate") != 1 {
		t.Fatal("no certificate was ordered")
	}
	if stringAt(t, inst.state, "fingerprint") != ordered.Fingerprint || stringAt(t, inst.state, "issuer") != "CN=Fake ACME CA" ||
		stringAt(t, inst.state, "subject") != "CN=pbs.example.org" || lengthAt(t, inst.state, "san") != 2 ||
		stringAt(t, inst.state, "not_before") != "2026-09-21T14:13:20Z" || stringAt(t, inst.state, "id") != "localhost" {
		t.Fatalf("state = %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_node_certificate", inst.identity), "node"); got != "localhost" {
		t.Fatalf("identity node = %q", got)
	}
	requireEmptyPlan(t, h, inst, config)

	// PBS renews on its own: a refresh records the new certificate, and
	// plans nothing.
	acme.renew()
	inst = h.refresh(t, inst)
	if stringAt(t, inst.state, "fingerprint") == ordered.Fingerprint {
		t.Fatal("refresh kept the fingerprint of the renewed certificate")
	}
	requireEmptyPlan(t, h, inst, config)

	// New triggers order a new certificate in place.
	config = certificateConfig(t, h, map[string]any{"domains": "backup.example.org,pbs.example.org,www.example.org"})
	acme.setNodeProperty("acmedomain4", "www.example.org")
	replan := h.plan(t, "pbs_node_certificate", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if len(replan.RequiresReplace) > 0 || !isUnknownAt(t, h.decodeResource(t, "pbs_node_certificate", replan.PlannedState), "fingerprint") {
		t.Fatalf("plan for new triggers: replace %v, planned %s", replan.RequiresReplace, h.decodeResource(t, "pbs_node_certificate", replan.PlannedState))
	}
	inst = h.update(t, inst, config)
	if fake.count("POST /nodes/localhost/certificates/acme/certificate") != 2 || fake.count("DELETE /nodes/localhost/certificates/custom") != 0 ||
		lengthAt(t, inst.state, "san") != 3 || stringAt(t, inst.state, "fingerprint") != acme.certificate().Fingerprint {
		t.Fatalf("after new triggers: state %s", inst.state)
	}

	// Destroying goes back to a new self-signed certificate, and says so.
	destroyPlan := h.plan(t, "pbs_node_certificate", inst, tftypes.NewValue(h.resourceType(t, "pbs_node_certificate"), nil))
	requireProtocolWarningContaining(t, destroyPlan.Diagnostics, "new self-signed one")
	destroyed := h.apply(t, "pbs_node_certificate", inst, tftypes.NewValue(h.resourceType(t, "pbs_node_certificate"), nil), destroyPlan)
	requireNoProtocolErrors(t, destroyed.Diagnostics)
	after := acme.certificate()
	if !after.SelfSigned() || after.Fingerprint == selfSigned {
		t.Fatalf("after destroy the node serves %+v", after)
	}
	requireProtocolWarningContaining(t, destroyed.Diagnostics, after.Fingerprint)

	// A self-signed certificate means the ACME one is gone.
	read := h.read(t, inst)
	requireProtocolWarningContaining(t, read.Diagnostics, "serves a self-signed certificate")
	if !h.decodeResource(t, "pbs_node_certificate", read.NewState).IsNull() {
		t.Fatal("refresh kept a certificate that is gone")
	}
}

// A provider that pins the certificate trusts the ordered one for the rest
// of the run, and warns that its configuration must change.
func TestNodeCertificateResourceWithPinnedProvider(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	h := newProtocolHarness(t, fake, withCertFingerprint(acme.certificate().Fingerprint))

	config := certificateConfig(t, h, nil)
	planned := h.plan(t, "pbs_node_certificate", nil, config)
	requireProtocolWarningContaining(t, planned.Diagnostics, "replaces the one the provider pins")
	applied := h.apply(t, "pbs_node_certificate", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	// The system's roots do not know the fake CA, as they do not know Let's
	// Encrypt's staging CAs: the new certificate is to be pinned in turn.
	requireProtocolWarningContaining(t, applied.Diagnostics, "Pin the new PBS certificate by its fingerprint")
	requireProtocolWarningContaining(t, applied.Diagnostics, "the system's CAs do not trust it")
	inst := &resourceInstance{typeName: "pbs_node_certificate", state: h.decodeResource(t, "pbs_node_certificate", applied.NewState), identity: applied.NewIdentity}

	destroyPlan := h.plan(t, "pbs_node_certificate", inst, tftypes.NewValue(h.resourceType(t, "pbs_node_certificate"), nil))
	destroyed := h.apply(t, "pbs_node_certificate", inst, tftypes.NewValue(h.resourceType(t, "pbs_node_certificate"), nil), destroyPlan)
	requireNoProtocolErrors(t, destroyed.Diagnostics)
	requireProtocolWarningContaining(t, destroyed.Diagnostics, "for the rest of this run only")
}

func TestNodeCertificateResourceChecksTheACMESettings(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	config := certificateConfig(t, h, nil)
	apply := func() []*tfprotov6.Diagnostic {
		t.Helper()
		return h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config)).Diagnostics
	}

	requireProtocolErrorContaining(t, apply(), "has no ACME domains")
	acme.setNodeProperty("acmedomain1", "pbs.example.org")
	requireProtocolErrorContaining(t, apply(), `ACME account "default"`)
	acme.setNodeProperty("acme", `account="broken`)
	requireProtocolErrorContaining(t, apply(), "cannot read")
	acme.setNodeProperty("acme", "account=le")
	acme.addAccount("le", fakeProperties{"directory": pbsclient.DefaultACMEDirectory, "status": "valid"})
	acme.setNodeProperty("acmedomain1", "pbs.example.org,plugin=missing")
	requireProtocolErrorContaining(t, apply(), "plugin 'missing' for domain 'pbs.example.org' not found!")
	requireProtocolErrorContaining(t, apply(), "The task log in PBS")
	acme.setNodeProperty("acmedomain1", "pbs.example.org")
	acme.orderFailure = "validation for pbs.example.org failed: connection refused"
	requireProtocolErrorContaining(t, apply(), "connection refused")
	if fake.count("DELETE /nodes/localhost/certificates/custom") != 0 {
		t.Fatal("a failed order deleted the certificate")
	}

	fake.reply("GET /nodes/localhost/config", http.StatusForbidden, "permission check failed")
	requireProtocolErrorContaining(t, apply(), "Sys.Audit on /system")
}

// An import leaves source unset; the next apply records it without
// ordering anything.
func TestNodeCertificateResourceImport(t *testing.T) {
	h, fake, acme := newACMEHarness(t)

	// A node with its self-signed certificate has no ACME certificate to
	// import.
	resp := h.importResource(t, "pbs_node_certificate", "localhost", nil)
	requireNoProtocolErrors(t, resp.Diagnostics)
	read := h.read(t, &resourceInstance{typeName: "pbs_node_certificate", state: h.decodeResource(t, "pbs_node_certificate", resp.ImportedResources[0].State)})
	if !h.decodeResource(t, "pbs_node_certificate", read.NewState).IsNull() {
		t.Fatal("importing a self-signed certificate succeeded")
	}

	readyForACME(acme)
	acme.install("pbs.example.org")
	inst := h.importByIdentity(t, "pbs_node_certificate", map[string]any{"node": "localhost"})
	if !isNullAt(t, inst.state, "source") || stringAt(t, inst.state, "fingerprint") != acme.certificate().Fingerprint {
		t.Fatalf("imported state = %s", inst.state)
	}
	config := certificateConfig(t, h, nil)
	replan := h.plan(t, "pbs_node_certificate", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if len(replan.RequiresReplace) > 0 {
		t.Fatalf("setting source after an import replaces the certificate: %v", replan.RequiresReplace)
	}
	inst = h.update(t, inst, config)
	if fake.count("POST /nodes/localhost/certificates/acme/certificate") != 0 || stringAt(t, inst.state, "source") != "acme" {
		t.Fatalf("after recording source: state %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)

	// Importing and then applying the configuration with triggers records
	// them too, without ordering.
	h2, fake2, acme2 := newACMEHarness(t)
	readyForACME(acme2)
	acme2.install("pbs.example.org")
	imported := h2.importByID(t, "pbs_node_certificate", "localhost")
	withTriggers := certificateConfig(t, h2, map[string]any{"domains": "pbs.example.org"})
	replan = h2.plan(t, "pbs_node_certificate", imported, withTriggers)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if isUnknownAt(t, h2.decodeResource(t, "pbs_node_certificate", replan.PlannedState), "fingerprint") {
		t.Fatal("the first apply after an import plans an order")
	}
	imported = h2.update(t, imported, withTriggers)
	if fake2.count("POST /nodes/localhost/certificates/acme/certificate") != 0 || stringAt(t, imported.state, "triggers", "domains") != "pbs.example.org" {
		t.Fatalf("after recording the triggers: state %s", imported.state)
	}
	requireEmptyPlan(t, h2, imported, withTriggers)

	other := h.importResource(t, "pbs_node_certificate", "pbs_1", nil)
	requireProtocolErrorContaining(t, other.Diagnostics, "by the node's name")
	requireProtocolErrorContaining(t, h.validateResource(t, "pbs_node_certificate", h.resourceValue(t, "pbs_node_certificate",
		map[string]any{"source": "custom"})), "acme")
}

func TestNodeCertificateResourceReadErrors(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	readyForACME(acme)
	inst := h.create(t, "pbs_node_certificate", certificateConfig(t, h, nil))

	fake.reply("GET /nodes/localhost/certificates/info", http.StatusForbidden, "permission check failed")
	requireProtocolErrorContaining(t, h.read(t, inst).Diagnostics, certificatesPrivilege)
	updated := h.apply(t, "pbs_node_certificate", inst, certificateConfig(t, h, map[string]any{"x": "1"}),
		h.plan(t, "pbs_node_certificate", inst, certificateConfig(t, h, map[string]any{"x": "1"})))
	requireProtocolErrorContaining(t, updated.Diagnostics, "reading the certificate before changing it")
	destroyed := h.apply(t, "pbs_node_certificate", inst, tftypes.NewValue(h.resourceType(t, "pbs_node_certificate"), nil),
		h.plan(t, "pbs_node_certificate", inst, tftypes.NewValue(h.resourceType(t, "pbs_node_certificate"), nil)))
	requireProtocolErrorContaining(t, destroyed.Diagnostics, "Unable to delete the certificate")
}

func TestConnectErrorDetailForCertificates(t *testing.T) {
	fake := newFakePBS()
	data := fake.configured(t)
	pinned, err := pbsclient.New(pbsclient.Options{Endpoint: "https://pbs.example.org:8007", APIToken: fakeAPIToken, CertFingerprint: strings.Repeat("ab", 32), Transport: fake})
	if err != nil {
		t.Fatal(err)
	}
	untrusted := &pbsclient.UntrustedCertificateError{Fingerprints: []string{strings.Repeat("cd", 32)}, Pinned: strings.Repeat("ab", 32)}
	if detail := connectErrorDetail(pinned, untrusted); !strings.Contains(detail, "remove tls_cert_fingerprint") ||
		!strings.Contains(detail, pbsclient.FormatFingerprint(strings.Repeat("cd", 32))) {
		t.Fatalf("detail = %q", detail)
	}
	verifying := &pbsclient.UntrustedCertificateError{Fingerprints: []string{strings.Repeat("cd", 32)}, Err: errors.New("x509: certificate signed by unknown authority")}
	if detail := connectErrorDetail(data.client, verifying); !strings.Contains(detail, "does not verify for pbs.test") ||
		!strings.Contains(detail, "set tls_cert_fingerprint") {
		t.Fatalf("detail = %q", detail)
	}
}

// Triggers unknown at plan time plan the certificate's attributes unknown;
// when they turn out unchanged, the update reads the certificate instead of
// ordering one.
func TestNodeCertificateResourceUnknownTriggersUnchanged(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	readyForACME(acme)
	config := certificateConfig(t, h, map[string]any{"domains": "pbs.example.org"})
	inst := h.create(t, "pbs_node_certificate", config)

	planned := h.plan(t, "pbs_node_certificate", inst, certificateConfig(t, h, map[string]any{"domains": tfUnknown}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	plannedState := h.decodeResource(t, "pbs_node_certificate", planned.PlannedState)
	if !isUnknownAt(t, plannedState, "fingerprint") {
		t.Fatalf("planned state = %s, want the certificate unknown", plannedState)
	}
	// What the plan becomes at apply time, with the triggers known again.
	var attrs map[string]tftypes.Value
	if err := plannedState.As(&attrs); err != nil {
		t.Fatal(err)
	}
	attrs["triggers"] = valueAt(t, inst.state, "triggers")
	planned.PlannedState = dynamicValue(t, tftypes.NewValue(plannedState.Type(), attrs))

	applied := h.apply(t, "pbs_node_certificate", inst, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	if got := stringAt(t, h.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != acme.certificate().Fingerprint {
		t.Fatalf("fingerprint = %q", got)
	}
	if fake.count("POST /nodes/localhost/certificates/acme/certificate") != 1 {
		t.Fatal("unchanged triggers ordered a certificate")
	}
}

// A provider that verifies against a CA file which holds the fake CA trusts
// the new certificate's chain, but not for the endpoint's host name.
func TestNodeCertificateResourceWarnsAboutTheEndpoint(t *testing.T) {
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: acme.ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newProtocolHarness(t, fake, withCACertFile(caFile))
	config := certificateConfig(t, h, nil)
	applied := h.apply(t, "pbs_node_certificate", nil, config, h.plan(t, "pbs_node_certificate", nil, config))
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "Set endpoint to a domain of the new PBS certificate")
	requireProtocolWarningContaining(t, applied.Diagnostics, "does not cover pbs.test")
}

// An unknown node in the configuration stays unknown in the plan, as
// Terraform requires; only a node left out is the provider's.
func TestNodeResourcesPlanAnUnknownNode(t *testing.T) {
	h, _, _ := newACMEHarness(t)
	planned := h.plan(t, "pbs_node_certificate", nil, h.resourceValue(t, "pbs_node_certificate", map[string]any{"source": "acme", "node": tfUnknown}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	state := h.decodeResource(t, "pbs_node_certificate", planned.PlannedState)
	if !isUnknownAt(t, state, "node") || !isUnknownAt(t, state, "id") {
		t.Fatalf("planned state = %s, want node and id unknown", state)
	}
}
