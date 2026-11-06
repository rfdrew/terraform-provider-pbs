package provider

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// customChain is a certificate for pbs.example.org from a private CA: the
// chain, leaf first, its key, and the leaf's fingerprint as PBS shows it.
type customChain struct {
	leaf        *x509.Certificate
	ca          *x509.Certificate
	chain       string
	key         string
	fingerprint string
}

func newCustomChain(t *testing.T, cn string) customChain {
	t.Helper()
	caKey, ca := fakeCertificate(t, "Private CA", nil, nil)
	key, leaf := fakeCertificate(t, cn, []string{cn}, ca, caKey)
	return customChain{
		leaf:        leaf,
		ca:          ca,
		chain:       pemOf(leaf) + pemOf(ca),
		key:         ecKeyPEM(t, key),
		fingerprint: pbsclient.FormatFingerprint(pbsclient.CertificateFingerprint(leaf)),
	}
}

func pemOf(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func ecKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func customCertificateConfig(t *testing.T, h *protocolHarness, chain, key string, version int) tftypes.Value {
	t.Helper()
	return h.resourceValue(t, "pbs_node_certificate", map[string]any{
		"source": "custom", "certificates": chain, "key_wo": key, "key_wo_version": version,
	})
}

func TestNodeCertificateResourceCustom(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	serveCustomCertificates(t, acme)
	custom := newCustomChain(t, "pbs.example.org")

	config := customCertificateConfig(t, h, custom.chain, custom.key, 1)
	planned := h.plan(t, "pbs_node_certificate", nil, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if got := stringAt(t, h.decodeResource(t, "pbs_node_certificate", planned.PlannedState), "fingerprint"); got != custom.fingerprint {
		t.Fatalf("planned fingerprint %q, want %q", got, custom.fingerprint)
	}
	applied := h.apply(t, "pbs_node_certificate", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "Pin the new PBS certificate by its fingerprint")
	inst := &resourceInstance{typeName: "pbs_node_certificate", state: h.decodeResource(t, "pbs_node_certificate", applied.NewState), identity: applied.NewIdentity}
	upload := fake.lastCall(t, "POST /nodes/localhost/certificates/custom").form
	if upload.Get("certificates") != custom.chain || upload.Get("key") != custom.key || upload.Has("restart") || upload.Has("force") {
		t.Fatalf("upload = %v", upload)
	}
	if acme.certificate().Fingerprint != custom.fingerprint || stringAt(t, inst.state, "subject") != "CN=pbs.example.org" ||
		stringAt(t, inst.state, "issuer") != "CN=Private CA" || !isNullAt(t, inst.state, "key_wo") {
		t.Fatalf("state = %s", inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
	inst = h.refresh(t, inst)
	requireEmptyPlan(t, h, inst, config)

	// The same chain laid out otherwise is no new certificate.
	uploads := fake.count("POST /nodes/localhost/certificates/custom")
	relaid := strings.ReplaceAll(custom.chain, "-----\n-----BEGIN", "-----\n\n# the CA\n-----BEGIN")
	inst = h.update(t, inst, customCertificateConfig(t, h, relaid, custom.key, 1))
	if fake.count("POST /nodes/localhost/certificates/custom") != uploads {
		t.Fatal("a new layout of the same chain uploaded it again")
	}

	// PBS renews with ACME on a node with ACME domains: the next apply
	// uploads the custom certificate again.
	acme.install("pbs.example.org")
	read := h.read(t, inst)
	requireProtocolWarningContaining(t, read.Diagnostics, "serves another certificate")
	inst.state = h.decodeResource(t, "pbs_node_certificate", read.NewState)
	inst = h.update(t, inst, config)
	if fake.count("POST /nodes/localhost/certificates/custom") != uploads+1 || acme.certificate().Fingerprint != custom.fingerprint {
		t.Fatal("the custom certificate was not uploaded again")
	}
	requireEmptyPlan(t, h, inst, config)

	// A new key version sends the key again, even for the same chain.
	inst = h.update(t, inst, customCertificateConfig(t, h, custom.chain, custom.key, 2))
	if fake.count("POST /nodes/localhost/certificates/custom") != uploads+2 {
		t.Fatal("a new key version uploaded nothing")
	}

	// A new chain is uploaded in place, with a fingerprint known in the plan.
	renewed := newCustomChain(t, "pbs.example.org")
	config = customCertificateConfig(t, h, renewed.chain, renewed.key, 3)
	replan := h.plan(t, "pbs_node_certificate", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if len(replan.RequiresReplace) != 0 || stringAt(t, h.decodeResource(t, "pbs_node_certificate", replan.PlannedState), "fingerprint") != renewed.fingerprint {
		t.Fatalf("replan replaces %v", replan.RequiresReplace)
	}
	inst = h.update(t, inst, config)
	if acme.certificate().Fingerprint != renewed.fingerprint || fake.count("DELETE /nodes/localhost/certificates/custom") != 0 {
		t.Fatal("the new chain was not uploaded in place")
	}

	// Switching to ACME orders in place, without a self-signed certificate
	// between.
	readyForACME(acme)
	acmeConfig := certificateConfig(t, h, nil)
	replan = h.plan(t, "pbs_node_certificate", inst, acmeConfig)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if len(replan.RequiresReplace) != 0 {
		t.Fatalf("switching to ACME replaces %v", replan.RequiresReplace)
	}
	inst = h.update(t, inst, acmeConfig)
	if fake.count("POST /nodes/localhost/certificates/acme/certificate") != 1 || fake.count("DELETE /nodes/localhost/certificates/custom") != 0 ||
		!strings.Contains(acme.certificate().Issuer, "Fake ACME CA") {
		t.Fatalf("switching to ACME: %v", fake.routes())
	}

	// And back, with a warning about the ACME domains, which renew it away.
	config = customCertificateConfig(t, h, custom.chain, custom.key, 1)
	planned = h.plan(t, "pbs_node_certificate", inst, config)
	applied = h.apply(t, "pbs_node_certificate", inst, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "replace the custom certificate with an ACME one")
	inst = &resourceInstance{typeName: "pbs_node_certificate", state: h.decodeResource(t, "pbs_node_certificate", applied.NewState), identity: applied.NewIdentity}

	h.destroy(t, inst)
	if !acme.certificate().SelfSigned() {
		t.Fatal("destroying left the custom certificate")
	}
}

// An import uploads nothing when the node serves the configured chain.
func TestNodeCertificateResourceCustomImport(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	serveCustomCertificates(t, acme)
	custom := newCustomChain(t, "pbs.example.org")
	acme.cert = certificateInfo(custom.leaf, custom.ca)

	inst := h.importByID(t, "pbs_node_certificate", "localhost")
	config := customCertificateConfig(t, h, custom.chain, custom.key, 1)
	planned := h.plan(t, "pbs_node_certificate", inst, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if stringAt(t, h.decodeResource(t, "pbs_node_certificate", planned.PlannedState), "fingerprint") != custom.fingerprint {
		t.Fatal("the first apply after an import plans a new fingerprint")
	}
	inst = h.update(t, inst, config)
	if fake.count("POST /nodes/localhost/certificates/custom") != 0 || stringAt(t, inst.state, "source") != "custom" {
		t.Fatalf("after the import: %v, state %s", fake.routes(), inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
}

func TestNodeCertificateResourceCustomValidation(t *testing.T) {
	h, _, _ := newACMEHarness(t)
	custom := newCustomChain(t, "pbs.example.org")
	other := newCustomChain(t, "other.example.org")
	ca := strings.SplitAfter(custom.chain, "-----END CERTIFICATE-----\n")[1]
	leaf := strings.TrimSuffix(custom.chain, ca)
	for _, tc := range []struct {
		attrs map[string]any
		want  string
	}{
		{map[string]any{"source": "custom", "certificates": custom.chain, "key_wo": other.key, "key_wo_version": 1}, "not the key of the first certificate"},
		{map[string]any{"source": "custom", "certificates": ca + leaf, "key_wo": custom.key, "key_wo_version": 1}, "not the key of the first certificate"},
		{map[string]any{"source": "custom", "certificates": custom.chain + custom.key, "key_wo": custom.key, "key_wo_version": 1}, "not a CERTIFICATE"},
		{map[string]any{"source": "custom", "certificates": "none", "key_wo": custom.key, "key_wo_version": 1}, "no PEM-encoded certificate"},
		{map[string]any{"source": "custom", "certificates": custom.chain}, "needs key_wo"},
		{map[string]any{"source": "custom", "key_wo": custom.key, "key_wo_version": 1}, "needs certificates"},
		{map[string]any{"source": "custom", "certificates": custom.chain, "key_wo": custom.key}, "key_wo_version"},
		{map[string]any{"source": "custom", "certificates": custom.chain, "key_wo": custom.key, "key_wo_version": 1,
			"triggers": map[string]any{"x": "y"}}, "order ACME certificates"},
		{map[string]any{"source": "acme", "certificates": custom.chain}, "needs a custom certificate"},
		{map[string]any{"source": "acme", "key_wo": custom.key, "key_wo_version": 1}, "needs a custom certificate"},
	} {
		requireProtocolErrorContaining(t, h.validateResource(t, "pbs_node_certificate", h.resourceValue(t, "pbs_node_certificate", tc.attrs)), tc.want)
	}
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_node_certificate", customCertificateConfig(t, h, leaf, custom.key, 1)))
}

// A certificate PBS reports after the upload that is not the one uploaded
// fails the apply, and nothing is recorded.
func TestNodeCertificateResourceCustomOtherCertificateInstalled(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	custom := newCustomChain(t, "pbs.example.org")
	other := newCustomChain(t, "other.example.org")
	fake.handle("POST /nodes/localhost/certificates/custom", func(w http.ResponseWriter, _ *http.Request) {
		acme.mu.Lock()
		defer acme.mu.Unlock()
		acme.cert = certificateInfo(other.leaf, other.ca)
		writeData(w, []pbsclient.CertificateInfo{acme.cert}, "")
	})
	config := customCertificateConfig(t, h, custom.chain, custom.key, 1)
	planned := h.plan(t, "pbs_node_certificate", nil, config)
	applied := h.apply(t, "pbs_node_certificate", nil, config, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "PBS installed another certificate")
	if !h.decodeResource(t, "pbs_node_certificate", applied.NewState).IsNull() {
		t.Fatal("a failed upload recorded state")
	}
}

// A self-signed certificate of one's own is a custom certificate like any
// other: importing a node that serves one keeps it, and the first apply
// uploads nothing.
func TestNodeCertificateResourceCustomSelfSignedImport(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	serveCustomCertificates(t, acme)
	key, cert := fakeCertificate(t, "pbs.example.org", []string{"pbs.example.org"}, nil)
	acme.cert = certificateInfo(cert)

	inst := h.importByID(t, "pbs_node_certificate", "localhost")
	config := customCertificateConfig(t, h, pemOf(cert), ecKeyPEM(t, key), 1)
	inst = h.update(t, inst, config)
	if fake.count("POST /nodes/localhost/certificates/custom") != 0 || stringAt(t, inst.state, "source") != "custom" {
		t.Fatalf("after the import: %v, state %s", fake.routes(), inst.state)
	}
	requireEmptyPlan(t, h, inst, config)
}
