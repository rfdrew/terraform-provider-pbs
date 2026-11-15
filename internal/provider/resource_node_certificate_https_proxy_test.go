package provider

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// pbs_node_certificate reaching PBS through an HTTPS forward proxy, as an
// https:// URL in HTTPS_PROXY has the provider do. The certificate a new
// connection gets, which the provider compares before and after a change
// (checkProxyLoad), is PBS's, past the forward proxy's own.

// httpsForwardProxy is an HTTPS forward proxy in memory: it presents a
// certificate of its own, answers CONNECT by dialling PBS's in-process TLS
// proxy (certificateProxy), and relays the tunnel both ways.
type httpsForwardProxy struct {
	listener *certificateProxyListener
	// connects counts the CONNECTs it got.
	connects atomic.Int32
}

// serveHTTPSForwardProxy serves a forward proxy that presents cert and
// reaches PBS with dial, until the test ends.
func serveHTTPSForwardProxy(t *testing.T, cert tls.Certificate, dial func(context.Context, string, string) (net.Conn, error)) *httpsForwardProxy {
	t.Helper()
	p := &httpsForwardProxy{listener: &certificateProxyListener{conns: make(chan net.Conn), closed: make(chan struct{})}}
	listener := tls.NewListener(p.listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.tunnel(conn, dial)
		}
	}()
	t.Cleanup(func() { _ = p.listener.Close() })
	return p
}

// tunnel serves one connection: a CONNECT, then the relay.
func (p *httpsForwardProxy) tunnel(conn net.Conn, dial func(context.Context, string, string) (net.Conn, error)) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.connects.Add(1)
	target, err := dial(context.Background(), "tcp", req.Host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = target.Close() }()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, target); done <- struct{}{} }()
	<-done
}

// forwardProxyCertificate is a self-signed certificate for name, and its
// PEM, valid around the time the test runs: the provider verifies it, as
// it verifies an HTTPS proxy's, against the clock.
func forwardProxyCertificate(t *testing.T, name string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newHTTPSForwardProxyHarness is newCertificateProxyHarness with the
// provider reaching PBS's proxy through an HTTPS forward proxy, whose
// certificate ca_cert_file holds.
func newHTTPSForwardProxyHarness(t *testing.T, loads bool) (*certificateProxyHarness, *httpsForwardProxy) {
	t.Helper()
	cert, certPEM := forwardProxyCertificate(t, "forward-proxy.test")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	p := newCertificateProxyHarness(t, loads)
	forward := serveHTTPSForwardProxy(t, cert, p.proxy.listener.dial)
	// A transport of the kind the provider makes, which verifies nothing
	// (see certificateProxy.transport), going through the forward proxy.
	transport := p.proxy.transport()
	transport.DialContext = forward.listener.dial
	transport.Proxy = http.ProxyURL(&url.URL{Scheme: "https", Host: "forward-proxy.test:3128"})
	p.protocolHarness = newProtocolHarness(t, p.acme.fake, withTransport(transport), withCACertFile(caFile))
	return p, forward
}

// Behind an HTTPS forward proxy, an ordered certificate PBS's proxy loads is
// recorded with the advice about the provider's TLS settings, and one it
// does not load fails the apply, as without the forward proxy: neither is
// taken for a TLS front end serving a certificate of its own, which the
// forward proxy's would look like.
func TestNodeCertificateResourceOrderThroughAnHTTPSProxy(t *testing.T) {
	t.Run("loaded", func(t *testing.T) {
		p, forward := newHTTPSForwardProxyHarness(t, true)
		config := certificateConfig(t, p.protocolHarness, nil)

		applied := p.apply(t, "pbs_node_certificate", nil, config, p.plan(t, "pbs_node_certificate", nil, config))
		requireNoProtocolErrors(t, applied.Diagnostics)
		for _, d := range applied.Diagnostics {
			if d.Summary == "The PBS proxy may not serve the new certificate" {
				t.Fatalf("the forward proxy's certificate taken for PBS's: %s", d.Detail)
			}
		}
		requireProtocolWarningContaining(t, applied.Diagnostics, "Pin the new PBS certificate by its fingerprint")
		p.requireLooked(t, 1)
		if got := stringAt(t, p.decodeResource(t, "pbs_node_certificate", applied.NewState), "fingerprint"); got != p.acme.certificate().Fingerprint {
			t.Fatalf("fingerprint = %q, want %q", got, p.acme.certificate().Fingerprint)
		}
		if forward.connects.Load() == 0 {
			t.Fatal("the provider did not go through the forward proxy")
		}
	})

	t.Run("not loaded", func(t *testing.T) {
		p, _ := newHTTPSForwardProxyHarness(t, false)
		config := certificateConfig(t, p.protocolHarness, nil)

		applied := p.apply(t, "pbs_node_certificate", nil, config, p.plan(t, "pbs_node_certificate", nil, config))
		requireProtocolErrorContaining(t, applied.Diagnostics, "The PBS proxy did not load the ordered certificate")
		requireNoTrustAdvice(t, applied.Diagnostics)
		p.requireLooked(t, proxyLoadAttempts)
		if !p.decodeResource(t, "pbs_node_certificate", applied.NewState).IsNull() {
			t.Fatal("an order the proxy did not load recorded state")
		}
	})
}
