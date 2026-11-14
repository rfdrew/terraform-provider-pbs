package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The tests in this file and in resource_node_certificate_proxy_test.go
// serve the fake PBS over TLS in process, as PBS's proxy serves its API, so
// that the provider's client has a TLS transport of its own: only with one
// can it look at the certificate a new connection gets, which is how the
// action and pbs_node_certificate find a proxy that did not load the
// certificate PBS wrote (checkProxyLoad). Over the fake's own transport,
// which answers without TLS, that look always comes back empty.

// certificateProxy serves a fake PBS over TLS with the certificate it
// presents, which tests swap as PBS's proxy swaps its own when it loads a
// new one.
type certificateProxy struct {
	presented  atomic.Pointer[tls.Certificate]
	handshakes atomic.Int32
	listener   *certificateProxyListener
}

// serveCertificateProxy serves fake over TLS until the test ends. It presents
// nothing until present is called.
func serveCertificateProxy(t *testing.T, fake *fakePBS) *certificateProxy {
	t.Helper()
	p := &certificateProxy{listener: &certificateProxyListener{conns: make(chan net.Conn), closed: make(chan struct{})}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		resp, err := fake.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		_ = resp.Body.Close()
	})
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		// The look at the certificate ends each handshake early, which the
		// server would log.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() {
		_ = server.Serve(tls.NewListener(p.listener, &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				p.handshakes.Add(1)
				return p.presented.Load(), nil
			},
			MinVersion: tls.VersionTLS12,
		}))
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = p.listener.Close()
	})
	return p
}

// present has the proxy present chain, leaf first, with the leaf's key, to
// the connections it accepts from now on.
func (p *certificateProxy) present(key *ecdsa.PrivateKey, chain ...*x509.Certificate) {
	certificate := &tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, c := range chain {
		certificate.Certificate = append(certificate.Certificate, c.Raw)
	}
	p.presented.Store(certificate)
}

// transport is an HTTP transport of the kind the provider makes, dialling
// the proxy. It verifies no certificate: the tests are about which one the
// proxy presents, not about trusting it.
func (p *certificateProxy) transport() *http.Transport {
	return &http.Transport{
		DialContext:     p.listener.dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
}

// certificateProxyListener is a net.Listener whose connections come from dial,
// in memory: no socket is opened.
type certificateProxyListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *certificateProxyListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *certificateProxyListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *certificateProxyListener) Addr() net.Addr { return certificateProxyAddr{} }

func (l *certificateProxyListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	toServer, toClient := newCertificateProxyPipe(), newCertificateProxyPipe()
	select {
	case l.conns <- &certificateProxyConn{in: toServer, out: toClient}:
		return &certificateProxyConn{in: toClient, out: toServer}, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// certificateProxyPipe is one direction of an in-memory connection, buffered as a
// socket is. net.Pipe would not do: its writes wait for the other side to
// read, and a client that ends the handshake early writes its alert while
// the server is still writing, so both would wait for good.
type certificateProxyPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newCertificateProxyPipe() *certificateProxyPipe {
	p := &certificateProxyPipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *certificateProxyPipe) read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.buf.Len() == 0 && !p.closed {
		p.cond.Wait()
	}
	if p.buf.Len() == 0 {
		return 0, io.EOF
	}
	return p.buf.Read(b)
}

func (p *certificateProxyPipe) write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	p.buf.Write(b)
	p.cond.Broadcast()
	return len(b), nil
}

func (p *certificateProxyPipe) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cond.Broadcast()
}

// certificateProxyConn is one end of an in-memory connection. Deadlines are
// ignored; closing either end ends both directions.
type certificateProxyConn struct{ in, out *certificateProxyPipe }

func (c *certificateProxyConn) Read(b []byte) (int, error)       { return c.in.read(b) }
func (c *certificateProxyConn) Write(b []byte) (int, error)      { return c.out.write(b) }
func (c *certificateProxyConn) Close() error                     { c.in.close(); c.out.close(); return nil }
func (c *certificateProxyConn) LocalAddr() net.Addr              { return certificateProxyAddr{} }
func (c *certificateProxyConn) RemoteAddr() net.Addr             { return certificateProxyAddr{} }
func (c *certificateProxyConn) SetDeadline(time.Time) error      { return nil }
func (c *certificateProxyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *certificateProxyConn) SetWriteDeadline(time.Time) error { return nil }

type certificateProxyAddr struct{}

func (certificateProxyAddr) Network() string { return "memory" }
func (certificateProxyAddr) String() string  { return "memory" }

// orderRoute is the route of an ACME order, which starts a task.
const orderRoute = "POST /nodes/localhost/certificates/acme/certificate"

// certificateProxyHarness is the ACME fake behind the TLS proxy, serving an
// ACME certificate that the proxy presents. Every order, renewal, upload and
// deletion of the certificate writes a new one, as PBS does, which the proxy
// loads while loads is set; otherwise it keeps presenting what it presented,
// as PBS's proxy does when it cannot load the new certificate. Orders and
// renewals run as tasks of tasks, which end at their first poll.
type certificateProxyHarness struct {
	*protocolHarness
	t     *testing.T
	acme  *fakeACME
	proxy *certificateProxy
	tasks *fakeTasks
	loads atomic.Bool
	// handshakesBefore is how many handshakes the proxy had answered when
	// PBS last wrote a certificate, -1 before it did.
	handshakesBefore atomic.Int32
	// uploadFailure, when set, makes the next upload fail with its text
	// after PBS wrote the certificate, without having the proxy load it, as
	// PBS does when it cannot reach the proxy.
	uploadFailure atomic.Pointer[string]
	// written is the key and chain PBS last wrote, which reload has the
	// proxy load.
	written struct {
		sync.Mutex
		key   *ecdsa.PrivateKey
		chain []*x509.Certificate
	}
}

// newCertificateProxyHarness starts the harness, configured with opts
// besides the proxy's transport.
func newCertificateProxyHarness(t *testing.T, loads bool, opts ...harnessOption) *certificateProxyHarness {
	t.Helper()
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	p := &certificateProxyHarness{t: t, acme: acme, proxy: serveCertificateProxy(t, fake), tasks: newFakeTasks(fake)}
	p.loads.Store(loads)
	p.handshakesBefore.Store(-1)
	key, cert := p.issue()
	acme.mu.Lock()
	acme.cert = certificateInfo(cert, acme.ca)
	acme.mu.Unlock()
	p.proxy.present(key, cert, acme.ca)

	ordering := func(workerType string) http.HandlerFunc {
		return p.tasks.starter(func(*http.Request) *fakeTask {
			return &fakeTask{
				workerType: workerType,
				log:        []string{"Placing ACME order", "All domains validated"},
				onStop: func() {
					key, cert := p.issue()
					p.write(key, certificateInfo(cert, acme.ca), cert, acme.ca)
				},
			}
		})
	}
	fake.handle(orderRoute, ordering("acme-new-cert"))
	fake.handle(renewRoute, ordering("acme-renew-cert"))
	fake.handle("DELETE /nodes/localhost/certificates/custom", func(w http.ResponseWriter, _ *http.Request) {
		key, cert := fakeCertificate(t, "pbs-test", nil, nil)
		info := certificateInfo(cert)
		info.Subject, info.Issuer = fakeSelfSignedIssuer, fakeSelfSignedIssuer
		p.write(key, info, cert)
		writeData(w, nil, "")
	})
	fake.handle("POST /nodes/localhost/certificates/custom", p.upload)
	p.protocolHarness = newProtocolHarness(t, fake, append([]harnessOption{withTransport(p.proxy.transport())}, opts...)...)
	return p
}

// issue has the fake CA issue a certificate for the node's domains.
func (p *certificateProxyHarness) issue() (*ecdsa.PrivateKey, *x509.Certificate) {
	domains := []string{"pbs.example.org", "backup.example.org"}
	return fakeCertificate(p.t, domains[0], domains, p.acme.ca, p.acme.caKey)
}

// write has PBS write info as its certificate, and the proxy load chain,
// leaf first, with key, while loads is set.
func (p *certificateProxyHarness) write(key *ecdsa.PrivateKey, info pbsclient.CertificateInfo, chain ...*x509.Certificate) {
	p.acme.mu.Lock()
	p.acme.cert = info
	p.acme.mu.Unlock()
	p.written.Lock()
	p.written.key, p.written.chain = key, chain
	p.written.Unlock()
	p.handshakesBefore.Store(p.proxy.handshakes.Load())
	if p.loads.Load() {
		p.proxy.present(key, chain...)
	}
}

// reload has the proxy load the certificate PBS last wrote, as `systemctl
// reload proxmox-backup-proxy` does once the cause is fixed.
func (p *certificateProxyHarness) reload() {
	p.written.Lock()
	defer p.written.Unlock()
	p.proxy.present(p.written.key, p.written.chain...)
}

// writeUnserved has PBS write a new certificate the proxy does not load,
// as after a renewal of PBS's daily update the proxy could not load, and
// returns it.
func (p *certificateProxyHarness) writeUnserved() pbsclient.CertificateInfo {
	_, cert := p.issue()
	info := certificateInfo(cert, p.acme.ca)
	p.acme.mu.Lock()
	p.acme.cert = info
	p.acme.mu.Unlock()
	return info
}

// upload serves POST /nodes/localhost/certificates/custom: PBS writes the
// chain, then has the proxy load it, or fails as uploadFailure says.
func (p *certificateProxyHarness) upload(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	certs, err := pbsclient.ParseCertificatesPEM(params.Get("certificates"))
	if err != nil {
		writeError(w, "failed to decode certificate chain: %s", err)
		return
	}
	block, _ := pem.Decode([]byte(params.Get("key")))
	if block == nil {
		writeError(w, "failed to decode private key")
		return
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		writeError(w, "failed to decode private key: %v", err)
		return
	}
	info := certificateInfo(certs[0], certs[1:]...)
	if failure := p.uploadFailure.Swap(nil); failure != nil {
		p.acme.mu.Lock()
		p.acme.cert = info
		p.acme.mu.Unlock()
		p.written.Lock()
		p.written.key, p.written.chain = key, certs
		p.written.Unlock()
		p.handshakesBefore.Store(p.proxy.handshakes.Load())
		writeError(w, "%s", *failure)
		return
	}
	p.write(key, info, certs...)
	writeData(w, nil, "")
}

// requireLooked fails the test unless the provider looked at the
// certificate the proxy presents at least n times after PBS last wrote one.
func (p *certificateProxyHarness) requireLooked(t *testing.T, n int32) {
	t.Helper()
	before := p.handshakesBefore.Load()
	if looks := p.proxy.handshakes.Load() - before; before < 0 || looks < n {
		t.Fatalf("the proxy answered %d handshakes after PBS wrote the certificate (%d before), want at least %d", looks, before, n)
	}
}

// requireNoTrustAdvice fails the test when diags say how to trust a
// certificate the proxy may not serve.
func requireNoTrustAdvice(t *testing.T, diags []*tfprotov6.Diagnostic) {
	t.Helper()
	for _, d := range diags {
		for _, advice := range []string{"Pin the new PBS certificate", "Remove tls_cert_fingerprint", "Remove ca_cert_file", "Set endpoint to a domain"} {
			if strings.Contains(d.Summary, advice) {
				t.Fatalf("advice about a certificate the proxy may not serve: %s: %s", d.Summary, d.Detail)
			}
		}
	}
}

// A proxy that still presents the previous certificate after PBS wrote the
// renewed one could not load it — the task ends OK, while the proxy only
// logs "error reloading certificate" —, and would not start with it: the
// action fails.
func TestNodeCertificateRenewActionProxyKeepsThePreviousCertificate(t *testing.T) {
	p := newCertificateProxyHarness(t, false)

	got := p.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	renewed := p.acme.certificate()
	requireProtocolErrorContaining(t, got.diagnostics, "The PBS proxy did not load the renewed certificate")
	requireProtocolErrorContaining(t, got.diagnostics, "with SHA-256 fingerprint "+renewed.Fingerprint)
	requireProtocolErrorContaining(t, got.diagnostics, "journalctl -u proxmox-backup-proxy")
	// It looked as often as proxyLoaded does before it concludes.
	p.requireLooked(t, proxyLoadAttempts)
	for _, message := range got.progress {
		if strings.Contains(message, "New SHA-256 fingerprint") {
			t.Fatalf("progress reports a certificate the proxy does not serve: %q", got.progress)
		}
	}
}

// A proxy that presents the renewed certificate loaded it.
func TestNodeCertificateRenewActionProxyLoadsTheRenewedCertificate(t *testing.T) {
	p := newCertificateProxyHarness(t, true)

	got := p.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireNoProtocolErrors(t, got.diagnostics)
	p.requireLooked(t, 1)
	requireProgressContaining(t, got, "PBS renewed the certificate of node localhost")
	requireProgressContaining(t, got, "New SHA-256 fingerprint: "+p.acme.certificate().Fingerprint)
}

// A proxy that presented, before the renewal, a certificate other than the
// one PBS reported — the proxy could not load the one PBS's daily update
// wrote, or a TLS front end serves PBS — and still does tells nothing for
// sure: the action warns, naming both, instead of saying how to trust the
// renewed certificate.
func TestNodeCertificateRenewActionProxyServesAnUnreportedCertificate(t *testing.T) {
	p := newCertificateProxyHarness(t, false)
	presented := p.acme.certificate()
	unserved := p.writeUnserved()

	got := p.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProtocolWarningContaining(t, got.diagnostics, "The PBS proxy may not serve the new certificate")
	requireProtocolWarningContaining(t, got.diagnostics, "with SHA-256 fingerprint "+p.acme.certificate().Fingerprint)
	requireProtocolWarningContaining(t, got.diagnostics, "with SHA-256 fingerprint "+presented.Fingerprint)
	requireProtocolWarningContaining(t, got.diagnostics, "although PBS reported another one then, with "+unserved.Fingerprint)
	requireProtocolWarningContaining(t, got.diagnostics, "systemctl reload proxmox-backup-proxy")
	requireNoTrustAdvice(t, got.diagnostics)
	requireProgressContaining(t, got, "PBS renewed the certificate of node localhost")
	for _, message := range got.progress {
		if strings.Contains(message, "New SHA-256 fingerprint") {
			t.Fatalf("progress reports a certificate the proxy may not serve: %q", got.progress)
		}
	}
}
