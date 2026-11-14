package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The tests in this file serve the fake PBS over TLS in process, as PBS's
// proxy serves its API, so that the provider's client has a TLS transport of
// its own: only with one can it look at the certificate a new connection
// gets, which is how the action finds a proxy that did not load the renewed
// certificate. Over the fake's own transport, which answers without TLS,
// that look always comes back empty.

// renewProxy serves a fake PBS over TLS with the certificate it presents,
// which tests swap as PBS's proxy swaps its own when it loads a new one.
type renewProxy struct {
	presented  atomic.Pointer[tls.Certificate]
	handshakes atomic.Int32
	listener   *renewProxyListener
}

// serveRenewProxy serves fake over TLS until the test ends. It presents
// nothing until present is called.
func serveRenewProxy(t *testing.T, fake *fakePBS) *renewProxy {
	t.Helper()
	p := &renewProxy{listener: &renewProxyListener{conns: make(chan net.Conn), closed: make(chan struct{})}}
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
func (p *renewProxy) present(key *ecdsa.PrivateKey, chain ...*x509.Certificate) {
	certificate := &tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, c := range chain {
		certificate.Certificate = append(certificate.Certificate, c.Raw)
	}
	p.presented.Store(certificate)
}

// transport is an HTTP transport of the kind the provider makes, dialling
// the proxy. It verifies no certificate: the tests are about which one the
// proxy presents, not about trusting it.
func (p *renewProxy) transport() *http.Transport {
	return &http.Transport{
		DialContext:     p.listener.dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
}

// renewProxyListener is a net.Listener whose connections come from dial,
// in memory: no socket is opened.
type renewProxyListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *renewProxyListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *renewProxyListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *renewProxyListener) Addr() net.Addr { return renewProxyAddr{} }

func (l *renewProxyListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	toServer, toClient := newRenewProxyPipe(), newRenewProxyPipe()
	select {
	case l.conns <- &renewProxyConn{in: toServer, out: toClient}:
		return &renewProxyConn{in: toClient, out: toServer}, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// renewProxyPipe is one direction of an in-memory connection, buffered as a
// socket is. net.Pipe would not do: its writes wait for the other side to
// read, and a client that ends the handshake early writes its alert while
// the server is still writing, so both would wait for good.
type renewProxyPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newRenewProxyPipe() *renewProxyPipe {
	p := &renewProxyPipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *renewProxyPipe) read(b []byte) (int, error) {
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

func (p *renewProxyPipe) write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	p.buf.Write(b)
	p.cond.Broadcast()
	return len(b), nil
}

func (p *renewProxyPipe) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cond.Broadcast()
}

// renewProxyConn is one end of an in-memory connection. Deadlines are
// ignored; closing either end ends both directions.
type renewProxyConn struct{ in, out *renewProxyPipe }

func (c *renewProxyConn) Read(b []byte) (int, error)       { return c.in.read(b) }
func (c *renewProxyConn) Write(b []byte) (int, error)      { return c.out.write(b) }
func (c *renewProxyConn) Close() error                     { c.in.close(); c.out.close(); return nil }
func (c *renewProxyConn) LocalAddr() net.Addr              { return renewProxyAddr{} }
func (c *renewProxyConn) RemoteAddr() net.Addr             { return renewProxyAddr{} }
func (c *renewProxyConn) SetDeadline(time.Time) error      { return nil }
func (c *renewProxyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *renewProxyConn) SetWriteDeadline(time.Time) error { return nil }

type renewProxyAddr struct{}

func (renewProxyAddr) Network() string { return "memory" }
func (renewProxyAddr) String() string  { return "memory" }

// newRenewProxyHarness is the ACME fake behind the TLS proxy, serving an
// ACME certificate, whose renewal installs a new one; the proxy loads it
// when loads is set, and otherwise keeps presenting the previous one, as
// PBS's proxy does when it cannot load the new certificate. It returns the
// renewed certificate, and how many handshakes the proxy had answered when
// the renewal installed it.
func newRenewProxyHarness(t *testing.T, loads bool) (*protocolHarness, *renewProxy, pbsclient.CertificateInfo, *atomic.Int32) {
	t.Helper()
	fake := newFakePBS()
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	domains := []string{"pbs.example.org"}
	previousKey, previous := fakeCertificate(t, domains[0], domains, acme.ca, acme.caKey)
	renewedKey, renewed := fakeCertificate(t, domains[0], domains, acme.ca, acme.caKey)
	acme.mu.Lock()
	acme.cert = certificateInfo(previous, acme.ca)
	acme.mu.Unlock()

	proxy := serveRenewProxy(t, fake)
	proxy.present(previousKey, previous, acme.ca)
	var handshakesBefore atomic.Int32
	handshakesBefore.Store(-1)
	tasks := newFakeTasks(fake)
	renewWithTasks(fake, tasks, func() *fakeTask {
		return &fakeTask{
			log: []string{"Placing ACME order", "All domains validated"},
			onStop: func() {
				acme.mu.Lock()
				acme.cert = certificateInfo(renewed, acme.ca)
				acme.mu.Unlock()
				handshakesBefore.Store(proxy.handshakes.Load())
				if loads {
					proxy.present(renewedKey, renewed, acme.ca)
				}
			},
		}
	})
	return newProtocolHarness(t, fake, withTransport(proxy.transport())), proxy, certificateInfo(renewed, acme.ca), &handshakesBefore
}

// A proxy that still presents the previous certificate after PBS wrote the
// renewed one could not load it — the task ends OK, while the proxy only
// logs "error reloading certificate" —, and would not start with it: the
// action fails.
func TestNodeCertificateRenewActionProxyKeepsThePreviousCertificate(t *testing.T) {
	h, proxy, renewed, handshakesBefore := newRenewProxyHarness(t, false)

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireProtocolErrorContaining(t, got.diagnostics, "The PBS proxy did not load the renewed certificate")
	requireProtocolErrorContaining(t, got.diagnostics, "with SHA-256 fingerprint "+renewed.Fingerprint)
	requireProtocolErrorContaining(t, got.diagnostics, "journalctl -u proxmox-backup-proxy")
	// It looked as often as proxyKeptPrevious does before it concludes.
	if looks := proxy.handshakes.Load() - handshakesBefore.Load(); handshakesBefore.Load() < 0 || looks < proxyLoadAttempts {
		t.Fatalf("the proxy answered %d handshakes after the renewal, want at least %d", looks, proxyLoadAttempts)
	}
	for _, message := range got.progress {
		if strings.Contains(message, "New SHA-256 fingerprint") {
			t.Fatalf("progress reports a certificate the proxy does not serve: %q", got.progress)
		}
	}
}

// A proxy that presents the renewed certificate loaded it.
func TestNodeCertificateRenewActionProxyLoadsTheRenewedCertificate(t *testing.T) {
	h, proxy, renewed, handshakesBefore := newRenewProxyHarness(t, true)

	got := h.invokeAction(t, "pbs_node_certificate_renew", map[string]any{"force": true})
	requireNoProtocolErrors(t, got.diagnostics)
	if handshakesBefore.Load() < 0 || proxy.handshakes.Load() <= handshakesBefore.Load() {
		t.Fatalf("nothing looked at the certificate the proxy presents after the renewal: %d handshakes, %d before it",
			proxy.handshakes.Load(), handshakesBefore.Load())
	}
	requireProgressContaining(t, got, "PBS renewed the certificate of node localhost")
	requireProgressContaining(t, got, "New SHA-256 fingerprint: "+renewed.Fingerprint)
}
