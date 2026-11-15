package pbsclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// swappableServer serves a fake PBS over TLS, through serveTLS's in-memory
// pipes, with a certificate a test can replace while it runs: like PBS's
// proxy loading a new certificate, the new one is presented on new
// connections only, and open connections keep theirs.
type swappableServer struct {
	current atomic.Pointer[testCertificate]
}

func (s *swappableServer) swap(cert testCertificate) { s.current.Store(&cert) }

// info is GET /nodes/{node}/certificates/info for the current certificate.
func (s *swappableServer) info() string {
	cert := s.current.Load()
	encoded, _ := json.Marshal(map[string]any{"data": []map[string]any{{
		"filename":    ProxyCertificateFile,
		"fingerprint": FormatFingerprint(CertificateFingerprint(cert.cert)),
		"subject":     cert.cert.Subject.String(),
		"issuer":      cert.cert.Issuer.String(),
		"notbefore":   cert.cert.NotBefore.Unix(),
		"notafter":    cert.cert.NotAfter.Unix(),
		"san":         cert.cert.DNSNames,
		"pem":         string(cert.pem),
	}}})
	return string(encoded)
}

// serveSwappableTLS serves fake with initial as the certificate and returns
// a client for opts, wired to dial it.
func serveSwappableTLS(t *testing.T, fake *fakePBS, initial testCertificate, opts Options) (*Client, *swappableServer) {
	t.Helper()
	s := &swappableServer{}
	s.swap(initial)

	listener := newPipeListener()
	server := &http.Server{Handler: http.HandlerFunc(fake.serveRecorded), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &s.current.Load().tlsCert, nil },
			MinVersion:     tls.VersionTLS12,
		}))
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})

	if opts.Username == "" {
		opts.APIToken = fakeAPIToken
	}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.httpClient.Transport)
	}
	transport.DialContext = listener.dial
	transport.Proxy = nil
	c.sleep = noSleep
	return c, s
}

// An acme-new-cert UPID: PBS gives the task no worker ID.
const orderUPID = "UPID:localhost:00000A1B:00001C2D:00000004:6AE11CDF:acme-new-cert::tfacc@pbs!acc:"

const orderStatusRoute = "GET /nodes/localhost/tasks/" + orderUPID + "/status"

// orderAndWait orders a certificate and waits for the task, as the
// provider does within a change.
func orderAndWait(ctx context.Context, c *Client, node string) error {
	upid, err := c.OrderACMECertificate(ctx, node)
	if err != nil {
		return err
	}
	_, err = c.WaitTask(ctx, upid)
	return err
}

func routeInfo(fake *fakePBS, s *swappableServer) {
	fake.handle("GET /nodes/localhost/certificates/info", func(w http.ResponseWriter, _ *http.Request) {
		writeFakeResponse(w, http.StatusOK, s.info())
	})
}

func TestChangeCertificateTrustsTheOrderedCertificate(t *testing.T) {
	old := newTestCertificate(t, "pbs.test")
	ordered := newTestCertificate(t, "pbs.example.com")
	fake := newFakePBS()
	c, server := serveSwappableTLS(t, fake, old, Options{Endpoint: "https://pbs.test:8007", CertFingerprint: CertificateFingerprint(old.cert)})
	routeInfo(fake, server)
	fake.reply("POST /nodes/localhost/certificates/acme/certificate", http.StatusOK, `{"data":"`+orderUPID+`"}`)

	// Another call of the same client meets the new certificate while the
	// task is still running: it waits for the change and goes through.
	conf := transportTLS(t, c)
	verify := conf.VerifyConnection
	rejected := make(chan struct{}, 8)
	conf.VerifyConnection = func(state tls.ConnectionState) error {
		err := verify(state)
		if err != nil {
			rejected <- struct{}{}
		}
		return err
	}
	var concurrent sync.WaitGroup
	var concurrentErr error
	fake.handle(orderStatusRoute, func(w http.ResponseWriter, _ *http.Request) {
		server.swap(ordered)
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			_, concurrentErr = c.ServerVersion(context.Background())
		}()
		select {
		case <-rejected:
		case <-time.After(5 * time.Second):
			t.Error("the concurrent call never met the new certificate")
		}
		writeFakeResponse(w, http.StatusOK, `{"data":{"status":"stopped","exitstatus":"OK"}}`)
	})

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(ctx context.Context) error {
		return orderAndWait(ctx, c, "localhost")
	})
	if err != nil {
		t.Fatalf("ChangeCertificate() error = %v", err)
	}
	concurrent.Wait()
	if concurrentErr != nil {
		t.Fatalf("the concurrent call failed: %v", concurrentErr)
	}
	if !change.Changed() || change.Before.Fingerprint != FormatFingerprint(CertificateFingerprint(old.cert)) ||
		change.After.Fingerprint != FormatFingerprint(CertificateFingerprint(ordered.cert)) {
		t.Fatalf("ChangeCertificate() = %+v, want the old and the ordered certificate", change)
	}
	if change.PresentedBefore != CertificateFingerprint(old.cert) {
		t.Fatalf("PresentedBefore = %q, want the old certificate's normalised fingerprint", change.PresentedBefore)
	}

	// New connections of the client trust the ordered certificate now.
	c.httpClient.CloseIdleConnections()
	if _, err := c.ServerVersion(context.Background()); err != nil {
		t.Fatalf("ServerVersion() after the change error = %v", err)
	}
	if !c.PinsCertificate() {
		t.Fatal("PinsCertificate() = false: the settings must stay as configured")
	}
	if err := c.VerifyCertificatePEM(string(ordered.pem)); err == nil {
		t.Fatal("VerifyCertificatePEM() accepted the ordered certificate: the pinned fingerprint alone must not")
	}

	// A new client with the same settings does not.
	fresh, _ := serveSwappableTLS(t, newFakePBS(), ordered, Options{Endpoint: "https://pbs.test:8007", CertFingerprint: CertificateFingerprint(old.cert)})
	_, err = fresh.ServerVersion(context.Background())
	var untrusted *UntrustedCertificateError
	if !errors.As(err, &untrusted) || untrusted.Presented() != CertificateFingerprint(ordered.cert) {
		t.Fatalf("a new client's ServerVersion() error = %v, want an *UntrustedCertificateError presenting the ordered certificate", err)
	}
}

func TestChangeCertificateRevertsToSelfSigned(t *testing.T) {
	// A client verifying against a CA trusts the new self-signed
	// certificate too, which no CA vouches for.
	acme := newTestCertificate(t, "pbs.test")
	selfSigned := newTestCertificate(t, "pbs-acc")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, acme.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	fake := newFakePBS()
	c, server := serveSwappableTLS(t, fake, acme, Options{Endpoint: "https://pbs.test:8007", CAFile: caFile})
	routeInfo(fake, server)
	fake.handle("DELETE /nodes/localhost/certificates/custom", func(w http.ResponseWriter, _ *http.Request) {
		server.swap(selfSigned)
		writeFakeResponse(w, http.StatusOK, `{"data":null}`)
	})

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(ctx context.Context) error {
		return c.DeleteCustomCertificate(ctx, "localhost")
	})
	if err != nil || !change.Changed() || change.After.Fingerprint != FormatFingerprint(CertificateFingerprint(selfSigned.cert)) {
		t.Fatalf("ChangeCertificate() = %+v, %v, want the new self-signed certificate", change, err)
	}
	c.httpClient.CloseIdleConnections()
	if _, err := c.ServerVersion(context.Background()); err != nil {
		t.Fatalf("ServerVersion() after the change error = %v", err)
	}
	if err := c.VerifyCertificatePEM(change.After.PEM); err == nil {
		t.Fatal("VerifyCertificatePEM() accepted the self-signed certificate against the CA file")
	}
}

// When the connection of the change closes, the new certificate can only
// be read over a new connection, which presents it; the client does not
// trust what it cannot confirm.
func TestChangeCertificateWithoutTheTrustedConnection(t *testing.T) {
	old := newTestCertificate(t, "pbs.test")
	ordered := newTestCertificate(t, "pbs.example.com")
	fake := newFakePBS()
	c, server := serveSwappableTLS(t, fake, old, Options{Endpoint: "https://pbs.test:8007", CertFingerprint: CertificateFingerprint(old.cert)})
	routeInfo(fake, server)
	fake.reply("POST /nodes/localhost/certificates/acme/certificate", http.StatusOK, `{"data":"`+orderUPID+`"}`)
	fake.handle(orderStatusRoute, func(w http.ResponseWriter, _ *http.Request) {
		server.swap(ordered)
		w.Header().Set("Connection", "close")
		writeFakeResponse(w, http.StatusOK, `{"data":{"status":"stopped","exitstatus":"OK"}}`)
	})

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(ctx context.Context) error {
		return orderAndWait(ctx, c, "localhost")
	})
	if err != nil || !change.Changed() || change.Unconfirmed == nil || change.Unconfirmed.Presented != CertificateFingerprint(ordered.cert) ||
		change.After.Fingerprint != "" {
		t.Fatalf("ChangeCertificate() = %+v, %v, want the ordered certificate unconfirmed", change, err)
	}
	var untrusted *UntrustedCertificateError
	if !errors.As(change.Unconfirmed, &untrusted) || !strings.Contains(change.Unconfirmed.Error(), FormatFingerprint(CertificateFingerprint(ordered.cert))) {
		t.Fatalf("Unconfirmed = %v, want the new fingerprint and the untrusted certificate", change.Unconfirmed)
	}
	c.httpClient.CloseIdleConnections()
	if _, err := c.ServerVersion(context.Background()); err == nil {
		t.Fatal("the client trusts a certificate it could not confirm")
	}
}

func TestChangeCertificateReportsTheTaskError(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	var calls int
	fake.handle("GET /nodes/localhost/certificates/info", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		writeFakeResponse(w, http.StatusOK, `{"data":[{"filename":"proxy.pem","fingerprint":"`+FormatFingerprint(strings.Repeat("ab", 32))+`","subject":"CN=pbs","issuer":"CN=pbs"}]}`)
	})
	fake.reply("POST /nodes/localhost/certificates/acme/certificate", http.StatusOK, `{"data":"`+orderUPID+`"}`)
	fake.reply(orderStatusRoute, http.StatusOK, `{"data":{"status":"stopped","exitstatus":"validating challenge 'https://ca.test/chall/1' failed - status: Invalid"}}`)

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(ctx context.Context) error {
		return orderAndWait(ctx, c, "localhost")
	})
	var taskErr *TaskError
	if !errors.As(err, &taskErr) || change.Changed() || calls != 2 || !change.Before.SelfSigned() {
		t.Fatalf("ChangeCertificate() = %+v, %v after %d reads, want the task error and the unchanged certificate read twice", change, err, calls)
	}
	// The fake's transport is not the client's own: there is nothing to
	// look at.
	if change.PresentedBefore != "" {
		t.Fatalf("PresentedBefore = %q without a TLS transport", change.PresentedBefore)
	}
	if failure, ok := ACMEOrderFailureOf(err); !ok || failure.Cause != ACMEOrderValidationFailed {
		t.Fatalf("ACMEOrderFailureOf() = %+v, %v", failure, ok)
	}
}

// A read of the certificate that fails after the change is a
// *CertificateReadError, joined with the change's own error, if any.
func TestChangeCertificateFailsToReadTheNewCertificate(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	info := `{"data":[{"filename":"proxy.pem","fingerprint":"` + FormatFingerprint(strings.Repeat("ab", 32)) + `","subject":"CN=pbs","issuer":"CN=pbs"}]}`
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, info)
	fake.reply("POST /nodes/localhost/certificates/acme/certificate", http.StatusOK, `{"data":"`+orderUPID+`"}`)
	fake.handle(orderStatusRoute, func(w http.ResponseWriter, _ *http.Request) {
		fake.reply("GET /nodes/localhost/certificates/info", http.StatusForbidden, "permission check failed")
		writeFakeResponse(w, http.StatusOK, `{"data":{"status":"stopped","exitstatus":"Address already in use (os error 98)"}}`)
	})

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(ctx context.Context) error {
		return orderAndWait(ctx, c, "localhost")
	})
	var read *CertificateReadError
	var taskErr *TaskError
	if change.Changed() || !errors.As(err, &read) || !read.After || !errors.As(err, &taskErr) || !IsForbidden(err) ||
		!strings.Contains(err.Error(), "reading the certificate after changing it: ") {
		t.Fatalf("ChangeCertificate() = %+v, %v, want the task's error and the failed read after it", change, err)
	}

	// Without an error of the change's own, the read's is the error.
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, info)
	_, err = c.ChangeCertificate(context.Background(), "localhost", func(context.Context) error {
		fake.reply("GET /nodes/localhost/certificates/info", http.StatusForbidden, "permission check failed")
		return nil
	})
	if !errors.As(err, &read) || !read.After || errors.As(err, &taskErr) {
		t.Fatalf("ChangeCertificate() error = %v, want only the failed read after the change", err)
	}
}

// What a new connection gets before the change is recorded apart from what
// PBS reports: the two differ behind a TLS front end, or when PBS's proxy
// could not load the certificate PBS wrote last.
func TestChangeCertificateLooksAtThePresentedCertificate(t *testing.T) {
	presented := newTestCertificate(t, "front.test")
	written := &swappableServer{}
	written.swap(newTestCertificate(t, "pbs.test"))
	fake := newFakePBS()
	c, _ := serveSwappableTLS(t, fake, presented, Options{Endpoint: "https://pbs.test:8007", CertFingerprint: CertificateFingerprint(presented.cert)})
	routeInfo(fake, written)

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(context.Context) error { return nil })
	if err != nil || change.Changed() {
		t.Fatalf("ChangeCertificate() = %+v, %v", change, err)
	}
	if change.PresentedBefore != CertificateFingerprint(presented.cert) ||
		change.Before.Fingerprint != FormatFingerprint(CertificateFingerprint(written.current.Load().cert)) {
		t.Fatalf("ChangeCertificate() = %+v, want the presented certificate apart from the written one", change)
	}
}

// httpsProxy is an HTTPS forward proxy in memory, as an https:// URL in
// HTTPS_PROXY names one: it presents a certificate of its own, answers
// CONNECT by dialling the target, and relays the tunnel both ways.
type httpsProxy struct {
	listener *pipeListener
	mu       sync.Mutex
	// connects are the targets of the CONNECTs the proxy got.
	connects []string
}

// serveHTTPSProxy serves an HTTPS proxy that presents cert and reaches its
// targets with dial, until the test ends.
func serveHTTPSProxy(t *testing.T, cert testCertificate, dial func(context.Context, string, string) (net.Conn, error)) *httpsProxy {
	t.Helper()
	p := &httpsProxy{listener: newPipeListener()}
	listener := tls.NewListener(p.listener, &tls.Config{Certificates: []tls.Certificate{cert.tlsCert}, MinVersion: tls.VersionTLS12})
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
func (p *httpsProxy) tunnel(conn net.Conn, dial func(context.Context, string, string) (net.Conn, error)) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.mu.Lock()
	p.connects = append(p.connects, req.Host)
	p.mu.Unlock()
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

func (p *httpsProxy) targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.connects)
}

// serveThroughHTTPSProxy serves fake as serveSwappableTLS does, behind an
// HTTPS proxy presenting proxyCert at proxyURL, through which the client
// reaches it.
func serveThroughHTTPSProxy(t *testing.T, fake *fakePBS, initial, proxyCert testCertificate, proxyURL string, opts Options) (*Client, *swappableServer, *httpsProxy) {
	t.Helper()
	c, server := serveSwappableTLS(t, fake, initial, opts)
	transport := c.httpClient.Transport.(*http.Transport)
	proxy := serveHTTPSProxy(t, proxyCert, transport.DialContext)
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	transport.DialContext = proxy.listener.dial
	transport.Proxy = http.ProxyURL(parsed)
	return c, server, proxy
}

// Through an HTTPS proxy, the first handshake is the proxy's: it is
// verified as the client's transport verifies it, the tunnel opened, and the
// certificate looked at is the endpoint's — the proxy named by its host
// name, which the handshake carries, or by its IP address, which it does
// not. Before the change, it is what PresentedBefore records.
func TestPresentedFingerprintThroughAnHTTPSProxy(t *testing.T) {
	old := newTestCertificate(t, "pbs.test")
	uploaded := newTestCertificate(t, "pbs.example.com")
	proxyCert := newTestCertificate(t, "proxy.test")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, append(append([]byte{}, old.pem...), proxyCert.pem...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, proxyURL string
		opts           Options
	}{
		{"the proxy's host name, against the CA file", "https://proxy.test:3128", Options{CAFile: caFile}},
		{"the proxy's IP address, without verification", "https://192.0.2.1:3128", Options{InsecureSkipVerify: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			tc.opts.Endpoint = "https://pbs.test:8007"
			c, server, proxy := serveThroughHTTPSProxy(t, fake, old, proxyCert, tc.proxyURL, tc.opts)
			routeInfo(fake, server)
			ctx := context.Background()

			got, err := c.PresentedFingerprint(ctx)
			if err != nil || got != CertificateFingerprint(old.cert) {
				t.Fatalf("PresentedFingerprint() = %q, %v, want the endpoint's certificate, not the proxy's (%s)", got, err, CertificateFingerprint(proxyCert.cert))
			}
			if targets := proxy.targets(); !slices.Equal(targets, []string{"pbs.test:8007"}) {
				t.Fatalf("the proxy got CONNECTs to %v, want one to the endpoint", targets)
			}
			if routes := fake.routes(); len(routes) != 0 {
				t.Fatalf("the probe sent requests: %v", routes)
			}
			server.swap(uploaded)
			if got, err := c.PresentedFingerprint(ctx); err != nil || got != CertificateFingerprint(uploaded.cert) {
				t.Fatalf("after the swap, PresentedFingerprint() = %q, %v", got, err)
			}

			server.swap(old)
			change, err := c.ChangeCertificate(ctx, "localhost", func(context.Context) error { return nil })
			if err != nil || change.PresentedBefore != CertificateFingerprint(old.cert) {
				t.Fatalf("ChangeCertificate() = %+v, %v, want the endpoint's certificate presented before", change, err)
			}
		})
	}
}

// The handshake keeps the endpoint's host name as the URL writes it, which
// is no other host for being in capitals: neither the client nor the probe
// takes the endpoint's handshake for a proxy's.
func TestPresentedFingerprintOfAnEndpointInCapitals(t *testing.T) {
	cert := newTestCertificate(t, "pbs.test")
	fake := newFakePBS()
	c, _ := serveSwappableTLS(t, fake, cert, Options{Endpoint: "https://PBS.Test:8007", CertFingerprint: CertificateFingerprint(cert.cert)})
	if got, err := c.PresentedFingerprint(context.Background()); err != nil || got != CertificateFingerprint(cert.cert) {
		t.Fatalf("PresentedFingerprint() = %q, %v", got, err)
	}
	if routes := fake.routes(); len(routes) != 0 {
		t.Fatalf("the probe sent requests: %v", routes)
	}
	if _, err := c.ServerVersion(context.Background()); err != nil {
		t.Fatalf("ServerVersion() error = %v", err)
	}
}

// A proxy whose certificate the client does not trust gets no CONNECT from
// the probe, as from the client's own transport: here, the client pins the
// endpoint's certificate, and the system's CAs do not vouch for the
// proxy's.
func TestPresentedFingerprintThroughAnUntrustedHTTPSProxy(t *testing.T) {
	endpoint := newTestCertificate(t, "pbs.test")
	proxyCert := newTestCertificate(t, "proxy.test")
	fake := newFakePBS()
	c, _, proxy := serveThroughHTTPSProxy(t, fake, endpoint, proxyCert, "https://user:secret@proxy.test:3128",
		Options{Endpoint: "https://pbs.test:8007", CertFingerprint: CertificateFingerprint(endpoint.cert)})

	got, err := c.PresentedFingerprint(context.Background())
	var verification *tls.CertificateVerificationError
	if err == nil || got != "" || !errors.As(err, &verification) {
		t.Fatalf("PresentedFingerprint() = %q, %v, want the proxy's certificate refused", got, err)
	}
	if _, err := c.ServerVersion(context.Background()); !errors.As(err, &verification) {
		t.Fatalf("ServerVersion() error = %v, want the proxy's certificate refused by the client's transport too", err)
	}
	if targets := proxy.targets(); len(targets) != 0 {
		t.Fatalf("the proxy got CONNECTs to %v over a connection nobody verified", targets)
	}
}

func TestChangeCertificateFailsWithoutTheCertificate(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusForbidden, "permission check failed")
	ran := false
	_, err := c.ChangeCertificate(context.Background(), "localhost", func(context.Context) error {
		ran = true
		return nil
	})
	var read *CertificateReadError
	if !IsForbidden(err) || ran || !errors.As(err, &read) || read.After ||
		!strings.HasPrefix(err.Error(), "reading the certificate before changing it: ") {
		t.Fatalf("ChangeCertificate() error = %v, ran = %v, want the read's error before any change", err, ran)
	}

	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, `{"data":[{"filename":"other.pem"}]}`)
	if _, err := c.ChangeCertificate(context.Background(), "localhost", func(context.Context) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "lists no proxy.pem") {
		t.Fatalf("ChangeCertificate() error = %v, want the missing proxy.pem", err)
	}
}

// The new certificate is read again when the proxy does not answer for a
// moment, but not after an answer from PBS.
func TestReadChangedCertificateRetriesNetworkErrors(t *testing.T) {
	fake := newFakePBS()
	c := fake.client(t)
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, `{"data":[{"filename":"proxy.pem","fingerprint":"aa"}]}`)
	failures := 2
	c.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if failures > 0 {
			failures--
			return nil, errors.New("connection reset by peer")
		}
		return fake.RoundTrip(req)
	})
	info, err := c.readChangedCertificate(context.Background(), "localhost")
	if err != nil || info.Fingerprint != "aa" {
		t.Fatalf("readChangedCertificate() = %+v, %v, want the certificate after two network errors", info, err)
	}

	c.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })
	if _, err := c.readChangedCertificate(context.Background(), "localhost"); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("readChangedCertificate() error = %v, want the last network error", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestTrustCertificateAndVerifyCertificatePEM(t *testing.T) {
	c := newFakePBS().client(t)
	if err := c.TrustCertificate("not a fingerprint"); err == nil {
		t.Fatal("TrustCertificate() accepted an invalid fingerprint")
	}
	if err := c.VerifyCertificatePEM("no PEM here"); err == nil {
		t.Fatal("VerifyCertificatePEM() accepted text without a certificate")
	}
	if err := c.VerifyCertificatePEM("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"); err == nil {
		t.Fatal("VerifyCertificatePEM() accepted a broken certificate")
	}
	cert := newTestCertificate(t, "pbs.test")
	pinned, err := New(Options{Endpoint: "https://pbs.test", APIToken: fakeAPIToken, CertFingerprint: CertificateFingerprint(cert.cert)})
	if err != nil {
		t.Fatal(err)
	}
	if err := pinned.VerifyCertificatePEM("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n" + string(cert.pem)); err != nil {
		t.Fatalf("VerifyCertificatePEM() error = %v, want the pinned certificate accepted", err)
	}
	// Without the fingerprint, the system's roots would not trust it; it
	// covers the endpoint's host name all the same.
	if p := pinned.CertificateProblems(string(cert.pem)); p.Chain == nil || p.SystemChain == nil || p.Host != nil || pinned.EndpointHost() != "pbs.test" {
		t.Fatalf("CertificateProblems() = %+v for %s, want only the chain refused", p, pinned.EndpointHost())
	}
	if p := pinned.CertificateProblems("nothing"); p.Chain == nil || p.SystemChain == nil {
		t.Fatal("CertificateProblems() accepted text without a certificate")
	}
	// With the certificate as the CA file, the chain verifies, but not for
	// another host name.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, cert.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := New(Options{Endpoint: "https://other.test", APIToken: fakeAPIToken, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if p := other.CertificateProblems(string(cert.pem)); p.Chain != nil || p.SystemChain == nil || p.Host == nil || !other.UsesCAFile() {
		t.Fatalf("CertificateProblems() = %+v, want the host name refused, and the chain by the system's CAs only", p)
	}

	// The handshake with an HTTPS proxy names the proxy, whose certificate
	// is verified for it against the CAs, not pinned.
	proxyCert := newTestCertificate(t, "proxy.test")
	proxyCAFile := filepath.Join(t.TempDir(), "proxy.pem")
	if err := os.WriteFile(proxyCAFile, proxyCert.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	viaProxy, err := New(Options{Endpoint: "https://pbs.test", APIToken: fakeAPIToken, CAFile: proxyCAFile})
	if err != nil {
		t.Fatal(err)
	}
	proxyState := tls.ConnectionState{ServerName: "proxy.test", PeerCertificates: []*x509.Certificate{proxyCert.cert}}
	if err := viaProxy.trust.verifyConnection(proxyState); err != nil {
		t.Fatalf("verifyConnection() for the proxy error = %v", err)
	}
	if err := pinned.trust.verifyConnection(proxyState); err == nil {
		t.Fatal("verifyConnection() accepted a proxy certificate no CA vouches for")
	}
	// A trailing dot in the endpoint is no other host.
	dotted, err := New(Options{Endpoint: "https://pbs.test.", APIToken: fakeAPIToken, CertFingerprint: CertificateFingerprint(cert.cert)})
	if err != nil {
		t.Fatal(err)
	}
	if err := dotted.trust.verifyConnection(tls.ConnectionState{ServerName: "pbs.test", PeerCertificates: []*x509.Certificate{cert.cert}}); err != nil {
		t.Fatalf("verifyConnection() for an endpoint with a trailing dot error = %v", err)
	}
	// Nor are capitals, which the handshake keeps.
	capitals, err := New(Options{Endpoint: "https://PBS.Test", APIToken: fakeAPIToken, CertFingerprint: CertificateFingerprint(cert.cert)})
	if err != nil {
		t.Fatal(err)
	}
	if err := capitals.trust.verifyConnection(tls.ConnectionState{ServerName: "PBS.Test", PeerCertificates: []*x509.Certificate{cert.cert}}); err != nil {
		t.Fatalf("verifyConnection() for an endpoint in capitals error = %v", err)
	}
	insecure, err := New(Options{Endpoint: "https://pbs.test", APIToken: fakeAPIToken, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := insecure.VerifyCertificatePEM(string(cert.pem)); err != nil {
		t.Fatalf("VerifyCertificatePEM() error = %v without verification", err)
	}
}

func TestUntrustedCertificateErrorMessages(t *testing.T) {
	if got := (&UntrustedCertificateError{}).Error(); got != "the server presented no certificate" || (&UntrustedCertificateError{}).Presented() != "" {
		t.Fatalf("Error() = %q", got)
	}
	cert := newTestCertificate(t, "pbs.test")
	c, err := New(Options{Endpoint: "https://other.test", APIToken: fakeAPIToken})
	if err != nil {
		t.Fatal(err)
	}
	err = c.trust.verifyConnection(tls.ConnectionState{})
	var untrusted *UntrustedCertificateError
	if !errors.As(err, &untrusted) {
		t.Fatalf("verifyConnection() without certificates error = %v", err)
	}
	err = c.VerifyCertificatePEM(string(cert.pem))
	var verification *tls.CertificateVerificationError
	if !errors.As(err, &verification) || !strings.HasPrefix(err.Error(), "tls: failed to verify certificate: ") {
		t.Fatalf("VerifyCertificatePEM() error = %v, want Go's own verification error", err)
	}
}

// With a password, a call that has to sign in again while the certificate
// changes meets the new certificate in the sign-in: it waits for the change
// too. A call on the connection of the change that joins such a sign-in
// signs in again over its own connection, which the change still trusts,
// rather than take on the other's error.
func TestChangeCertificateWithASignInMeetingTheNewCertificate(t *testing.T) {
	old := newTestCertificate(t, "pbs.test")
	ordered := newTestCertificate(t, "pbs.example.com")
	fake := newFakePBS()
	c, server := serveSwappableTLS(t, fake, old, Options{
		Endpoint: "https://pbs.test:8007", Username: fakeUsername, Password: fakePassword,
		CertFingerprint: CertificateFingerprint(old.cert),
	})
	routeInfo(fake, server)
	fake.reply("POST /nodes/localhost/certificates/acme/certificate", http.StatusOK, `{"data":"`+orderUPID+`"}`)

	start := time.Now()
	clock := atomic.Pointer[time.Time]{}
	clock.Store(&start)
	now = func() time.Time { return *clock.Load() }
	t.Cleanup(func() { now = time.Now })

	// New connections of the client's own transport are slow, so that a
	// sign-in over one is still running when the change reads the new
	// certificate.
	transport := c.httpClient.Transport.(*http.Transport)
	dial := transport.DialContext
	var slow atomic.Bool
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if slow.Load() {
			time.Sleep(200 * time.Millisecond)
		}
		return dial(ctx, network, addr)
	}

	var concurrent sync.WaitGroup
	var concurrentErr error
	fake.handle(orderStatusRoute, func(w http.ResponseWriter, _ *http.Request) {
		server.swap(ordered)
		// The ticket is due for renewal from now on.
		later := start.Add(2 * time.Hour)
		clock.Store(&later)
		slow.Store(true)
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			_, concurrentErr = c.ServerVersion(context.Background())
		}()
		writeFakeResponse(w, http.StatusOK, `{"data":{"status":"stopped","exitstatus":"OK"}}`)
	})

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(ctx context.Context) error {
		return orderAndWait(ctx, c, "localhost")
	})
	concurrent.Wait()
	if err != nil || change.Unconfirmed != nil || change.After.Fingerprint != FormatFingerprint(CertificateFingerprint(ordered.cert)) {
		t.Fatalf("ChangeCertificate() = %+v, %v, want the ordered certificate confirmed", change, err)
	}
	if concurrentErr != nil {
		t.Fatalf("the concurrent call failed: %v", concurrentErr)
	}
}

// A call whose ticket PBS rejects while the certificate changes signs in
// again, meets the new certificate, waits for the change, and then tries
// again with a new ticket, not the rejected one.
func TestChangeCertificateWithATicketRejectedMeanwhile(t *testing.T) {
	old := newTestCertificate(t, "pbs.test")
	ordered := newTestCertificate(t, "pbs.example.com")
	fake := newFakePBS()
	c, server := serveSwappableTLS(t, fake, old, Options{
		Endpoint: "https://pbs.test:8007", Username: fakeUsername, Password: fakePassword,
		CertFingerprint: CertificateFingerprint(old.cert),
	})
	fake.reply("POST /nodes/localhost/certificates/acme/certificate", http.StatusOK, `{"data":"`+orderUPID+`"}`)
	fake.reply(orderStatusRoute, http.StatusOK, `{"data":{"status":"stopped","exitstatus":"OK"}}`)

	// The first call signs in, with ticket 1, over a connection that stays
	// open.
	if _, err := c.ServerVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	var rejectFirstTicket atomic.Bool
	fake.handle("GET /version", func(w http.ResponseWriter, req *http.Request) {
		cookie, _ := req.Cookie(ticketCookieName)
		if rejectFirstTicket.Load() && strings.Contains(cookie.Value, "ticket-1") {
			w.Header().Set("Connection", "close")
			writeFakeResponse(w, http.StatusUnauthorized, "authentication failed - invalid PBS authentication cookie")
			return
		}
		writeFakeResponse(w, http.StatusOK, fakeVersionJSON)
	})

	conf := transportTLS(t, c)
	verify := conf.VerifyConnection
	rejected := make(chan struct{}, 8)
	conf.VerifyConnection = func(state tls.ConnectionState) error {
		err := verify(state)
		if err != nil {
			rejected <- struct{}{}
		}
		return err
	}

	reads := 0
	var concurrent sync.WaitGroup
	var concurrentErr error
	fake.handle("GET /nodes/localhost/certificates/info", func(w http.ResponseWriter, _ *http.Request) {
		reads++
		if reads == 2 {
			// The change reads the new certificate: PBS has it, and
			// rejects ticket 1 from now on.
			server.swap(ordered)
			rejectFirstTicket.Store(true)
			concurrent.Add(1)
			go func() {
				defer concurrent.Done()
				_, concurrentErr = c.ServerVersion(context.Background())
			}()
			select {
			case <-rejected:
			case <-time.After(5 * time.Second):
				t.Error("the concurrent sign-in never met the new certificate")
			}
		}
		writeFakeResponse(w, http.StatusOK, server.info())
	})

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(ctx context.Context) error {
		return orderAndWait(ctx, c, "localhost")
	})
	concurrent.Wait()
	if err != nil || change.Unconfirmed != nil {
		t.Fatalf("ChangeCertificate() = %+v, %v", change, err)
	}
	if concurrentErr != nil {
		t.Fatalf("the concurrent call failed: %v", concurrentErr)
	}
}
