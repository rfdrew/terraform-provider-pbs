package pbsclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
		return c.OrderACMECertificate(ctx, "localhost")
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
		return c.OrderACMECertificate(ctx, "localhost")
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
	fake.reply(orderStatusRoute, http.StatusOK, `{"data":{"status":"stopped","exitstatus":"validation for pbs.example.com failed"}}`)

	change, err := c.ChangeCertificate(context.Background(), "localhost", func(ctx context.Context) error {
		return c.OrderACMECertificate(ctx, "localhost")
	})
	var taskErr *TaskError
	if !errors.As(err, &taskErr) || change.Changed() || calls != 2 || !change.Before.SelfSigned() {
		t.Fatalf("ChangeCertificate() = %+v, %v after %d reads, want the task error and the unchanged certificate read twice", change, err, calls)
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
	if !IsForbidden(err) || ran {
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
		return c.OrderACMECertificate(ctx, "localhost")
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
		return c.OrderACMECertificate(ctx, "localhost")
	})
	concurrent.Wait()
	if err != nil || change.Unconfirmed != nil {
		t.Fatalf("ChangeCertificate() = %+v, %v", change, err)
	}
	if concurrentErr != nil {
		t.Fatalf("the concurrent call failed: %v", concurrentErr)
	}
}
