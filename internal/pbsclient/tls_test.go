package pbsclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCertificate is a self-signed certificate shaped like the one PBS
// generates at installation: not a CA, usable for server authentication,
// valid for the given DNS name.
type testCertificate struct {
	cert    *x509.Certificate
	tlsCert tls.Certificate
	pem     []byte
}

func newTestCertificate(t *testing.T, dnsName string) testCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"PBS"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate{
		cert:    cert,
		tlsCert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert},
		pem:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func TestNormaliseFingerprint(t *testing.T) {
	const want = "cd50843049f0c6da48255e8022728d28124cb5b72fc3a2d81be496219c2cccf3"
	accepted := map[string]string{
		"bare hex digits":     want,
		"upper case":          strings.ToUpper(want),
		"PBS's colons":        "cd:50:84:30:49:f0:c6:da:48:25:5e:80:22:72:8d:28:12:4c:b5:b7:2f:c3:a2:d8:1b:e4:96:21:9c:2c:cc:f3",
		"OpenSSL's colons":    "CD:50:84:30:49:F0:C6:DA:48:25:5E:80:22:72:8D:28:12:4C:B5:B7:2F:C3:A2:D8:1B:E4:96:21:9C:2C:CC:F3",
		"surrounding spaces":  "  " + want + "\n",
		"mixed case, grouped": "Cd50 8430 49f0 c6da 4825 5e80 2272 8d28 124c b5b7 2fc3 a2d8 1be4 9621 9c2c ccf3",
	}
	for name, input := range accepted {
		got, err := NormaliseFingerprint(input)
		if err != nil || got != want {
			t.Errorf("%s: NormaliseFingerprint(%q) = %q, %v, want %q", name, input, got, err, want)
		}
	}

	rejected := map[string]string{
		"empty":          "",
		"63 digits":      want[:63],
		"65 digits":      want + "0",
		"not hex":        strings.Repeat("g", 64),
		"SHA-1":          "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"prefixed":       "SHA256:" + want,
		"OpenSSL output": "sha256 Fingerprint=" + want,
	}
	for name, input := range rejected {
		if got, err := NormaliseFingerprint(input); err == nil {
			t.Errorf("%s: NormaliseFingerprint(%q) = %q, want an error", name, input, got)
		}
	}
}

func TestCertificateFingerprintIsTheSHA256OfTheDER(t *testing.T) {
	cert := newTestCertificate(t, "pbs.test")
	// openssl x509 -outform DER | openssl dgst -sha256, done the long way.
	block, _ := pem.Decode(cert.pem)
	sum := sha256Hex(block.Bytes)
	if got := CertificateFingerprint(cert.cert); got != sum {
		t.Fatalf("CertificateFingerprint() = %s, want %s", got, sum)
	}
}

// The pinned certificate may be any one the server presents, leaf or
// intermediate.
func TestVerifyFingerprintAcceptsAnyPresentedCertificate(t *testing.T) {
	leaf := newTestCertificate(t, "pbs.test")
	other := newTestCertificate(t, "intermediate.test")
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf.cert, other.cert}}

	for _, cert := range []*x509.Certificate{leaf.cert, other.cert} {
		if err := verifyFingerprint(CertificateFingerprint(cert))(state); err != nil {
			t.Errorf("verifyFingerprint(%s) error = %v, want a match", CertificateFingerprint(cert), err)
		}
	}
}

func TestVerifyFingerprintRejectsEveryOtherCertificate(t *testing.T) {
	leaf := newTestCertificate(t, "pbs.test")
	pinned := strings.Repeat("ab", 32)

	err := verifyFingerprint(pinned)(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf.cert}})
	if err == nil {
		t.Fatal("verifyFingerprint() accepted a certificate with another fingerprint")
	}
	for _, want := range []string{pinned, CertificateFingerprint(leaf.cert)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}

	if err := verifyFingerprint(pinned)(tls.ConnectionState{}); err == nil {
		t.Fatal("verifyFingerprint() accepted a connection without certificates")
	}
}

func transportTLS(t *testing.T, c *Client) *tls.Config {
	t.Helper()
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.httpClient.Transport)
	}
	return transport.TLSClientConfig
}

func TestNewConfiguresTLS(t *testing.T) {
	cert := newTestCertificate(t, "pbs.test")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, cert.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	base := Options{Endpoint: "https://pbs.test:8007", APIToken: fakeAPIToken}

	t.Run("system roots by default", func(t *testing.T) {
		c, err := New(base)
		if err != nil {
			t.Fatal(err)
		}
		if conf := transportTLS(t, c); conf != nil && (conf.InsecureSkipVerify || conf.RootCAs != nil) {
			t.Fatalf("TLS config = %+v, want Go's defaults", conf)
		}
	})

	t.Run("fingerprint", func(t *testing.T) {
		opts := base
		opts.CertFingerprint = strings.ToUpper(CertificateFingerprint(cert.cert))
		c, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		conf := transportTLS(t, c)
		if conf == nil || !conf.InsecureSkipVerify || conf.VerifyConnection == nil || conf.VerifyPeerCertificate != nil {
			t.Fatalf("TLS config = %+v, want chain verification replaced by VerifyConnection", conf)
		}
		if err := conf.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert.cert}}); err != nil {
			t.Fatalf("VerifyConnection() error = %v, want the normalised fingerprint to match", err)
		}
	})

	t.Run("CA file", func(t *testing.T) {
		opts := base
		opts.CAFile = caFile
		c, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		conf := transportTLS(t, c)
		if conf == nil || conf.RootCAs == nil || conf.InsecureSkipVerify {
			t.Fatalf("TLS config = %+v, want the CA file as roots with verification on", conf)
		}
	})

	t.Run("missing CA file", func(t *testing.T) {
		opts := base
		opts.CAFile = filepath.Join(t.TempDir(), "missing.pem")
		if _, err := New(opts); err == nil || !strings.Contains(err.Error(), "reading the CA certificate file") {
			t.Fatalf("New() error = %v, want a read error", err)
		}
	})

	t.Run("CA file without certificates", func(t *testing.T) {
		opts := base
		opts.CAFile = filepath.Join(t.TempDir(), "empty.pem")
		if err := os.WriteFile(opts.CAFile, []byte("not a certificate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(opts); err == nil || !strings.Contains(err.Error(), "contains no PEM-encoded certificate") {
			t.Fatalf("New() error = %v, want a parse error", err)
		}
	})

	t.Run("insecure", func(t *testing.T) {
		opts := base
		opts.InsecureSkipVerify = true
		c, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		if conf := transportTLS(t, c); conf == nil || !conf.InsecureSkipVerify || conf.VerifyConnection != nil {
			t.Fatalf("TLS config = %+v, want verification skipped", conf)
		}
	})

	// A test transport replaces the TLS settings but they are still checked,
	// so configuration errors surface in unit tests too.
	t.Run("validated with a test transport", func(t *testing.T) {
		opts := base
		opts.CAFile = filepath.Join(t.TempDir(), "missing.pem")
		opts.Transport = newFakePBS()
		if _, err := New(opts); err == nil {
			t.Fatal("New() accepted a missing CA file because a transport was set")
		}
	})
}

// The handshake tests below run a real TLS server in process: the client's
// own transport dials one end of an in-memory connection, and an http.Server
// serves the fake PBS on the other, so no socket is opened.
//
// net.Pipe would not do: its writes block until the other side reads, and a
// TLS client that rejects the server's certificate writes an alert while the
// server is still writing the rest of its flight, so both would wait for the
// server's handshake timeout. bufferedPipe buffers like a socket does.

// pipeHalf is one direction of a bufferedPipe. Writes never block.
type pipeHalf struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newPipeHalf() *pipeHalf {
	h := &pipeHalf{}
	h.cond = sync.NewCond(&h.mu)
	return h
}

func (h *pipeHalf) read(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for h.buf.Len() == 0 && !h.closed {
		h.cond.Wait()
	}
	if h.buf.Len() == 0 {
		return 0, io.EOF
	}
	return h.buf.Read(p)
}

func (h *pipeHalf) write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return 0, io.ErrClosedPipe
	}
	h.buf.Write(p)
	h.cond.Broadcast()
	return len(p), nil
}

func (h *pipeHalf) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	h.cond.Broadcast()
}

// bufferedConn is one end of a bufferedPipe. Deadlines are ignored; closing
// either end ends both directions.
type bufferedConn struct{ in, out *pipeHalf }

func bufferedPipe() (net.Conn, net.Conn) {
	a, b := newPipeHalf(), newPipeHalf()
	return &bufferedConn{in: a, out: b}, &bufferedConn{in: b, out: a}
}

func (c *bufferedConn) Read(p []byte) (int, error)       { return c.in.read(p) }
func (c *bufferedConn) Write(p []byte) (int, error)      { return c.out.write(p) }
func (c *bufferedConn) Close() error                     { c.in.close(); c.out.close(); return nil }
func (c *bufferedConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (c *bufferedConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (c *bufferedConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferedConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// pipeListener is a net.Listener whose connections come from dial.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := bufferedPipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// serveTLS serves fake over TLS with the given certificate chain and returns
// a client for opts, wired to dial it.
func serveTLS(t *testing.T, fake *fakePBS, chain []testCertificate, opts Options) *Client {
	t.Helper()
	var certificate tls.Certificate
	for i, c := range chain {
		if i == 0 {
			certificate = c.tlsCert
			continue
		}
		certificate.Certificate = append(certificate.Certificate, c.tlsCert.Certificate[0])
	}

	listener := newPipeListener()
	server := &http.Server{Handler: http.HandlerFunc(fake.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}))
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})

	opts.APIToken = fakeAPIToken
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
	return c
}

func TestTLSHandshake(t *testing.T) {
	leaf := newTestCertificate(t, "pbs.test")
	intermediate := newTestCertificate(t, "intermediate.test")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, leaf.pem, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		opts    Options
		chain   []testCertificate
		wantErr string
	}{
		{
			name:  "pinned leaf",
			opts:  Options{Endpoint: "https://pbs.test", CertFingerprint: CertificateFingerprint(leaf.cert)},
			chain: []testCertificate{leaf},
		},
		{
			// Pinning ignores host names: a self-signed certificate is
			// trusted by its hash alone.
			name:  "pinned leaf under another host name",
			opts:  Options{Endpoint: "https://127.0.0.1:8007", CertFingerprint: CertificateFingerprint(leaf.cert)},
			chain: []testCertificate{leaf},
		},
		{
			name:  "pinned intermediate",
			opts:  Options{Endpoint: "https://pbs.test", CertFingerprint: CertificateFingerprint(intermediate.cert)},
			chain: []testCertificate{leaf, intermediate},
		},
		{
			name:    "fingerprint mismatch",
			opts:    Options{Endpoint: "https://pbs.test", CertFingerprint: strings.Repeat("0", 64)},
			chain:   []testCertificate{leaf},
			wantErr: "no certificate the server presented matches SHA-256 fingerprint",
		},
		{
			name:  "CA file",
			opts:  Options{Endpoint: "https://pbs.test", CAFile: caFile},
			chain: []testCertificate{leaf},
		},
		{
			// With a CA file the host name is verified, unlike with a
			// pinned fingerprint.
			name:    "CA file under another host name",
			opts:    Options{Endpoint: "https://other.test", CAFile: caFile},
			chain:   []testCertificate{leaf},
			wantErr: "certificate is valid for pbs.test, not other.test",
		},
		{
			name:    "system roots",
			opts:    Options{Endpoint: "https://pbs.test"},
			chain:   []testCertificate{leaf},
			wantErr: "certificate",
		},
		{
			name:  "verification skipped",
			opts:  Options{Endpoint: "https://pbs.test", InsecureSkipVerify: true},
			chain: []testCertificate{leaf},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			c := serveTLS(t, fake, tc.chain, tc.opts)

			version, err := c.ServerVersion(context.Background())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ServerVersion() error = %v, want one containing %q", err, tc.wantErr)
				}
				if len(fake.routes()) != 0 {
					t.Fatalf("requests reached the server despite the failed handshake: %v", fake.routes())
				}
				return
			}
			if err != nil {
				t.Fatalf("ServerVersion() error = %v", err)
			}
			if version.String() != "4.2.8" {
				t.Fatalf("ServerVersion() = %q, want 4.2.8", version)
			}
		})
	}
}

// A resumed TLS session skips VerifyPeerCertificate but not VerifyConnection,
// so pinning holds for every connection, not only the first.
func TestPinningAppliesToEveryConnection(t *testing.T) {
	leaf := newTestCertificate(t, "pbs.test")
	fake := newFakePBS()
	c := serveTLS(t, fake, []testCertificate{leaf}, Options{Endpoint: "https://pbs.test", CertFingerprint: CertificateFingerprint(leaf.cert)})

	conf := transportTLS(t, c)
	verify := conf.VerifyConnection
	var mu sync.Mutex
	verified := 0
	conf.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	conf.VerifyConnection = func(state tls.ConnectionState) error {
		mu.Lock()
		verified++
		mu.Unlock()
		return verify(state)
	}

	for i := 0; i < 3; i++ {
		if _, err := c.ServerVersion(context.Background()); err != nil {
			t.Fatalf("ServerVersion() error = %v", err)
		}
		// A fresh connection each time, so later ones can resume the
		// first one's session.
		c.httpClient.CloseIdleConnections()
	}
	mu.Lock()
	defer mu.Unlock()
	if verified < 3 {
		t.Fatalf("VerifyConnection ran %d times for at least 3 connections", verified)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
