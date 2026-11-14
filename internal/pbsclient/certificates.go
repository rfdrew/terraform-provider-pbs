package pbsclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// The proxy, proxmox-backup-proxy, serves the API and the web interface on
// port 8007 with one certificate, proxy.pem. What PBS 4.0 and 4.2 do with it,
// read in their source (src/api2/node/certificates.rs, proxmox-acme-api):
//
//   - GET /nodes/{node}/certificates/info describes it: the first
//     certificate of proxy.pem, with its fingerprint, and the PEM of the
//     whole file. It needs Sys.Modify on /system/certificates.
//   - POST /nodes/{node}/certificates/acme/certificate answers with the
//     UPID of an acme-new-cert task, which orders a certificate for the
//     node's ACME domains with its ACME account, writes it to proxy.pem and
//     has the proxy load it. A node without domains is no error: the task
//     logs "No domains configured" and ends OK without a new certificate.
//   - DELETE /nodes/{node}/certificates/custom deletes proxy.pem, generates
//     a new self-signed certificate — with a new key, so a new fingerprint
//     — and has the proxy load it, before it answers; there is no task.
//   - POST /nodes/{node}/certificates/custom writes certificates, the chain
//     re-encoded, and key — the current key when there is none — and has
//     the proxy load them, before it answers. It checks only that they
//     parse: a key that is not the certificate's leaves the proxy on the old
//     certificate, unable to start again, and text without a certificate is
//     written as an empty proxy.pem. restart and force are accepted and
//     ignored.
//   - The proxy loads a new certificate by a command on its control socket,
//     without restarting: it keeps listening, and connections already open
//     keep the certificate they started with. Only new connections get the
//     new one.
//
// PBS also renews an ACME certificate on its own, in its daily update, once
// two thirds of its lifetime have passed (30 days before it expires before
// PBS 4.1.9), so the certificate — and its fingerprint — changes without
// anyone asking.

// ProxyCertificateFile is the certificate the PBS proxy serves on port 8007,
// the one clients pin.
const ProxyCertificateFile = "proxy.pem"

// CertificateInfo is one entry of GET /nodes/{node}/certificates/info.
type CertificateInfo struct {
	Filename string `json:"filename"`
	// Fingerprint is the SHA-256 fingerprint, as colon-separated lower-case
	// hex pairs.
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   int64  `json:"notbefore"`
	NotAfter    int64  `json:"notafter"`
	// SAN are the DNS names among the subject alternative names.
	SAN []string `json:"san"`
	// PEM is the whole file: the certificate and the chain after it.
	PEM string `json:"pem"`
	// PublicKeyType is e.g. "rsaEncryption", PublicKeyBits its size.
	PublicKeyType string `json:"public-key-type"`
	PublicKeyBits int64  `json:"public-key-bits"`
}

// SelfSigned reports whether the certificate names itself as its issuer, as
// the one PBS generates does.
func (i CertificateInfo) SelfSigned() bool { return i.Issuer == i.Subject }

// generatedSubjectPrefix starts the subject of the certificate PBS
// generates for itself: "O = Proxmox Backup Server, OU = <UUID>, CN =
// <host>", as GET certificates/info writes names (src/config/mod.rs).
const generatedSubjectPrefix = "O = Proxmox Backup Server, OU = "

// Generated reports whether the certificate is one PBS generated for itself,
// self-signed, at installation or after its custom certificate was deleted —
// rather than any self-signed certificate someone uploaded.
func (i CertificateInfo) Generated() bool {
	return i.SelfSigned() && strings.HasPrefix(i.Subject, generatedSubjectPrefix)
}

// Certificates reads the certificates of the client's node. It needs
// Sys.Modify on /system/certificates.
func (c *Client) Certificates(ctx context.Context) ([]CertificateInfo, error) {
	return c.NodeCertificates(ctx, c.node)
}

// NodeCertificates reads the certificates of a node.
func (c *Client) NodeCertificates(ctx context.Context, node string) ([]CertificateInfo, error) {
	var certs []CertificateInfo
	if _, err := c.Get(ctx, Path("nodes", node, "certificates", "info"), nil, &certs); err != nil {
		return nil, err
	}
	return certs, nil
}

// ProxyCertificate returns the certificate the proxy of the client's node
// serves.
func (c *Client) ProxyCertificate(ctx context.Context) (CertificateInfo, error) {
	return c.NodeProxyCertificate(ctx, c.node)
}

// NodeProxyCertificate returns the certificate the proxy of a node serves.
func (c *Client) NodeProxyCertificate(ctx context.Context, node string) (CertificateInfo, error) {
	certs, err := c.NodeCertificates(ctx, node)
	if err != nil {
		return CertificateInfo{}, err
	}
	for _, cert := range certs {
		if cert.Filename == ProxyCertificateFile {
			return cert, nil
		}
	}
	return CertificateInfo{}, fmt.Errorf("GET %s lists no %s", Path("nodes", node, "certificates", "info"), ProxyCertificateFile)
}

// OrderACMECertificate has a node order a certificate for its ACME domains
// and returns the UPID of the acme-new-cert task that orders it. Run it
// through ChangeCertificate, and wait for the task within the change, as
// for RenewACMECertificate: the task's error, such as a failed validation,
// is a *TaskError, whose cause ACMEOrderFailureOf reads.
func (c *Client) OrderACMECertificate(ctx context.Context, node string) (UPID, error) {
	return c.StartTask(ctx, http.MethodPost, Path("nodes", node, "certificates", "acme", "certificate"), nil)
}

// DeleteCustomCertificate has a node replace its certificate with a new
// self-signed one. Run it through ChangeCertificate.
func (c *Client) DeleteCustomCertificate(ctx context.Context, node string) error {
	_, err := c.Delete(ctx, Path("nodes", node, "certificates", "custom"), nil, nil)
	return err
}

// UploadCustomCertificate installs a certificate chain, leaf first, and its
// private key, both PEM-encoded, as a node's certificate. Run it through
// ChangeCertificate, after CheckCustomCertificate: PBS checks neither that
// there is a certificate nor that the key is the certificate's, and writes
// both files before its proxy fails to load them. The key is kept out of any
// error.
func (c *Client) UploadCustomCertificate(ctx context.Context, node, certificates, key string) error {
	_, err := c.Post(ctx, Path("nodes", node, "certificates", "custom"),
		url.Values{"certificates": {certificates}, "key": {key}}, nil)
	return redactAPIError(err, key, strings.TrimSpace(key))
}

// ErrNoTLSTransport means the client has no TLS transport of its own to look
// at the server's certificate with, as in tests.
var ErrNoTLSTransport = errors.New("the client has no TLS transport of its own")

// errLookedAt ends the handshake of PresentedFingerprint.
var errLookedAt = errors.New("certificate looked at")

// PresentedFingerprint opens a new connection to the endpoint and returns
// the normalised SHA-256 fingerprint of the certificate the server presents
// to it — what PBS's proxy serves now, which GET certificates/info, reading
// the file, may not be. It ends the handshake once it has seen the
// certificate, so nothing is sent over a connection it has not verified.
//
// Through an HTTPS forward proxy — an https:// proxy URL, such as one in
// HTTPS_PROXY, which the client supports (see trust.verifyConnection) —
// net/http first has a TLS handshake with the proxy, with the same TLS
// configuration, then sends CONNECT over that connection, with
// Proxy-Authorization when the proxy URL holds a user, and only then has
// the endpoint's handshake, through the tunnel (net/http transport.go,
// dialConn and addTLS, read in Go 1.27). The proxy's handshake — the first
// one then, or one that names a host other than the endpoint's, as
// trust.verifyConnection tells it — is verified exactly as the client's
// own transport verifies it, and its certificate is not the one looked at:
// the endpoint's, through the tunnel, is.
func (c *Client) PresentedFingerprint(ctx context.Context) (string, error) {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return "", ErrNoTLSTransport
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/", nil)
	if err != nil {
		return "", err
	}
	probe := transport.Clone()
	probe.DisableKeepAlives = true
	// The probe makes one request over one new connection, whose first
	// handshake is the proxy's when net/http reaches the endpoint through
	// an HTTPS proxy: the proxy URL's scheme is the first hop's.
	proxyHandshake := false
	if probe.Proxy != nil {
		if proxyURL, err := probe.Proxy(req); err == nil && proxyURL != nil && proxyURL.Scheme == "https" {
			proxyHandshake = true
		}
	}
	config := &tls.Config{}
	if probe.TLSClientConfig != nil {
		config = probe.TLSClientConfig.Clone()
	}
	// The handshakes run on net/http's dialling goroutine, which may
	// outlive the request when its context ends.
	var mu sync.Mutex
	var presented string
	config.InsecureSkipVerify = true //nolint:gosec // VerifyConnection verifies a proxy's handshake; the endpoint's ends below, with nothing sent.
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = func(state tls.ConnectionState) error {
		mu.Lock()
		defer mu.Unlock()
		if proxyHandshake || (state.ServerName != "" && !strings.EqualFold(state.ServerName, c.trust.host)) {
			proxyHandshake = false
			return c.trust.verifyConnection(state)
		}
		if len(state.PeerCertificates) > 0 {
			presented = CertificateFingerprint(state.PeerCertificates[0])
		}
		return errLookedAt
	}
	probe.TLSClientConfig = config
	defer probe.CloseIdleConnections()
	resp, err := (&http.Client{Transport: probe, Timeout: c.httpClient.Timeout}).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if presented == "" {
		return "", fmt.Errorf("looking at the certificate the server presents: %w", err)
	}
	return presented, nil
}

// ParseCertificatesPEM parses the certificates in PEM text, in order,
// skipping other blocks; it fails without any.
func ParseCertificatesPEM(certPEM string) ([]*x509.Certificate, error) {
	return parseCertificatesPEM(certPEM)
}

// CheckCustomCertificate checks a certificate chain and private key before
// they are uploaded. The key must be the first certificate's, and the keys
// of the chain strong enough for OpenSSL, which PBS does not check: it
// writes both, and its proxy keeps the old certificate and fails to start
// the next time. The chain must also hold certificates only, at least one —
// PBS drops other blocks —, and the key be PEM and unencrypted — PBS fails
// to read it otherwise —, so that such mistakes fail early. It returns the
// first certificate's fingerprint, normalised. Its errors never show the
// key.
func CheckCustomCertificate(certificates, key string) (string, error) {
	certs, err := CheckCertificateChain(certificates)
	if err != nil {
		return "", err
	}
	private, err := parsePrivateKeyPEM(key)
	if err != nil {
		return "", err
	}
	public, ok := private.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !public.Equal(certs[0].PublicKey) {
		return "", errors.New("the private key is not the key of the first certificate of the chain, which PBS " +
			"serves: the chain must start with the server's own certificate, followed by its intermediates")
	}
	return CertificateFingerprint(certs[0]), nil
}

// CheckCertificateChain parses a PEM certificate chain as PBS would, refusing
// blocks other than certificates, which PBS would drop.
func CheckCertificateChain(certificates string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(certificates)
	for i := 1; ; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %d is a %s, not a CERTIFICATE: the chain holds certificates only", i, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d of the chain: %w", i, err)
		}
		if err := checkKeyStrength(cert); err != nil {
			return nil, fmt.Errorf("certificate %d of the chain, %s, %w", i, cert.Subject, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("the chain holds no PEM-encoded certificate (-----BEGIN CERTIFICATE-----)")
	}
	return certs, nil
}

// checkKeyStrength refuses a certificate whose key OpenSSL refuses at its
// default security level, 2, which PBS's proxy keeps: RSA keys under 2048
// bits, EC keys under 224. PBS writes such a certificate all the same,
// and its proxy keeps the old one and does not start again.
func checkKeyStrength(cert *x509.Certificate) error {
	var kind string
	var bits, least int
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		kind, bits, least = "RSA", key.N.BitLen(), 2048
	case *ecdsa.PublicKey:
		kind, bits, least = "EC", key.Curve.Params().BitSize, 224
	default:
		return nil
	}
	if bits < least {
		return fmt.Errorf("has a %d-bit %s key: PBS's OpenSSL refuses %s keys under %d bits, and its proxy would "+
			"keep the old certificate and not start again", bits, kind, kind, least)
	}
	return nil
}

// parsePrivateKeyPEM parses a PEM private key in any form PBS's OpenSSL
// reads without a passphrase: PKCS #8, PKCS #1 RSA or SEC 1 EC.
func parsePrivateKeyPEM(key string) (crypto.Signer, error) {
	// Like OpenSSL, look past other blocks, such as the EC PARAMETERS that
	// `openssl ecparam -genkey` writes before the key.
	var block *pem.Block
	var others []string
	for rest := []byte(key); ; {
		block, rest = pem.Decode(rest)
		if block == nil || strings.HasSuffix(block.Type, "PRIVATE KEY") {
			break
		}
		others = append(others, block.Type)
	}
	switch {
	case block == nil && len(others) > 0:
		return nil, fmt.Errorf("the PEM text holds no private key, only %s", strings.Join(others, ", "))
	case block == nil:
		return nil, errors.New("the private key is not PEM-encoded (-----BEGIN PRIVATE KEY-----)")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" {
		return nil, errors.New("the private key is encrypted: PBS takes it without a passphrase")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("the PEM block of the private key is a %s, not a PRIVATE KEY", block.Type)
	}
	if err != nil {
		// The parser's error may quote the key's bytes.
		return nil, fmt.Errorf("the %s does not parse", block.Type)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("the private key is of an unexpected kind, %T", parsed)
	}
	return signer, nil
}

// --- changing the certificate under the client ------------------------------

// When the client has the server change its certificate, the server presents
// another one from then on, which the client's settings may not trust: a
// pinned fingerprint never matches it, and a self-signed certificate never
// verifies against CAs. Every later call would fail, for this resource and
// every other one of the same run.
//
// ChangeCertificate prevents that without trusting whatever the server
// presents next. It makes the change over a connection of its own, opened
// and verified before the change, which keeps the old certificate since the
// proxy does not touch open connections, and over the same connection reads
// what PBS now serves. That answer comes over a connection the client
// trusted, so the client may trust the certificate it describes, and does,
// for the rest of its life. Calls that meet the new certificate while the
// change runs wait for it to end and try again.

// connectionKey is the context key of the HTTP client a call should use
// instead of the client's own: the dedicated connection of a certificate
// change.
type connectionKey struct{}

// requestTimeoutKey is the context key of a time limit that replaces the
// client's own for the requests made with that context; see
// WithRequestTimeout.
type requestTimeoutKey struct{}

// WithRequestTimeout returns a context whose requests may take up to timeout
// each, instead of the client's request timeout: for the few calls that PBS
// answers only after it has talked to another server, such as checking an
// S3 endpoint, which takes over half a minute to fail when the endpoint does
// not answer.
func WithRequestTimeout(ctx context.Context, timeout time.Duration) context.Context {
	return context.WithValue(ctx, requestTimeoutKey{}, timeout)
}

// httpClientFor returns the HTTP client a call with ctx goes through.
func (c *Client) httpClientFor(ctx context.Context) *http.Client {
	hc := c.httpClient
	if dedicated, ok := ctx.Value(connectionKey{}).(*http.Client); ok {
		hc = dedicated
	}
	if timeout, ok := ctx.Value(requestTimeoutKey{}).(time.Duration); ok && timeout > 0 && timeout != hc.Timeout {
		return &http.Client{Timeout: timeout, Transport: hc.Transport, CheckRedirect: hc.CheckRedirect, Jar: hc.Jar}
	}
	return hc
}

// dedicatedConnection returns an HTTP client that keeps to one connection,
// and a function that closes it. A test transport, which has no
// connections, is shared.
func (c *Client) dedicatedConnection() (*http.Client, func()) {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return &http.Client{Timeout: c.httpClient.Timeout, Transport: c.httpClient.Transport, CheckRedirect: c.httpClient.CheckRedirect}, func() {}
	}
	single := transport.Clone()
	single.MaxConnsPerHost = 1
	single.MaxIdleConnsPerHost = 1
	return &http.Client{Timeout: c.httpClient.Timeout, Transport: single, CheckRedirect: c.httpClient.CheckRedirect}, single.CloseIdleConnections
}

// awaitCertificateChange decides whether a call that failed with err should
// be tried again: when err is a certificate the client does not trust, a
// certificate change is under way or has made the client trust a new
// certificate since generation. It waits for a change under way to end. A
// call on the change's own connection is never tried again: it would wait
// for itself.
func (c *Client) awaitCertificateChange(ctx context.Context, err error, generation uint64) bool {
	var untrusted *UntrustedCertificateError
	if !errors.As(err, &untrusted) {
		return false
	}
	if _, dedicated := ctx.Value(connectionKey{}).(*http.Client); dedicated {
		return false
	}
	c.changingMu.Lock()
	changing := c.changing
	c.changingMu.Unlock()
	if changing != nil {
		tflog.Debug(ctx, "the PBS certificate is being changed; waiting for the change before trying again")
		select {
		case <-changing:
		case <-ctx.Done():
			return false
		}
	}
	return c.trust.currentGeneration() != generation
}

// UnconfirmedCertificateError means the server's certificate changed, but
// the client could not read the new one over a connection it trusted before
// — the connection of the change closed — so it does not trust it.
type UnconfirmedCertificateError struct {
	// Presented is the fingerprint of the certificate the server presents
	// now, normalised.
	Presented string
	// Err is the failed attempt to read the certificate.
	Err error
}

func (e *UnconfirmedCertificateError) Error() string {
	return fmt.Sprintf("the server now presents a certificate with SHA-256 fingerprint %s, which could not be "+
		"confirmed to be PBS's over a connection trusted before the change: %s", FormatFingerprint(e.Presented), e.Err)
}

func (e *UnconfirmedCertificateError) Unwrap() error { return e.Err }

// CertificateReadError is a failure to read the proxy's certificate, GET
// /nodes/{node}/certificates/info, around a change: before it, when nothing
// was changed, or after it, when the change may have installed a new
// certificate the client does not know of, and so does not trust.
type CertificateReadError struct {
	// After is whether the read came after the change.
	After bool
	Err   error
}

func (e *CertificateReadError) Error() string {
	if e.After {
		return "reading the certificate after changing it: " + e.Err.Error()
	}
	return "reading the certificate before changing it: " + e.Err.Error()
}

func (e *CertificateReadError) Unwrap() error { return e.Err }

// CertificateChange is the certificate of the proxy before and after a
// change.
type CertificateChange struct {
	// Before is what PBS reported before the change: the certificate in
	// proxy.pem, which its proxy serves unless it could not load it.
	Before CertificateInfo
	// PresentedBefore is the normalised fingerprint of the certificate a new
	// connection to the endpoint got before the change — the endpoint's,
	// never an HTTPS proxy's on the way (see PresentedFingerprint): Before's,
	// unless PBS's proxy could not load the certificate PBS last wrote, or a
	// TLS front end serves PBS under the endpoint. It is empty when the
	// client could not look, as with a transport that is not its own
	// (ErrNoTLSTransport).
	PresentedBefore string
	// After is empty when the new certificate could not be confirmed.
	After CertificateInfo
	// Unconfirmed is set when the proxy presents another certificate, which
	// could not be read over the connection of the change.
	Unconfirmed *UnconfirmedCertificateError
}

// Changed reports whether the proxy serves another certificate now.
func (c CertificateChange) Changed() bool {
	return c.Unconfirmed != nil || (c.After.Fingerprint != "" && c.Before.Fingerprint != c.After.Fingerprint)
}

// The new certificate is read again after a network error this many times,
// starting this far apart and doubling, in case the proxy was briefly not
// answering.
const (
	certificateReadAttempts = 5
	certificateReadInterval = 250 * time.Millisecond
)

// ChangeCertificate runs change, which has a node change the certificate of
// its proxy — OrderACMECertificate or RenewACMECertificate and a wait for
// the task, UploadCustomCertificate or DeleteCustomCertificate, called with
// the context it is given —, and returns the certificate before and after.
// The client trusts the new certificate from then on, whatever its
// settings say (see above). Certificate changes of one client run one at a
// time.
//
// Before the change, it also looks at the certificate a new connection gets
// (PresentedFingerprint), which is what tells, after the change, a proxy
// that could not load the new certificate from one that never served PBS's
// file, such as a TLS front end. Failing to look is no error.
//
// The certificate is read after change even when change fails, since a task
// may fail after it installed the new certificate; the error is then
// change's, joined with the read's. A failed read is a
// *CertificateReadError. When the proxy presents another certificate that
// cannot be read over the connection of the change, the result's
// Unconfirmed says so and the client does not trust it.
func (c *Client) ChangeCertificate(ctx context.Context, node string, change func(ctx context.Context) error) (CertificateChange, error) {
	c.certificateChange.Lock()
	defer c.certificateChange.Unlock()

	changing := make(chan struct{})
	c.changingMu.Lock()
	c.changing = changing
	c.changingMu.Unlock()
	defer func() {
		c.changingMu.Lock()
		c.changing = nil
		c.changingMu.Unlock()
		close(changing)
	}()

	conn, closeConn := c.dedicatedConnection()
	defer closeConn()
	connCtx := context.WithValue(ctx, connectionKey{}, conn)

	var result CertificateChange
	before, err := c.NodeProxyCertificate(connCtx, node)
	if err != nil {
		return result, &CertificateReadError{Err: err}
	}
	result.Before = before
	if presented, err := c.PresentedFingerprint(ctx); err == nil {
		result.PresentedBefore = presented
	} else if !errors.Is(err, ErrNoTLSTransport) {
		tflog.Debug(ctx, "could not look at the certificate the PBS endpoint presents before the change", map[string]any{"error": err.Error()})
	}

	changeErr := change(connCtx)

	after, readErr := c.readChangedCertificate(connCtx, node)
	var untrusted *UntrustedCertificateError
	switch {
	case errors.As(readErr, &untrusted) && untrusted.Presented() != "":
		result.Unconfirmed = &UnconfirmedCertificateError{Presented: untrusted.Presented(), Err: readErr}
		readErr = nil
	case readErr != nil:
		readErr = &CertificateReadError{After: true, Err: readErr}
	default:
		// Read over the connection the client trusted before the change:
		// what PBS says it serves now is what the client may trust.
		result.After = after
		if result.Changed() {
			if err := c.TrustCertificate(after.Fingerprint); err != nil {
				readErr = fmt.Errorf("PBS reported the new certificate's fingerprint as %q: %w", after.Fingerprint, err)
			} else {
				tflog.Info(ctx, "PBS changed its certificate; trusting the new one", map[string]any{
					"before": before.Fingerprint, "after": after.Fingerprint,
				})
			}
		}
	}
	return result, errors.Join(changeErr, readErr)
}

// readChangedCertificate reads the proxy's certificate after a change,
// again after a network error: the proxy may not have answered for a moment.
// An error from PBS or a certificate the client does not trust is not tried
// again.
func (c *Client) readChangedCertificate(ctx context.Context, node string) (CertificateInfo, error) {
	delay := certificateReadInterval
	for attempt := 1; ; attempt++ {
		info, err := c.NodeProxyCertificate(ctx, node)
		var apiErr *Error
		var untrusted *UntrustedCertificateError
		if err == nil || errors.As(err, &apiErr) || errors.As(err, &untrusted) || isContextError(err) || attempt >= certificateReadAttempts {
			return info, err
		}
		tflog.Debug(ctx, "reading the PBS certificate after the change failed; trying again", map[string]any{"error": err.Error()})
		if err := c.sleep(ctx, delay); err != nil {
			return info, err
		}
		delay *= 2
	}
}
