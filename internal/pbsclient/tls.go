package pbsclient

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// PBS generates a self-signed certificate at installation and shows its
// fingerprint on the dashboard, in `proxmox-backup-manager cert info` and in
// GET /nodes/{node}/certificates/info, as 32 colon-separated lower-case hex
// pairs. Proxmox VE and proxmox-backup-client trust such a server by that
// fingerprint alone, and so does this client: CertFingerprint pins it. CAFile
// is the alternative for a certificate issued by a private CA, the system's
// roots the default for one a public CA such as Let's Encrypt issued, and
// InsecureSkipVerify the last resort. The three settings are mutually
// exclusive.
//
// The client also trusts certificates the server switched to while the
// client itself had it change its certificate — ordering an ACME
// certificate, or going back to a self-signed one: see ChangeCertificate. Go
// verifies a chain only before VerifyConnection runs, and a certificate
// accepted that way must pass whatever the settings say, so the client
// switches Go's own verification off and does all of it in
// VerifyConnection: the same chain and host name verification, or the
// pinned fingerprint.

// NormaliseFingerprint turns a SHA-256 certificate fingerprint into 64
// lower-case hex digits. It accepts any case, the colon separators PBS and
// OpenSSL print (`openssl x509 -noout -fingerprint -sha256`), and whitespace,
// but nothing else: a value that can never match would only fail later, on
// every TLS handshake.
func NormaliseFingerprint(fingerprint string) (string, error) {
	normalised := strings.Map(func(r rune) rune {
		switch {
		case r == ':' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
			return -1
		case r >= 'A' && r <= 'F':
			return r + ('a' - 'A')
		default:
			return r
		}
	}, fingerprint)

	if len(normalised) != sha256.Size*2 {
		return "", fmt.Errorf("invalid SHA-256 certificate fingerprint %q: want 64 hexadecimal digits, optionally separated by colons, got %d", fingerprint, len(normalised))
	}
	if _, err := hex.DecodeString(normalised); err != nil {
		return "", fmt.Errorf("invalid SHA-256 certificate fingerprint %q: want 64 hexadecimal digits, optionally separated by colons", fingerprint)
	}
	return normalised, nil
}

// FormatFingerprint writes a normalised fingerprint the way PBS shows it:
// colon-separated lower-case hex pairs.
func FormatFingerprint(normalised string) string {
	var b strings.Builder
	for i := 0; i+1 < len(normalised); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(normalised[i : i+2])
	}
	return b.String()
}

// CertificateFingerprint is the SHA-256 fingerprint of a certificate's DER
// encoding, in the form NormaliseFingerprint returns.
func CertificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// UntrustedCertificateError means the server presented a certificate the
// client does not trust: one whose fingerprint is not the pinned one, or
// whose chain or host name does not verify.
type UntrustedCertificateError struct {
	// Fingerprints are those of the certificates the server presented, leaf
	// first, normalised.
	Fingerprints []string
	// Pinned is the fingerprint the client pins, when it pins one.
	Pinned string
	// Err is why the chain did not verify, when the client verifies it.
	Err error
}

func (e *UntrustedCertificateError) Error() string {
	switch {
	case e.Pinned != "" && len(e.Fingerprints) == 0:
		return fmt.Sprintf("the server presented no certificate to match SHA-256 fingerprint %s", e.Pinned)
	case e.Pinned != "":
		return fmt.Sprintf("the certificate the server presented does not match SHA-256 fingerprint %s (the server presented %s)",
			e.Pinned, strings.Join(e.Fingerprints, ", "))
	case e.Err != nil:
		return e.Err.Error()
	}
	return "the server presented no certificate"
}

func (e *UntrustedCertificateError) Unwrap() error { return e.Err }

// Presented returns the fingerprint of the certificate the server presented,
// normalised, or "" when it presented none.
func (e *UntrustedCertificateError) Presented() string {
	if len(e.Fingerprints) == 0 {
		return ""
	}
	return e.Fingerprints[0]
}

// verifyFingerprint returns a tls.Config.VerifyConnection callback that
// accepts a connection when the certificate the server presents has the given
// fingerprint, which must already be normalised.
//
// Only the server's own certificate, the leaf, may match: the handshake
// proves the server holds the leaf's key, while the certificates after it are
// sent as they are, and anyone may send PBS's. The host name is not checked,
// because a self-signed certificate is trusted by its hash alone — as Proxmox
// VE and proxmox-backup-client do, which compare the leaf only.
// VerifyConnection rather than VerifyPeerCertificate, because Go skips
// VerifyPeerCertificate on resumed TLS sessions and VerifyConnection runs on
// every connection.
func verifyFingerprint(fingerprint string) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		return matchFingerprint(fingerprint, state.PeerCertificates)
	}
}

// matchFingerprint accepts certs, leaf first, when the leaf has the given
// fingerprint.
func matchFingerprint(fingerprint string, certs []*x509.Certificate) error {
	presented := make([]string, 0, len(certs))
	for _, cert := range certs {
		presented = append(presented, CertificateFingerprint(cert))
	}
	if len(presented) > 0 && presented[0] == fingerprint {
		return nil
	}
	return &UntrustedCertificateError{Fingerprints: presented, Pinned: fingerprint}
}

// trust decides which certificates the client accepts: the pinned one, or a
// chain that verifies against the CA file's roots or the system's for the
// endpoint's host name, or anything at all — and, whatever the settings,
// the certificates the server switched to while the client changed them.
type trust struct {
	// pinned is the normalised fingerprint to pin, or "".
	pinned string
	// roots are the CA file's certificates, or nil for the system's roots.
	roots *x509.CertPool
	// host is the endpoint's host name, which a verified chain must cover.
	host string
	// insecure skips verification.
	insecure bool

	// mu guards accepted and generation. accepted holds the normalised
	// fingerprints of the certificates the server switched to;
	// generation counts additions, so that a request that failed can tell
	// whether trying again may succeed.
	mu         sync.RWMutex
	accepted   map[string]bool
	generation uint64
}

// newTrust builds the trust Options asks for; host is the endpoint's host
// name.
func newTrust(opts Options, host string) (*trust, error) {
	set := 0
	for _, isSet := range []bool{opts.CertFingerprint != "", opts.CAFile != "", opts.InsecureSkipVerify} {
		if isSet {
			set++
		}
	}
	if set > 1 {
		return nil, errors.New("a certificate fingerprint, a CA file and skipping certificate verification are mutually exclusive; set only one of them")
	}

	t := &trust{host: host, insecure: opts.InsecureSkipVerify, accepted: map[string]bool{}}
	switch {
	case opts.CertFingerprint != "":
		fingerprint, err := NormaliseFingerprint(opts.CertFingerprint)
		if err != nil {
			return nil, err
		}
		t.pinned = fingerprint

	case opts.CAFile != "":
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading the CA certificate file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the CA certificate file %s contains no PEM-encoded certificate", opts.CAFile)
		}
		t.roots = pool
	}
	return t, nil
}

// tlsConfig is the TLS configuration of the client's transport. Go's
// verification is off; VerifyConnection does it instead, on every
// connection, resumed ones included.
func (t *trust) tlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection verifies the certificate.
		VerifyConnection:   t.verifyConnection,
		MinVersion:         tls.VersionTLS12,
	}
}

func (t *trust) verifyConnection(state tls.ConnectionState) error {
	if t.insecure {
		return nil
	}
	// The handshake with an HTTPS proxy, through which net/http reaches
	// the endpoint, names the proxy: its certificate is verified for it, as
	// Go would, against the CAs. The client sets ServerName itself; it is
	// empty for an IP address, which the SNI leaves out.
	if state.ServerName != "" && state.ServerName != t.host {
		return (&trust{roots: t.roots, host: state.ServerName}).verifyCertificates(state.PeerCertificates)
	}
	if len(state.PeerCertificates) > 0 && t.isAccepted(CertificateFingerprint(state.PeerCertificates[0])) {
		return nil
	}
	return t.verifyCertificates(state.PeerCertificates)
}

// verifyCertificates checks a presented chain, leaf first, against the
// settings alone, without the certificates accepted since.
func (t *trust) verifyCertificates(certs []*x509.Certificate) error {
	switch {
	case t.insecure:
		return nil
	case t.pinned != "":
		return matchFingerprint(t.pinned, certs)
	case len(certs) == 0:
		return &UntrustedCertificateError{}
	}
	// What Go's TLS client does itself: the leaf must chain to a root
	// through the other presented certificates, and cover the host name.
	opts := x509.VerifyOptions{DNSName: t.host, Roots: t.roots, Intermediates: x509.NewCertPool()}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		presented := make([]string, 0, len(certs))
		for _, cert := range certs {
			presented = append(presented, CertificateFingerprint(cert))
		}
		// Wrapped as Go's TLS client wraps it, so that the message reads
		// the same as without this client's verification.
		return &UntrustedCertificateError{
			Fingerprints: presented,
			Err:          &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err},
		}
	}
	return nil
}

func (t *trust) isAccepted(fingerprint string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.accepted[fingerprint]
}

// accept trusts the certificate with the given normalised fingerprint from
// now on.
func (t *trust) accept(fingerprint string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.accepted[fingerprint] {
		t.accepted[fingerprint] = true
		t.generation++
	}
}

func (t *trust) currentGeneration() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.generation
}

// PinsCertificate reports whether the client trusts the server by a pinned
// fingerprint, rather than by verifying its certificate against CAs or not
// at all.
func (c *Client) PinsCertificate() bool { return c.trust.pinned != "" }

// SkipsCertificateVerification reports whether the client trusts any
// certificate.
func (c *Client) SkipsCertificateVerification() bool { return c.trust.insecure }

// VerifyCertificatePEM reports whether the client's settings alone — the
// pinned fingerprint, or the CA file's or the system's roots and the
// endpoint's host name — trust the certificate chain in certPEM, leaf first,
// as PBS reports it in GET /nodes/{node}/certificates/info. A new client
// configured the same way would accept the server presenting it only if
// this returns nil.
func (c *Client) VerifyCertificatePEM(certPEM string) error {
	certs, err := parseCertificatesPEM(certPEM)
	if err != nil {
		return err
	}
	return c.trust.verifyCertificates(certs)
}

// CertificateProblems are the reasons a client verifying certificates against
// CAs would not trust a certificate chain.
type CertificateProblems struct {
	// Chain is why the chain does not verify against the client's CAs:
	// the CA file's when the client has one, otherwise the system's.
	Chain error
	// SystemChain is why it does not verify against the system's CAs; the
	// same as Chain for a client without a CA file.
	SystemChain error
	// Host is why the leaf does not cover the endpoint's host name.
	Host error
}

// CertificateProblems reports why a client that verifies certificates
// against CAs would not trust the certificate chain in certPEM, leaf first.
// For a client that pins a fingerprint, it is what removing the fingerprint
// would leave.
func (c *Client) CertificateProblems(certPEM string) CertificateProblems {
	certs, err := parseCertificatesPEM(certPEM)
	if err != nil {
		return CertificateProblems{Chain: err, SystemChain: err}
	}
	p := CertificateProblems{
		Chain: (&trust{roots: c.trust.roots}).verifyCertificates(certs),
		Host:  certs[0].VerifyHostname(c.trust.host),
	}
	p.SystemChain = p.Chain
	if c.trust.roots != nil {
		p.SystemChain = (&trust{}).verifyCertificates(certs)
	}
	return p
}

// UsesCAFile reports whether the client verifies certificates against a CA
// file rather than the system's CAs.
func (c *Client) UsesCAFile() bool { return c.trust.roots != nil }

// parseCertificatesPEM parses the certificates in PEM text, skipping other
// blocks.
func parseCertificatesPEM(certPEM string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing the certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM-encoded certificate to verify")
	}
	return certs, nil
}

// TrustCertificate makes the client trust, for the rest of its life, the
// certificate with the given SHA-256 fingerprint, in any form
// NormaliseFingerprint accepts, whatever its settings say.
func (c *Client) TrustCertificate(fingerprint string) error {
	normalised, err := NormaliseFingerprint(fingerprint)
	if err != nil {
		return err
	}
	c.trust.accept(normalised)
	return nil
}

// EndpointHost is the host name of the endpoint, which a certificate must
// cover for a client that verifies it against CAs.
func (c *Client) EndpointHost() string { return c.trust.host }
