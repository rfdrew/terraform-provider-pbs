package pbsclient

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// PBS generates a self-signed certificate at installation and shows its
// fingerprint on the dashboard, in `proxmox-backup-manager cert info` and in
// GET /nodes/{node}/certificates/info, as 32 colon-separated lower-case hex
// pairs. Proxmox VE and proxmox-backup-client trust such a server by that
// fingerprint alone, and so does this client: CertFingerprint pins it. CAFile
// is the alternative for a certificate issued by a private CA, and
// InsecureSkipVerify the last resort. The three are mutually exclusive.

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

// verifyFingerprint returns a tls.Config.VerifyConnection callback that
// accepts a connection when any certificate the server presents has the given
// fingerprint, which must already be normalised.
//
// Any presented certificate may match, leaf or intermediate, and the host
// name is not checked, because a self-signed certificate is trusted by its
// hash alone — as Proxmox VE does for a PBS storage. VerifyConnection rather
// than VerifyPeerCertificate, because Go skips VerifyPeerCertificate on
// resumed TLS sessions and VerifyConnection runs on every connection.
func verifyFingerprint(fingerprint string) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		presented := make([]string, 0, len(state.PeerCertificates))
		for _, cert := range state.PeerCertificates {
			got := CertificateFingerprint(cert)
			if got == fingerprint {
				return nil
			}
			presented = append(presented, got)
		}
		if len(presented) == 0 {
			return fmt.Errorf("the server presented no certificate to match SHA-256 fingerprint %s", fingerprint)
		}
		return fmt.Errorf("no certificate the server presented matches SHA-256 fingerprint %s (the server presented %s)",
			fingerprint, strings.Join(presented, ", "))
	}
}

// tlsConfig builds the TLS configuration Options asks for, or nil for Go's
// defaults: the system roots and host name verification.
func tlsConfig(opts Options) (*tls.Config, error) {
	set := 0
	for _, isSet := range []bool{opts.CertFingerprint != "", opts.CAFile != "", opts.InsecureSkipVerify} {
		if isSet {
			set++
		}
	}
	if set > 1 {
		return nil, errors.New("a certificate fingerprint, a CA file and skipping certificate verification are mutually exclusive; set only one of them")
	}

	switch {
	case opts.CertFingerprint != "":
		fingerprint, err := NormaliseFingerprint(opts.CertFingerprint)
		if err != nil {
			return nil, err
		}
		// Chain and host name verification are switched off only so that
		// VerifyConnection can decide instead; it trusts nothing but the
		// pinned certificate.
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // VerifyConnection pins the certificate.
			VerifyConnection:   verifyFingerprint(fingerprint),
			MinVersion:         tls.VersionTLS12,
		}, nil

	case opts.CAFile != "":
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading the CA certificate file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the CA certificate file %s contains no PEM-encoded certificate", opts.CAFile)
		}
		return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil

	case opts.InsecureSkipVerify:
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Explicitly requested.
			MinVersion:         tls.VersionTLS12,
		}, nil
	}
	return nil, nil
}
