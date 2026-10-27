package pbsclient

import (
	"context"
	"fmt"
)

// ProxyCertificateFile is the certificate the PBS proxy serves on port 8007,
// the one clients pin.
const ProxyCertificateFile = "proxy.pem"

// CertificateInfo is one entry of GET /nodes/{node}/certificates/info.
type CertificateInfo struct {
	Filename string `json:"filename"`
	// Fingerprint is the SHA-256 fingerprint, as colon-separated lower-case
	// hex pairs.
	Fingerprint string   `json:"fingerprint"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	NotBefore   int64    `json:"notbefore"`
	NotAfter    int64    `json:"notafter"`
	SAN         []string `json:"san"`
	// PublicKeyType is e.g. "rsaEncryption", PublicKeyBits its size.
	PublicKeyType string `json:"public-key-type"`
	PublicKeyBits int64  `json:"public-key-bits"`
}

// Certificates reads the node's certificates. It needs Sys.Audit on
// /system/certificates.
func (c *Client) Certificates(ctx context.Context) ([]CertificateInfo, error) {
	var certs []CertificateInfo
	if _, err := c.Get(ctx, c.NodePath("certificates", "info"), nil, &certs); err != nil {
		return nil, err
	}
	return certs, nil
}

// ProxyCertificate returns the certificate the proxy serves.
func (c *Client) ProxyCertificate(ctx context.Context) (CertificateInfo, error) {
	certs, err := c.Certificates(ctx)
	if err != nil {
		return CertificateInfo{}, err
	}
	for _, cert := range certs {
		if cert.Filename == ProxyCertificateFile {
			return cert, nil
		}
	}
	return CertificateInfo{}, fmt.Errorf("GET %s lists no %s", c.NodePath("certificates", "info"), ProxyCertificateFile)
}
