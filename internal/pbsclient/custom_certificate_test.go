package pbsclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// customCertificate makes a certificate for cn with key, signed by parent's
// key, or self-signed without a parent, and returns its PEM.
func customCertificate(t *testing.T, cn string, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, string) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(1790000000, 0),
		NotAfter:              time.Unix(1790000000+365*24*3600, 0),
		DNSNames:              []string{cn},
		BasicConstraintsValid: true,
		IsCA:                  parent == nil,
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func pkcs8PEM(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestCheckCustomCertificate(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, caPEM := customCertificate(t, "Private CA", caKey, nil, nil)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leaf, leafPEM := customCertificate(t, "pbs.example.org", ecKey, ca, caKey)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, rsaPEM := customCertificate(t, "rsa.example.org", rsaKey, ca, caKey)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	_, edPEM := customCertificate(t, "ed.example.org", edKey, ca, caKey)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, weakPEM := customCertificate(t, "weak.example.org", weakKey, ca, caKey)
	_, weakCAPEM := customCertificate(t, "Weak CA", weakKey, nil, nil)
	ecParams := "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"

	fingerprint, err := CheckCustomCertificate(leafPEM+"\n# the CA\n"+caPEM, pkcs8PEM(t, ecKey))
	if err != nil || fingerprint != CertificateFingerprint(leaf) {
		t.Fatalf("CheckCustomCertificate = %q, %v", fingerprint, err)
	}
	for name, tc := range map[string]struct{ certs, key string }{
		"SEC 1 EC":   {leafPEM, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))},
		"ecparam":    {leafPEM, ecParams + string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))},
		"PKCS #1":    {rsaPEM, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))},
		"PKCS #8 ed": {edPEM, pkcs8PEM(t, edKey)},
	} {
		if _, err := CheckCustomCertificate(tc.certs, tc.key); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	secretKey := pkcs8PEM(t, ecKey)
	for name, tc := range map[string]struct{ certs, key, want string }{
		"no certificate":    {"nothing here", secretKey, "no PEM-encoded certificate"},
		"key in the chain":  {leafPEM + secretKey, secretKey, "not a CERTIFICATE"},
		"broken block":      {"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", secretKey, "parsing certificate 1"},
		"CA first":          {caPEM + leafPEM, secretKey, "not the key of the first certificate"},
		"other key":         {rsaPEM, secretKey, "not the key of the first certificate"},
		"not PEM":           {leafPEM, "secret", "not PEM-encoded"},
		"encrypted":         {leafPEM, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", "encrypted"},
		"legacy encrypted":  {leafPEM, "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END EC PRIVATE KEY-----\n", "encrypted"},
		"garbled key":       {leafPEM, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "does not parse"},
		"public key":        {leafPEM, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", "no private key, only PUBLIC KEY"},
		"weak RSA leaf":     {weakPEM, pkcs8PEM(t, weakKey), "1024-bit RSA key"},
		"weak RSA in chain": {leafPEM + weakCAPEM, secretKey, "certificate 2 of the chain"},
	} {
		_, err := CheckCustomCertificate(tc.certs, tc.key)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", name, err, tc.want)
		}
		if body := strings.Split(secretKey, "\n")[1]; err != nil && strings.Contains(err.Error(), body) {
			t.Errorf("%s: the error shows the key: %v", name, err)
		}
	}
}

func TestUploadCustomCertificateKeepsTheKeyOutOfErrors(t *testing.T) {
	fake := newFakePBS()
	const key = "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n"
	var got map[string][]string
	fake.handle("POST /nodes/localhost/certificates/custom", func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		got = req.PostForm
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("failed to parse private key: " + req.PostForm.Get("key")))
	})
	client := fake.client(t)
	err := client.UploadCustomCertificate(context.Background(), "localhost", "chain", key)
	if err == nil || strings.Contains(err.Error(), "c2VjcmV0") || !strings.Contains(err.Error(), "failed to parse private key") {
		t.Fatalf("error = %v", err)
	}
	if got["certificates"][0] != "chain" || got["key"][0] != key || len(got) != 2 {
		t.Fatalf("form = %v", got)
	}
}

// PresentedFingerprint sees what a new connection gets, whatever the
// client trusts, and sends nothing over it.
func TestPresentedFingerprint(t *testing.T) {
	old := newTestCertificate(t, "pbs.test")
	uploaded := newTestCertificate(t, "pbs.example.com")
	fake := newFakePBS()
	c, server := serveSwappableTLS(t, fake, old, Options{Endpoint: "https://pbs.test:8007", CertFingerprint: CertificateFingerprint(old.cert)})
	ctx := context.Background()

	got, err := c.PresentedFingerprint(ctx)
	if err != nil || got != CertificateFingerprint(old.cert) {
		t.Fatalf("PresentedFingerprint = %q, %v", got, err)
	}
	server.swap(uploaded)
	got, err = c.PresentedFingerprint(ctx)
	if err != nil || got != CertificateFingerprint(uploaded.cert) {
		t.Fatalf("after the swap, PresentedFingerprint = %q, %v", got, err)
	}
	if routes := fake.routes(); len(routes) != 0 {
		t.Fatalf("the probe sent requests: %v", routes)
	}
	if _, err := (&Client{httpClient: &http.Client{Transport: fake}}).PresentedFingerprint(ctx); !errors.Is(err, ErrNoTLSTransport) {
		t.Fatalf("without a TLS transport: %v", err)
	}
}
