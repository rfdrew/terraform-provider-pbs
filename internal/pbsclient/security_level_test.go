package pbsclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSecurityLevelBits(t *testing.T) {
	for level, want := range map[int]int{-1: 0, 0: 0, 1: 80, 2: 112, 3: 128, 4: 192, 5: 256, 6: 256, 99: 256} {
		if got := SecurityLevelBits(level); got != want {
			t.Errorf("level %d: %d bits, want %d", level, got, want)
		}
	}
	for level, want := range map[int]string{
		0: "nothing",
		2: "112 bits of security: RSA keys of 2048 bits or more, EC keys of 224 bits or more, and no SHA-1",
		3: "128 bits of security: RSA keys of 3072 bits",
		7: "256 bits of security: RSA keys of 15360 bits",
	} {
		if got := SecurityLevelRequirement(level); !strings.HasPrefix(got, want) {
			t.Errorf("level %d: %q, want %q…", level, got, want)
		}
	}
}

// The levels and refusals are OpenSSL 3.5's: `openssl s_server -cipher`
// with each list loads a certificate at the level given, and refuses the
// lists with an error as an "invalid command" of ssl_cipher_process_rulestr.
func TestCipherListSecurityLevel(t *testing.T) {
	for _, tc := range []struct {
		list    string
		level   int
		command string
		err     string
	}{
		{list: "", level: -1},
		{list: "HIGH:!aNULL", level: -1},
		{list: "HIGH:@STRENGTH", level: -1},
		{list: "HIGH:@SECLEVEL=0", level: 0, command: "@SECLEVEL=0"},
		{list: "@SECLEVEL=1:HIGH", level: 1, command: "@SECLEVEL=1"},
		{list: "HIGH:@SECLEVEL=5", level: 5, command: "@SECLEVEL=5"},
		// The last level counts.
		{list: "@SECLEVEL=4:HIGH:@SECLEVEL=3", level: 3, command: "@SECLEVEL=3"},
		{list: "HIGH:@SECLEVEL=3:@SECLEVEL=1", level: 1, command: "@SECLEVEL=1"},
		{list: "HIGH:@STRENGTH:@SECLEVEL=1", level: 1, command: "@SECLEVEL=1"},
		{list: "HIGH::@SECLEVEL=1:", level: 1, command: "@SECLEVEL=1"},
		// Every separator OpenSSL knows, and a command straight after a
		// name.
		{list: "HIGH @SECLEVEL=3", level: 3, command: "@SECLEVEL=3"},
		{list: "HIGH,@SECLEVEL=3", level: 3, command: "@SECLEVEL=3"},
		{list: "HIGH;@SECLEVEL=3", level: 3, command: "@SECLEVEL=3"},
		{list: "HIGH:!aNULL@SECLEVEL=3", level: 3, command: "@SECLEVEL=3"},
		{list: "HIGH:kRSA+AES@SECLEVEL=3", level: 3, command: "@SECLEVEL=3"},
		// OpenSSL ignores the rest of the item after a command.
		{list: "HIGH:@SECLEVEL=3@SECLEVEL=1", level: 3, command: "@SECLEVEL=3"},
		{list: "HIGH:@SECLEVEL=3+@SECLEVEL=1", level: 3, command: "@SECLEVEL=3"},
		{list: "HIGH:@SECLEVEL=3!", level: 3, command: "@SECLEVEL=3"},
		{list: "HIGH:!aNULL:@SECLEVEL=4+HIGH", level: 4, command: "@SECLEVEL=4"},
		{list: "HIGH:@STRENGTH@SECLEVEL=1", level: -1},
		// OpenSSL refuses a level that is not one digit from 0 to 5.
		{list: "HIGH:@SECLEVEL=9", err: `OpenSSL refuses the command "@SECLEVEL=9"`},
		{list: "HIGH:@SECLEVEL=10", err: `"@SECLEVEL=10"`},
		{list: "HIGH:@SECLEVEL=99999999999999999999", err: `"@SECLEVEL=99999999999999999999"`},
		{list: "HIGH:@SECLEVEL=03", err: `"@SECLEVEL=03"`},
		{list: "HIGH:@SECLEVEL=3X", err: `"@SECLEVEL=3X"`},
		{list: "HIGH:@SECLEVEL=3.0", err: `"@SECLEVEL=3.0"`},
		{list: "HIGH:@SECLEVEL=3=", err: `"@SECLEVEL=3="`},
		{list: "HIGH:@SECLEVEL=-1", err: `"@SECLEVEL=-1"`},
		{list: "HIGH:@SECLEVEL=", err: `"@SECLEVEL="`},
		// Any other command, lower case included, and an @ alone.
		{list: "HIGH:@seclevel=3", err: `"@seclevel=3": it knows @STRENGTH and @SECLEVEL=N`},
		{list: "HIGH:@strength", err: `"@strength"`},
		{list: "HIGH:@FOO", err: `"@FOO"`},
		{list: "HIGH:@", err: `the command "@"`},
		{list: "HIGH:@@SECLEVEL=3", err: `the command "@"`},
		// An @ where OpenSSL expects a name.
		{list: "HIGH:!@SECLEVEL=3", err: `OpenSSL refuses "!@SECLEVEL=3": an @ command cannot follow the operator '!'`},
		{list: "HIGH:-@SECLEVEL=3", err: `"-@SECLEVEL=3"`},
		{list: "HIGH:+@SECLEVEL=3", err: `"+@SECLEVEL=3"`},
		{list: "HIGH+@SECLEVEL=3", err: `"+@SECLEVEL=3"`},
		{list: "HIGH:AES256+@SECLEVEL=3", err: `"+@SECLEVEL=3"`},
		// An operator that no name follows.
		{list: "HIGH:!", err: `OpenSSL refuses "!": the operator '!' must be followed by a cipher name`},
		{list: "HIGH:-", err: `OpenSSL refuses "-": the operator '-'`},
		{list: "HIGH:+", err: `OpenSSL refuses "+": the operator '+'`},
		{list: "HIGH:@SECLEVEL=3:!", err: `OpenSSL refuses "!"`},
		{list: "HIGH:!:@SECLEVEL=3", err: `OpenSSL refuses "!"`},
		{list: "HIGH:! aNULL", err: `OpenSSL refuses "!"`},
		{list: "HIGH:!!aNULL", err: `OpenSSL refuses "!!aNULL": the operator '!'`},
		{list: "HIGH:-+AES", err: `OpenSSL refuses "-+AES": the operator '-'`},
		// After a name it does not know, OpenSSL ignores the item, the
		// command in it too, and takes this list at level 2; the provider
		// cannot know which names those are.
		{list: "FOO@SECLEVEL=9:HIGH", err: `"@SECLEVEL=9"`},
		// The same goes for a '+' that no name follows, which OpenSSL
		// refuses after a name it knows only: the provider leaves it to
		// OpenSSL, as it leaves names that match no cipher.
		{list: "FOO+:HIGH:@SECLEVEL=3", level: 3, command: "@SECLEVEL=3"},
		{list: "ECDHE-RSA-AES256-GCM-SHA38", level: -1},
	} {
		level, command, err := CipherListSecurityLevel(tc.list)
		switch {
		case tc.err != "":
			if err == nil || !strings.Contains(err.Error(), tc.err) || level != -1 || command != "" {
				t.Errorf("%q: %d, %q, %v; want an error with %q", tc.list, level, command, err, tc.err)
			}
		case err != nil || level != tc.level || command != tc.command:
			t.Errorf("%q: %d, %q, %v; want %d, %q", tc.list, level, command, err, tc.level, tc.command)
		}
	}
}

// chainCertificate makes a certificate for cn with key's public key, signed
// by parentKey, or self-signed without a parent.
func chainCertificate(t *testing.T, cn string, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(1790000000, 0),
		NotAfter:              time.Unix(1790000000+90*24*3600, 0),
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
	return cert
}

// rewrapCertificate returns cert with another signature algorithm, when
// algorithm is set, and another subject public key info, when spki is set:
// certificates Go cannot make, such as one signed with SHA-1 or holding an
// Ed448 key. The signature is garbage, which no check here verifies.
func rewrapCertificate(t *testing.T, cert *x509.Certificate, algorithm *pkix.AlgorithmIdentifier, spki []byte) *x509.Certificate {
	t.Helper()
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(cert.RawTBSCertificate, &tbs); err != nil {
		t.Fatal(err)
	}
	// version, serial number, signature, issuer, validity, subject, subject
	// public key info, extensions.
	var fields []asn1.RawValue
	for rest := tbs.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			t.Fatal(err)
		}
		fields = append(fields, field)
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		t.Fatal(err)
	}
	if algorithm != nil {
		der, err := asn1.Marshal(*algorithm)
		if err != nil {
			t.Fatal(err)
		}
		fields[2] = asn1.RawValue{FullBytes: der}
		outer.Algorithm = *algorithm
	}
	if spki != nil {
		fields[6] = asn1.RawValue{FullBytes: spki}
	}
	var body []byte
	for _, field := range fields {
		body = append(body, field.FullBytes...)
	}
	newTBS, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatal(err)
	}
	outer.TBS = asn1.RawValue{FullBytes: newTBS}
	der, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return rewrapped
}

// withRSAKey returns cert holding an RSA public key of bits, which is all a
// check of the chain looks at: making a large RSA key would take long.
func withRSAKey(t *testing.T, cert *x509.Certificate, bits int) *x509.Certificate {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return rewrapCertificate(t, cert, nil, spki)
}

// withEd448Key returns cert holding an Ed448 key, which Go does not know.
func withEd448Key(t *testing.T, cert *x509.Certificate) *x509.Certificate {
	t.Helper()
	spki, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: oidEd448}, asn1.BitString{Bytes: make([]byte, 57), BitLength: 57 * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return rewrapCertificate(t, cert, nil, spki)
}

// signedWith returns cert with a signature algorithm of oid.
func signedWith(t *testing.T, cert *x509.Certificate, oid asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	return rewrapCertificate(t, cert, &pkix.AlgorithmIdentifier{Algorithm: oid}, nil)
}

var (
	oidSHA1WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidMD5WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidECDSAWithSHA1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
)

func TestCheckChainSecurityLevel(t *testing.T) {
	ecKey := func(curve elliptic.Curve) *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	rootKey := ecKey(elliptic.P384())
	root := chainCertificate(t, "Root", rootKey, nil, nil)
	leaf := func(cn string, key crypto.Signer) *x509.Certificate {
		return chainCertificate(t, cn, key, root, rootKey)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	p256 := ecKey(elliptic.P256())
	// PBS's own certificate is self-signed.
	selfSigned := chainCertificate(t, "pbs", p256, nil, nil)

	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
		// weak are, for levels 1 to 5, the weaknesses found.
		weak [5][]string
	}{{
		name:  "self-signed P-256",
		chain: []*x509.Certificate{selfSigned},
		weak:  [5][]string{nil, nil, nil, {"1: a 256-bit EC key (P-256)"}, {"1: a 256-bit EC key (P-256)"}},
	}, {
		name:  "P-224 under a P-384 root",
		chain: []*x509.Certificate{leaf("leaf", ecKey(elliptic.P224())), root},
		weak:  [5][]string{nil, nil, {"1: a 224-bit EC key (P-224)"}, {"1: a 224-bit EC key (P-224)"}, {"1: a 224-bit EC key (P-224)", "1: a signature with SHA-384", "2: a 384-bit EC key (P-384)"}},
	}, {
		name:  "P-521 under a P-384 root",
		chain: []*x509.Certificate{leaf("leaf", ecKey(elliptic.P521()))},
		weak:  [5][]string{nil, nil, nil, nil, {"1: a signature with SHA-384"}},
	}, {
		name:  "RSA-2048",
		chain: []*x509.Certificate{withRSAKey(t, leaf("leaf", p256), 2048)},
		weak:  [5][]string{nil, nil, {"1: a 2048-bit RSA key"}, {"1: a 2048-bit RSA key"}, {"1: a 2048-bit RSA key", "1: a signature with SHA-384"}},
	}, {
		name:  "RSA-1024",
		chain: []*x509.Certificate{withRSAKey(t, leaf("leaf", p256), 1024)},
		weak:  [5][]string{nil, {"1: a 1024-bit RSA key"}, {"1: a 1024-bit RSA key"}, {"1: a 1024-bit RSA key"}, {"1: a 1024-bit RSA key", "1: a signature with SHA-384"}},
	}, {
		// OpenSSL gives an RSA key of an unusual size more than its
		// threshold: the check is stricter, never laxer.
		name:  "RSA-3000",
		chain: []*x509.Certificate{withRSAKey(t, leaf("leaf", p256), 3000)},
		weak:  [5][]string{nil, nil, {"1: a 3000-bit RSA key"}, {"1: a 3000-bit RSA key"}, {"1: a 3000-bit RSA key", "1: a signature with SHA-384"}},
	}, {
		name:  "RSA-3072, RSA-4096, RSA-7680 and RSA-15360",
		chain: []*x509.Certificate{withRSAKey(t, leaf("a", p256), 3072), withRSAKey(t, leaf("b", p256), 4096), withRSAKey(t, leaf("c", p256), 7680), withRSAKey(t, leaf("d", p256), 15360)},
		weak: [5][]string{nil, nil, nil, {"1: a 3072-bit RSA key", "2: a 4096-bit RSA key"}, {
			"1: a 3072-bit RSA key", "1: a signature with SHA-384", "2: a 4096-bit RSA key", "2: a signature with SHA-384",
			"3: a 7680-bit RSA key", "3: a signature with SHA-384", "4: a signature with SHA-384",
		}},
	}, {
		name:  "an RSA-2048 intermediate",
		chain: []*x509.Certificate{leaf("leaf", p256), withRSAKey(t, leaf("intermediate", p256), 2048), root},
		weak: [5][]string{nil, nil, {"2: a 2048-bit RSA key"}, {"1: a 256-bit EC key (P-256)", "2: a 2048-bit RSA key"}, {
			"1: a 256-bit EC key (P-256)", "1: a signature with SHA-384", "2: a 2048-bit RSA key", "2: a signature with SHA-384",
			"3: a 384-bit EC key (P-384)",
		}},
	}, {
		name:  "Ed25519",
		chain: []*x509.Certificate{leaf("leaf", edKey), chainCertificate(t, "ed", edKey, nil, nil)},
		weak: [5][]string{nil, nil, nil, {"1: an Ed25519 key", "2: an Ed25519 key"}, {
			"1: an Ed25519 key", "1: a signature with SHA-384", "2: an Ed25519 key",
		}},
	}, {
		name:  "signed with Ed25519",
		chain: []*x509.Certificate{chainCertificate(t, "leaf", ecKey(elliptic.P521()), chainCertificate(t, "ed", edKey, nil, nil), edKey)},
		weak:  [5][]string{nil, nil, nil, {"1: a signature with Ed25519"}, {"1: a signature with Ed25519"}},
	}, {
		name:  "Ed448, which Go does not know",
		chain: []*x509.Certificate{signedWith(t, withEd448Key(t, leaf("leaf", p256)), oidEd448), withEd448Key(t, signedWith(t, root, oidEd448))},
		weak:  [5][]string{nil, nil, nil, nil, {"1: an Ed448 key", "1: a signature with Ed448", "2: an Ed448 key"}},
	}, {
		name:  "signed with SHA-1 and MD5",
		chain: []*x509.Certificate{signedWith(t, leaf("leaf", p256), oidECDSAWithSHA1), signedWith(t, withRSAKey(t, leaf("intermediate", p256), 4096), oidMD5WithRSA)},
		weak: [5][]string{
			{"1: a signature with SHA-1", "2: a signature with MD5"},
			{"1: a signature with SHA-1", "2: a signature with MD5"},
			{"1: a signature with SHA-1", "2: a signature with MD5"},
			{"1: a 256-bit EC key (P-256)", "1: a signature with SHA-1", "2: a 4096-bit RSA key", "2: a signature with MD5"},
			{"1: a 256-bit EC key (P-256)", "1: a signature with SHA-1", "2: a 4096-bit RSA key", "2: a signature with MD5"},
		},
	}, {
		name:  "signed with SHA-224, which Go does not know",
		chain: []*x509.Certificate{signedWith(t, leaf("leaf", ecKey(elliptic.P521())), oidECDSAWithSHA224), signedWith(t, withRSAKey(t, leaf("i", p256), 15360), oidSHA224WithRSA)},
		weak:  [5][]string{nil, nil, {"1: a signature with SHA-224", "2: a signature with SHA-224"}, {"1: a signature with SHA-224", "2: a signature with SHA-224"}, {"1: a signature with SHA-224", "2: a signature with SHA-224"}},
	}, {
		// OpenSSL does not check the signature of a self-signed
		// certificate, such as a root, but its key.
		name:  "a self-signed root signed with SHA-1",
		chain: []*x509.Certificate{signedWith(t, root, oidECDSAWithSHA1), signedWith(t, withRSAKey(t, root, 2048), oidSHA1WithRSA)},
		weak: [5][]string{nil, nil, {"2: a 2048-bit RSA key"}, {"2: a 2048-bit RSA key"}, {
			"1: a 384-bit EC key (P-384)", "2: a 2048-bit RSA key",
		}},
	}, {
		// A certificate that names itself as its issuer but is signed with
		// another kind of key is no self-signed one for OpenSSL.
		name:  "self-issued, signed with another kind of key",
		chain: []*x509.Certificate{signedWith(t, root, oidSHA1WithRSA)},
		weak:  [5][]string{{"1: a signature with SHA-1"}, {"1: a signature with SHA-1"}, {"1: a signature with SHA-1"}, {"1: a signature with SHA-1"}, {"1: a 384-bit EC key (P-384)", "1: a signature with SHA-1"}},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CheckChainSecurityLevel(tc.chain, 0); got != nil {
				t.Errorf("level 0: %v", got)
			}
			for level := 1; level <= MaxSecurityLevel; level++ {
				var got []string
				for _, w := range CheckChainSecurityLevel(tc.chain, level) {
					got = append(got, strings.TrimPrefix(w.String(), "certificate ")[:1]+": "+w.Weakness)
					if !strings.HasPrefix(w.String(), "certificate ") || !strings.Contains(w.String(), "of the chain (CN=") {
						t.Errorf("level %d: %q", level, w)
					}
				}
				if !slices.Equal(got, tc.weak[level-1]) {
					t.Errorf("level %d: %q, want %q", level, got, tc.weak[level-1])
				}
			}
		})
	}
}
