package pbsclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// OpenSSL refuses a certificate whose key or signature offers fewer bits of
// security than its security level asks for, and PBS's proxy loads its
// certificate chain under the level its cipher lists set: `@SECLEVEL=N` in
// ciphers-tls-1.2 of node.cfg, Debian's 2 otherwise. TlsAcceptorBuilder
// (proxmox-rest-server/src/connection.rs, proxmox 601a11e6) sets the cipher
// lists before it loads proxy.pem with set_certificate_chain_file, and a
// chain OpenSSL refuses keeps the proxy from starting.
//
// What OpenSSL 3 asks for, as SSL_CTX_set_security_level(3) documents it:
// levels 1 to 5 ask for 80, 112, 128, 192 and 256 bits, which RSA keys of
// 1024, 2048, 3072, 7680 and 15360 bits and EC keys of 160, 224, 256, 384
// and 512 bits offer; SHA-1 and MD5 signatures fall short from level 1.
// Every certificate of the chain is checked — its key, and its signature
// unless it is self-signed, as a root is. An Ed25519 key or signature
// offers 128 bits, an Ed448 one 224, and a signature by a SHA-2 digest half
// the digest's size; OpenSSL counts SHA-1 as 63 bits and MD5 as 39.
//
// OpenSSL estimates the strength of an RSA key of any size with a formula
// (SP 800-56B); CheckChainSecurityLevel goes by the sizes above, which can
// refuse a key of an unusual size, such as 3000 bits, that OpenSSL takes at
// level 3, but never takes one that OpenSSL refuses. Keys and signatures of
// a kind it does not know are not checked.

// securityLevelBits are the bits of security OpenSSL asks for at levels 1
// to 5.
var securityLevelBits = [...]int{1: 80, 2: 112, 3: 128, 4: 192, 5: 256}

// MaxSecurityLevel is the highest security level OpenSSL knows.
// SSL_CTX_set_security_level treats a higher one as this, but a cipher list
// cannot set one: its @SECLEVEL takes a single digit from 0 to this, and
// OpenSSL refuses the list otherwise (CipherListSecurityLevel).
const MaxSecurityLevel = 5

// SecurityLevelBits returns the bits of security OpenSSL asks keys and
// signatures for at a security level: none at level 0.
func SecurityLevelBits(level int) int {
	switch {
	case level <= 0:
		return 0
	case level > MaxSecurityLevel:
		level = MaxSecurityLevel
	}
	return securityLevelBits[level]
}

// SecurityLevelRequirement says, in words, what a certificate chain needs at
// a security level, such as "112 bits of security: RSA keys of 2048 bits or
// more, EC keys of 224 bits or more, and no SHA-1 or MD5 signatures".
func SecurityLevelRequirement(level int) string {
	switch {
	case level <= 0:
		return "nothing"
	case level > MaxSecurityLevel:
		level = MaxSecurityLevel
	}
	requirement := [...]string{
		1: "RSA keys of 1024 bits or more, EC keys of 160 bits or more, and no SHA-1 or MD5 signatures",
		2: "RSA keys of 2048 bits or more, EC keys of 224 bits or more, and no SHA-1 or MD5 signatures",
		3: "RSA keys of 3072 bits or more, EC keys of 256 bits or more, and signatures with SHA-256 or a stronger digest",
		4: "RSA keys of 7680 bits or more, EC keys of 384 bits or more — not Ed25519 —, and signatures with SHA-384 or " +
			"a stronger digest",
		5: "RSA keys of 15360 bits or more, EC keys of 512 bits or more — not Ed25519 nor Ed448 —, and signatures with " +
			"SHA-512",
	}[level]
	return fmt.Sprintf("%d bits of security: %s", securityLevelBits[level], requirement)
}

// CipherListSecurityLevel reads the security level an OpenSSL cipher list
// for TLS 1.2 sets, as SSL_CTX_set_cipher_list does (ssl_cipher_process_rulestr
// in ssl/ssl_ciph.c): every `@SECLEVEL=N` sets it, so the last one counts.
// command is that one, such as "@SECLEVEL=3"; when the list sets no level,
// level is -1 and command empty. A list for TLS 1.3 sets none: OpenSSL takes
// it as names of cipher suites only, and skips @SECLEVEL there as a name it
// does not know.
//
// OpenSSL reads an @ command at the start of an item, which ':', ' ', ','
// or ';' separate, or straight after a cipher name, up to the first
// character that cannot be part of a name, and ignores the rest of the item
// after it. It knows two commands, @STRENGTH and @SECLEVEL= followed by one
// digit from 0 to 5, in upper case, and refuses the whole list for any other,
// such as "@SECLEVEL=9", "@SECLEVEL=03" or "@seclevel=3", for an @ that
// follows the operators '!', '-' or '+', and for one of those operators at
// the start of an item that no name follows, as in "HIGH:!"; the error says
// which. After a cipher name it does not know, OpenSSL ignores the rest of
// the item, an @ command in it included. Which names those are depends on
// the OpenSSL that reads the list, so CipherListSecurityLevel reads every @
// command as one after a known name. The rest of the list, which PBS has
// OpenSSL check before it stores it, it does not check: whether a name
// matches any cipher, above all, depends on that OpenSSL too.
func CipherListSecurityLevel(list string) (level int, command string, err error) {
	level = -1
	for i := 0; i < len(list); {
		op := list[i]
		switch {
		case isCipherItemSeparator(op):
			i++
			continue
		case op == '!' || op == '-' || op == '+' || op == '@':
			i++
		}
		if op == '@' {
			end := cipherNameEnd(list, i)
			switch name := list[i:end]; {
			case name == "STRENGTH":
			case len(name) == len("SECLEVEL=0") && name[:len("SECLEVEL=")] == "SECLEVEL=" &&
				name[len("SECLEVEL=")] >= '0' && name[len("SECLEVEL=")] <= '0'+MaxSecurityLevel:
				level, command = int(name[len("SECLEVEL=")]-'0'), "@"+name
			default:
				return -1, "", fmt.Errorf("OpenSSL refuses the command %q: it knows @STRENGTH and @SECLEVEL=N, N "+
					"being one digit from 0 to %d, in upper case", "@"+name, MaxSecurityLevel)
			}
			i = cipherItemEnd(list, end)
			continue
		}
		// One or more cipher names, joined by '+'; OpenSSL goes on reading
		// the list at the character after them.
		for first := true; ; first = false {
			end := cipherNameEnd(list, i)
			if end == i {
				switch {
				case i < len(list) && list[i] == '@':
					return -1, "", fmt.Errorf("OpenSSL refuses %q: an @ command cannot follow the operator %q",
						list[i-1:cipherNameEnd(list, i+1)], list[i-1])
				case first && (op == '!' || op == '-' || op == '+'):
					// OpenSSL refuses this before it looks any name up, as
					// an "invalid command", so whichever OpenSSL reads the
					// list.
					return -1, "", fmt.Errorf("OpenSSL refuses %q: the operator %q must be followed by a cipher name",
						list[i-1:cipherItemEnd(list, i)], op)
				}
				// A '+' that no name follows: OpenSSL refuses it after a
				// name it knows, and ignores it with the rest of the item
				// after one it does not.
				i = cipherItemEnd(list, i)
				break
			}
			i = end
			if i == len(list) || list[i] != '+' {
				break
			}
			i++
		}
	}
	return level, command, nil
}

// isCipherItemSeparator reports whether OpenSSL separates the items of a
// cipher list with c.
func isCipherItemSeparator(c byte) bool {
	return c == ':' || c == ' ' || c == ',' || c == ';'
}

// cipherNameEnd returns where a cipher name or the name of an @ command
// that starts at i ends: OpenSSL reads letters, digits and "-_.=".
func cipherNameEnd(list string, i int) int {
	for i < len(list) {
		switch c := list[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '=':
			i++
		default:
			return i
		}
	}
	return i
}

// cipherItemEnd returns where the item of a cipher list that i is in ends:
// at the next separator.
func cipherItemEnd(list string, i int) int {
	for i < len(list) && !isCipherItemSeparator(list[i]) {
		i++
	}
	return i
}

// WeakCertificate is a certificate of a chain whose key or signature falls
// short of a security level.
type WeakCertificate struct {
	// Position is the certificate's place in the chain, from 1, the leaf
	// first.
	Position int
	// Subject is the certificate's subject.
	Subject string
	// Weakness says what falls short, such as "a 2048-bit RSA key" or "a
	// signature with SHA-1".
	Weakness string
}

func (w WeakCertificate) String() string {
	return fmt.Sprintf("certificate %d of the chain (%s) has %s", w.Position, w.Subject, w.Weakness)
}

// CheckChainSecurityLevel returns the certificates of chain, the leaf
// first, that OpenSSL refuses at a security level, and why; none when it
// takes them all.
func CheckChainSecurityLevel(chain []*x509.Certificate, level int) []WeakCertificate {
	least := SecurityLevelBits(level)
	if least == 0 {
		return nil
	}
	var weak []WeakCertificate
	for i, cert := range chain {
		if kind, bits, known := keySecurityBits(cert); known && bits < least {
			weak = append(weak, WeakCertificate{Position: i + 1, Subject: cert.Subject.String(), Weakness: kind})
		}
		if selfSigned(cert) {
			continue
		}
		if digest, bits, known := signatureSecurityBits(cert); known && bits < least {
			weak = append(weak, WeakCertificate{Position: i + 1, Subject: cert.Subject.String(), Weakness: "a signature with " + digest})
		}
	}
	return weak
}

// Object identifiers Go's x509 does not know.
var (
	oidEd448           = asn1.ObjectIdentifier{1, 3, 101, 113}
	oidSHA224WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
	oidECDSAWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	oidDSAWithSHA224   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 1}
	oidUnparsed        = asn1.ObjectIdentifier{}
)

// keySecurityBits describes a certificate's key and the bits of security
// OpenSSL gives it. known is false for a kind of key it does not know.
func keySecurityBits(cert *x509.Certificate) (kind string, bits int, known bool) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		size := key.N.BitLen()
		return fmt.Sprintf("a %d-bit RSA key", size), rsaSecurityBits(size), true
	case *ecdsa.PublicKey:
		// OpenSSL goes by the bits of the curve's order.
		params := key.Params()
		order := params.N.BitLen()
		return fmt.Sprintf("a %d-bit EC key (%s)", order, params.Name), ecSecurityBits(order), true
	case ed25519.PublicKey:
		return "an Ed25519 key", 128, true
	}
	if publicKeyAlgorithm(cert).Equal(oidEd448) {
		return "an Ed448 key", 224, true
	}
	return "", 0, false
}

// rsaSecurityBits is the strength of an RSA key of a size, at most what
// OpenSSL gives it.
func rsaSecurityBits(size int) int {
	switch {
	case size >= 15360:
		return 256
	case size >= 7680:
		return 192
	case size >= 3072:
		return 128
	case size >= 2048:
		return 112
	case size >= 1024:
		return 80
	}
	return 0
}

// ecSecurityBits is the strength OpenSSL gives an EC key whose curve's
// order has that many bits.
func ecSecurityBits(order int) int {
	switch {
	case order >= 512:
		return 256
	case order >= 384:
		return 192
	case order >= 256:
		return 128
	case order >= 224:
		return 112
	case order >= 160:
		return 80
	}
	return order / 2
}

// signatureSecurityBits names the digest of a certificate's signature and
// the bits of security OpenSSL gives the signature. known is false for a
// signature it does not know.
func signatureSecurityBits(cert *x509.Certificate) (digest string, bits int, known bool) {
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA:
		// OpenSSL 3 cannot tell the strength of MD2, and refuses it at
		// every level.
		return "MD2", 0, true
	case x509.MD5WithRSA:
		return "MD5", 39, true
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA-1", 63, true
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		return "SHA-256", 128, true
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return "SHA-384", 192, true
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return "SHA-512", 256, true
	case x509.PureEd25519:
		return "Ed25519", 128, true
	}
	switch oid := signatureAlgorithm(cert); {
	case oid.Equal(oidEd448):
		return "Ed448", 224, true
	case oid.Equal(oidSHA224WithRSA), oid.Equal(oidECDSAWithSHA224), oid.Equal(oidDSAWithSHA224):
		return "SHA-224", 112, true
	}
	return "", 0, false
}

// selfSigned reports whether OpenSSL takes a certificate as self-signed,
// and does not check its signature then: it names itself as its issuer,
// its authority key identifier, if any, is its own subject key identifier,
// and it is signed with the kind of key it holds. OpenSSL does not verify
// the signature for that, and neither does this.
func selfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	if len(cert.AuthorityKeyId) > 0 && len(cert.SubjectKeyId) > 0 && !bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
		return false
	}
	return signedWithOwnKind(cert)
}

// signedWithOwnKind reports whether a certificate's signature is of the
// kind its own key makes.
func signedWithOwnKind(cert *x509.Certificate) bool {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		switch cert.SignatureAlgorithm {
		case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA,
			x509.SHA512WithRSA, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			return true
		}
		return signatureAlgorithm(cert).Equal(oidSHA224WithRSA)
	case x509.ECDSA:
		switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			return true
		}
		return signatureAlgorithm(cert).Equal(oidECDSAWithSHA224)
	case x509.Ed25519:
		return cert.SignatureAlgorithm == x509.PureEd25519
	case x509.DSA:
		switch cert.SignatureAlgorithm {
		case x509.DSAWithSHA1, x509.DSAWithSHA256:
			return true
		}
		return signatureAlgorithm(cert).Equal(oidDSAWithSHA224)
	}
	return publicKeyAlgorithm(cert).Equal(oidEd448) && signatureAlgorithm(cert).Equal(oidEd448)
}

// signatureAlgorithm is the object identifier of a certificate's signature
// algorithm, read from its DER; empty when it does not parse.
func signatureAlgorithm(cert *x509.Certificate) asn1.ObjectIdentifier {
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		return oidUnparsed
	}
	return outer.Algorithm.Algorithm
}

// publicKeyAlgorithm is the object identifier of the algorithm of a
// certificate's key; empty when it does not parse.
func publicKeyAlgorithm(cert *x509.Certificate) asn1.ObjectIdentifier {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		return oidUnparsed
	}
	return info.Algorithm.Algorithm
}
