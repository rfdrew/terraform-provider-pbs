package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeACME keeps ACME accounts and plugins, the node's ACME settings and
// the proxy's certificate in memory and serves PBS's API for them through a
// fakePBS, with the behaviour of PBS 4.2's source (see
// internal/pbsclient/acme.go and certificates.go):
//
//   - registering, updating and deactivating an account answer a UPID, and
//     the task does the work when it is first polled; "account 'x' already
//     exists" and an External Account Binding given half are refused at
//     once, a missing account fails the task. A CA that returns contacts, as
//     Pebble does, is the default; caForgets makes it one that does not, as
//     Let's Encrypt;
//   - the CA checks an External Account Binding as Pebble does, against the
//     keys in eabKeys, after PBS decoded the key as PBS does; eabRequired
//     makes it require one. It echoes the binding at registration, unless
//     eabNotEchoed, and drops it on the next update of the account, as
//     Pebble does;
//   - refuseDeactivation makes the CA refuse to deactivate accounts: the
//     task fails with the CA's answer, or, with force, logs it as a warning,
//     ends "WARNINGS: 1" and deactivates the account all the same. Only
//     such tasks have a log, which GET .../log serves. saveFailure makes
//     the task fail where PBS saves the answer of a CA that accepted, force
//     or not, as PBS 4.1.2 and later do: PBS keeps the account, deactivated
//     at the CA, with the status it had. renameFailure makes the task fail
//     after the CA's answer, force or not, where PBS renames the account's
//     file: PBS keeps the account, deactivated at the CA when the CA
//     accepted;
//   - plugins carry the digest of plugins.cfg; the built-in standalone
//     plugin always exists, cannot be created or updated, and deleting it
//     changes nothing; data is taken base64-encoded and returned decoded;
//   - the node's configuration keeps every property as sent, with a digest,
//     refuses a stale digest, deletes before it sets, and refuses the same
//     ACME domain twice; it holds a description too, which the ACME
//     resources must leave alone;
//   - ordering answers a UPID; the task orders nothing for a node without
//     domains, fails for a missing account or plugin, and otherwise installs
//     a certificate a fake CA issued for the domains, lower-cased. Deleting
//     the custom certificate installs a new self-signed one at once;
//   - the account list answers the names only, in reverse name order: PBS
//     answers in the order of the directory it keeps the accounts in, and
//     the data source must sort. Deactivated accounts are not listed, as
//     PBS leaves them out;
//   - the directories are the two PBS has built in, production first, and
//     the challenge schema is challengeSchema, by default a subset of what
//     PBS 4.2 serves from libproxmox-acme-plugins' schema file.
//
// Tests set up state with addAccount, addPlugin and setNodeProperty, renew
// the certificate as PBS does on its own with renew, and look at state with
// account, plugin, nodeProperty and certificate.
type fakeACME struct {
	fake *fakePBS
	t    *testing.T

	mu         sync.Mutex
	accounts   map[string]fakeProperties
	accountGen int
	// deactivated are the accounts deactivated, in order.
	deactivated []string
	// caForgets makes the CA return no contacts, as Let's Encrypt does.
	caForgets bool
	// registerFailures make the next registration tasks fail with their
	// text, one each. orderFailure makes the next order task fail with its
	// text; orderFailureAfterInstall makes it fail after it installed the
	// certificate, orderNothing end it without one, as for a node whose
	// domains went away.
	registerFailures         []string
	orderFailure             string
	orderFailureAfterInstall string
	orderNothing             bool
	// eabKeys are the External Account Binding keys the CA knows, by key
	// identifier.
	eabKeys      map[string][]byte
	eabRequired  bool
	eabNotEchoed bool
	// refuseDeactivation is the CA's answer to deactivating an account,
	// such as fakeAccountGone; empty for none. saveFailure is the error of
	// saving the answer of a CA that accepted, such as "write failed: No
	// space left on device", and renameFailure the error of renaming the
	// account's file after the CA's answer, such as fakeNoFreeSlot.
	refuseDeactivation string
	saveFailure        string
	renameFailure      string

	plugins   map[string]fakeProperties
	pluginGen int
	// challengeSchema is the data GET /config/acme/challenge-schema answers,
	// as JSON; tests may replace it.
	challengeSchema string

	node       map[string]string
	nodeGen    int
	staleNodes int

	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	cert  pbsclient.CertificateInfo

	tasks   map[string]func() string
	taskGen int
	// taskLogs are the log lines of the tasks that have a log, by UPID.
	taskLogs map[string][]string
}

// fakeACMETaskNode is the node name the ACME fake's UPIDs carry, apart from
// the datastore fake's.
const fakeACMETaskNode = "pbs-acme"

// fakeToS are the terms of service of the directories the fake knows.
var fakeToS = map[string]string{
	pbsclient.DefaultACMEDirectory:  "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf",
	pbsclient.ACMEStagingDirectory:  "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf",
	"https://pebble.test:14000/dir": "data:text/plain,Do%20what%20thou%20wilt",
}

// The properties of each kind of entry that are not strings, and what
// updates may delete.
var (
	fakePluginInts       = []string{"validation-delay"}
	fakePluginBools      = []string{"disable"}
	fakePluginDeletable  = []string{"disable", "validation-delay"}
	fakeNodeDeletable    = []string{"acme", "acmedomain0", "acmedomain1", "acmedomain2", "acmedomain3", "acmedomain4", "http-proxy", "email-from", "ciphers-tls-1.3", "ciphers-tls-1.2", "default-lang", "description", "task-log-max-days", "consent-text", "location"}
	fakeNodeDescription  = "PBS for cluster1\n"
	fakeSelfSignedIssuer = "O = Proxmox Backup Server, OU = 9C5A9B5E2A1D4C0FB4E3A1F25E9C0D77, CN = pbs-test"
)

// newFakeACME serves the ACME, node configuration and certificate API from
// fake, for node localhost.
func newFakeACME(t *testing.T, fake *fakePBS) *fakeACME {
	t.Helper()
	a := &fakeACME{
		fake:     fake,
		t:        t,
		accounts: map[string]fakeProperties{},
		plugins:  map[string]fakeProperties{},
		node:     map[string]string{"description": fakeNodeDescription},
		tasks:    map[string]func() string{},
		taskLogs: map[string][]string{},
		eabKeys:  map[string][]byte{},

		challengeSchema: fakeChallengeSchema,
	}
	a.caKey, a.ca = fakeCertificate(t, "Fake ACME CA", nil, nil)
	a.cert = a.selfSignedLocked()

	fake.handle("GET /config/acme/account", a.listAccounts)
	fake.handle("POST /config/acme/account", a.registerAccount)
	fake.handle("GET /config/acme/tos", a.tos)
	fake.handle("GET /config/acme/directories", a.directories)
	fake.handle("GET /config/acme/challenge-schema", a.challengeSchemas)
	fake.handle("POST /config/acme/plugins", a.createPlugin)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/acme/account/", a.serveAccount)
		fake.handlePrefix(method+" /config/acme/plugins/", a.servePlugin)
	}
	fake.handle("GET /nodes/localhost/config", a.getNode)
	fake.handle("PUT /nodes/localhost/config", a.updateNode)
	fake.handle("GET /nodes/localhost/certificates/info", a.certificateInfo)
	fake.handle("POST /nodes/localhost/certificates/acme/certificate", a.order)
	fake.handle("DELETE /nodes/localhost/certificates/custom", a.deleteCustom)
	fake.handlePrefix("GET /nodes/"+fakeACMETaskNode+"/tasks/", a.taskStatus)
	return a
}

// fakeCertificate creates a certificate for cn, signed by parent with
// parentKey, or self-signed when parent is nil.
func fakeCertificate(t *testing.T, cn string, dnsNames []string, parent *x509.Certificate, parentKey ...*ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		// Fixed dates, which tests assert, valid long enough that tests
		// checking a chain against the clock, as CertificateProblems does,
		// keep passing: 90 days, as Let's Encrypt's, would have run out on
		// 2026-12-20.
		NotBefore:             time.Unix(1790000000, 0),
		NotAfter:              time.Unix(1790000000+10*365*24*3600, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  parent == nil,
		DNSNames:              dnsNames,
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent, parentKey[0]
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// certificateInfo describes cert as PBS does, the chain after it.
func certificateInfo(cert *x509.Certificate, chain ...*x509.Certificate) pbsclient.CertificateInfo {
	sum := sha256.Sum256(cert.Raw)
	var pemText strings.Builder
	for _, c := range append([]*x509.Certificate{cert}, chain...) {
		_ = pem.Encode(&pemText, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return pbsclient.CertificateInfo{
		Filename:      pbsclient.ProxyCertificateFile,
		Fingerprint:   pbsclient.FormatFingerprint(hex.EncodeToString(sum[:])),
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore.Unix(),
		NotAfter:      cert.NotAfter.Unix(),
		SAN:           cert.DNSNames,
		PEM:           pemText.String(),
		PublicKeyType: "id-ecPublicKey",
		PublicKeyBits: 256,
	}
}

func (a *fakeACME) selfSignedLocked() pbsclient.CertificateInfo {
	_, cert := fakeCertificate(a.t, "pbs-test", nil, nil)
	info := certificateInfo(cert)
	// PBS's own certificate names the host and PBS, in subject and issuer
	// alike.
	info.Subject, info.Issuer = fakeSelfSignedIssuer, fakeSelfSignedIssuer
	return info
}

func (a *fakeACME) issueLocked(domains []string) pbsclient.CertificateInfo {
	_, cert := fakeCertificate(a.t, domains[0], domains, a.ca, a.caKey)
	return certificateInfo(cert, a.ca)
}

// --- test helpers -------------------------------------------------------------

func (a *fakeACME) addAccount(name string, props fakeProperties) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accounts[name] = cloneProperties(props)
}

func (a *fakeACME) account(name string) (fakeProperties, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	props, ok := a.accounts[name]
	return cloneProperties(props), ok
}

func (a *fakeACME) addPlugin(id string, props fakeProperties) {
	a.mu.Lock()
	defer a.mu.Unlock()
	props = cloneProperties(props)
	props["type"] = pbsclient.DNSACMEPluginType
	a.plugins[id] = props
	a.pluginGen++
}

func (a *fakeACME) plugin(id string) (fakeProperties, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	props, ok := a.plugins[id]
	return cloneProperties(props), ok
}

// setNodeProperty changes the node's configuration as another client would;
// "" removes the property.
func (a *fakeACME) setNodeProperty(key, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if value == "" {
		delete(a.node, key)
	} else {
		a.node[key] = value
	}
	a.nodeGen++
}

func (a *fakeACME) nodeProperty(key string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	value, ok := a.node[key]
	return value, ok
}

func (a *fakeACME) certificate() pbsclient.CertificateInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cert
}

// renew installs a new certificate for the same names, as PBS's daily
// renewal does.
func (a *fakeACME) renew() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cert = a.issueLocked(a.cert.SAN)
}

// install installs a certificate the fake CA issued for domains, as an
// order made outside Terraform does.
func (a *fakeACME) install(domains ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cert = a.issueLocked(domains)
}

// --- serving ------------------------------------------------------------------

func (a *fakeACME) startTaskLocked(workerType, workerID string, run func() string) string {
	a.taskGen++
	upid := fmt.Sprintf("UPID:%s:00000002:00000002:%08X:6AE11CDF:%s:%s:%s:", fakeACMETaskNode, a.taskGen, workerType, workerID, fakeTokenID)
	a.tasks[upid] = run
	return upid
}

func (a *fakeACME) taskStatus(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/nodes/"+fakeACMETaskNode+"/tasks/")
	if upid, ok := strings.CutSuffix(rest, "/log"); ok {
		a.taskLog(w, req, upid)
		return
	}
	upid, ok := strings.CutSuffix(rest, "/status")
	if !ok {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exit := "unknown"
	if run, ok := a.tasks[upid]; ok {
		exit = run()
		delete(a.tasks, upid)
	}
	writeData(w, map[string]any{"status": "stopped", "exitstatus": exit, "upid": upid}, "")
}

// taskLog serves the log of a task that has one, as PBS does: the lines from
// start on, at most limit of them (all with 0), each with its number and a
// timestamp, and total next to data. Other tasks' logs are not found, as
// the tests of the other ACME tasks expect.
func (a *fakeACME) taskLog(w http.ResponseWriter, req *http.Request, upid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	lines, ok := a.taskLogs[upid]
	if !ok {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	start, _ := strconv.Atoi(req.URL.Query().Get("start"))
	limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
	data := []map[string]any{}
	for i, line := range lines {
		if i+1 < start || (limit > 0 && len(data) == limit) {
			continue
		}
		data = append(data, map[string]any{"n": i + 1, "t": "2026-11-14T10:00:00+01:00: " + line})
	}
	body, _ := json.Marshal(map[string]any{"data": data, "total": len(lines), "active": false})
	writeFakeResponse(w, http.StatusOK, string(body))
}

// contactsLocked turns contact into the CA's contacts the way PBS does:
// split at spaces, semicolons, commas and NULs, empty parts kept, each one
// a mailto: URL. An empty one fails, as Pebble and Let's Encrypt refuse it.
func (a *fakeACME) contactsLocked(contact string) ([]string, string) {
	var contacts []string
	for _, part := range splitLikePBS(contact) {
		if part == "" {
			return nil, "Error: invalidContact: empty contact email"
		}
		contacts = append(contacts, "mailto:"+part)
	}
	if a.caForgets {
		return nil, ""
	}
	return contacts, ""
}

// splitLikePBS splits at every space, semicolon, comma and NUL, keeping the
// empty parts, as Rust's str::split does.
func splitLikePBS(s string) []string {
	parts := []string{""}
	for _, r := range s {
		if r == ' ' || r == ';' || r == ',' || r == 0 {
			parts = append(parts, "")
			continue
		}
		parts[len(parts)-1] += string(r)
	}
	return parts
}

func (a *fakeACME) accountJSON(props fakeProperties) map[string]any {
	account := map[string]any{"status": props["status"]}
	if contacts, ok := props["contact"].([]string); ok && len(contacts) > 0 {
		account["contact"] = contacts
	}
	if kid, ok := props["eab_kid"].(string); ok && kid != "" {
		account["externalAccountBinding"] = fakeEABEcho(kid)
	}
	out := map[string]any{"directory": props["directory"], "location": props["location"], "account": account}
	if tos, ok := props["tos"].(string); ok && tos != "" {
		out["tos"] = tos
	}
	return out
}

// fakeEABEcho is an External Account Binding as Pebble echoes it in the
// account object: a JWS whose protected header names the key identifier.
func fakeEABEcho(kid string) map[string]any {
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": kid, "url": "https://ca.test/acme/new-acct"})
	return map[string]any{
		"protected": base64.RawURLEncoding.EncodeToString(header),
		"payload":   base64.RawURLEncoding.EncodeToString([]byte(`{"kty":"EC"}`)),
		"signature": base64.RawURLEncoding.EncodeToString([]byte("signature")),
	}
}

// The CA's answers to an External Account Binding, as Pebble 2.10.1 gives
// them (wfe/wfe.go, verifyEAB) and PBS prints a CA's problem: "<type>:
// <detail>". The text after Pebble's "verification error: " is go-jose's.
const (
	fakeEABRequired   = "urn:ietf:params:acme:error:externalAccountRequired: ACME server policy requires newAccount requests must include a value for the 'externalAccountBinding' field"
	fakeEABUnknownKid = "urn:ietf:params:acme:error:unauthorized: the field 'kid' references a key that is not known to the ACME server"
	fakeEABBadMAC     = "urn:ietf:params:acme:error:unauthorized: external account binding JWS verification error: go-jose/go-jose: error in cryptographic primitive"
)

// fakeNoFreeSlot is how PBS fails to deactivate an account whose file it
// cannot rename, all of _deactivated_<name>_0 to _99 being taken
// (proxmox-acme-api's account_config.rs, mark_account_deactivated).
func fakeNoFreeSlot(name string) string {
	return fmt.Sprintf(`No free slot to rename deactivated account "/etc/proxmox-backup/acme/accounts/%s", please cleanup "/etc/proxmox-backup/acme/accounts"`, name)
}

// The errors PBS fails a registration with when it cannot decode the
// binding's key: proxmox-base64's DecodeError, which hides the base64
// crate's message (proxmox-base64/src/error.rs).
const (
	fakeBase64Padding = "invalid padding in base64 encoded data"
	fakeBase64Other   = "error decoding base64 data"
)

// decodeEABKeyLikePBS decodes an External Account Binding's HMAC key as
// PBS does: standard base64, padding optional, for a key holding "+" or
// "/", base64url without padding otherwise, with proxmox-base64's errors.
func decodeEABKeyLikePBS(key string) ([]byte, string) {
	if strings.ContainsAny(key, "+/") {
		raw, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimRight(key, "="))
		if err != nil || strings.ContainsAny(key, "\r\n") {
			return nil, fakeBase64Other
		}
		return raw, ""
	}
	if strings.HasSuffix(key, "=") {
		return nil, fakeBase64Padding
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(key)
	if err != nil || strings.ContainsAny(key, "\r\n") {
		return nil, fakeBase64Other
	}
	return raw, ""
}

// eabFailureLocked is how the CA, through PBS, answers the binding of a
// registration: "" when it accepts it.
func (a *fakeACME) eabFailureLocked(kid, key string) string {
	if kid == "" {
		if a.eabRequired {
			return fakeEABRequired
		}
		return ""
	}
	raw, failure := decodeEABKeyLikePBS(key)
	if failure != "" {
		return failure
	}
	known, ok := a.eabKeys[kid]
	switch {
	case !ok:
		return fakeEABUnknownKid
	case string(known) != string(raw):
		return fakeEABBadMAC
	}
	return ""
}

func (a *fakeACME) registerAccount(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "contact") {
		return
	}
	if params.Has("eab_kid") != params.Has("eab_hmac_key") {
		writeError(w, "either both or none of 'eab_kid' and 'eab_hmac_key' have to be set.")
		return
	}
	name := params.Get("name")
	if name == "" {
		name = "default"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.accounts[name]; exists {
		writeError(w, "account %s already exists", name)
		return
	}
	directory := params.Get("directory")
	if directory == "" {
		directory = pbsclient.DefaultACMEDirectory
	}
	upid := a.startTaskLocked("acme-register", name, func() string {
		if len(a.registerFailures) > 0 {
			failure := a.registerFailures[0]
			a.registerFailures = a.registerFailures[1:]
			return failure
		}
		contacts, failure := a.contactsLocked(params.Get("contact"))
		if failure != "" {
			return failure
		}
		if failure := a.eabFailureLocked(params.Get("eab_kid"), params.Get("eab_hmac_key")); failure != "" {
			return failure
		}
		a.accountGen++
		a.accounts[name] = fakeProperties{
			"directory": directory,
			"location":  fmt.Sprintf("https://ca.test/acme/acct/%d", a.accountGen),
			"tos":       params.Get("tos_url"),
			"contact":   contacts,
			"status":    "valid",
		}
		if !a.eabNotEchoed && params.Get("eab_kid") != "" {
			a.accounts[name]["eab_kid"] = params.Get("eab_kid")
		}
		return "OK"
	})
	writeData(w, upid, "")
}

func (a *fakeACME) serveAccount(w http.ResponseWriter, req *http.Request) {
	name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/acme/account/")
	params := form(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	missing := fmt.Sprintf("acme account '%s' does not exist", name)
	switch req.Method {
	case http.MethodGet:
		props, ok := a.accounts[name]
		if !ok {
			writeError(w, "%s", missing)
			return
		}
		writeData(w, a.accountJSON(props), "")
	case http.MethodPut:
		upid := a.startTaskLocked("acme-update", name, func() string {
			props, ok := a.accounts[name]
			if !ok {
				return missing
			}
			if params.Has("contact") {
				contacts, failure := a.contactsLocked(params.Get("contact"))
				if failure != "" {
					return failure
				}
				if !a.caForgets {
					props["contact"] = contacts
				}
			}
			// The CA's answer replaces the account object PBS keeps, and
			// Pebble leaves the binding out of it.
			delete(props, "eab_kid")
			return "OK"
		})
		writeData(w, upid, "")
	case http.MethodDelete:
		force := fakeBool(params.Get("force"))
		var upid string
		upid = a.startTaskLocked("acme-deactivate", name, func() string {
			if _, ok := a.accounts[name]; !ok {
				return missing
			}
			exit := "OK"
			if refusal := a.refuseDeactivation; refusal != "" {
				if !force {
					return refusal
				}
				a.taskLogs[upid] = []string{
					fmt.Sprintf("error deactivating account %s, proceedeing anyway - %s", name, refusal),
					"TASK WARNINGS: 1",
				}
				exit = "WARNINGS: 1"
			} else {
				// PBS saves the CA's answer before it renames the file.
				if failure := a.saveFailure; failure != "" {
					a.taskLogs[upid] = append(a.taskLogs[upid], "TASK ERROR: "+failure)
					return failure
				}
				a.accounts[name]["status"] = "deactivated"
			}
			if failure := a.renameFailure; failure != "" {
				a.taskLogs[upid] = append(a.taskLogs[upid], "TASK ERROR: "+failure)
				return failure
			}
			delete(a.accounts, name)
			a.deactivated = append(a.deactivated, name)
			return exit
		})
		writeData(w, upid, "")
	}
}

func (a *fakeACME) tos(w http.ResponseWriter, req *http.Request) {
	directory := form(req).Get("directory")
	if directory == "" {
		directory = pbsclient.DefaultACMEDirectory
	}
	tos, ok := fakeToS[directory]
	if !ok {
		writeData(w, nil, "")
		return
	}
	writeData(w, tos, "")
}

// listAccounts serves GET /config/acme/account: an entry with the name of
// each account, in reverse name order. Deactivated accounts are gone from
// accounts, so they are left out as PBS leaves them out.
func (a *fakeACME) listAccounts(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	names := slices.Sorted(maps.Keys(a.accounts))
	slices.Reverse(names)
	entries := []map[string]string{}
	for _, name := range names {
		entries = append(entries, map[string]string{"name": name})
	}
	writeData(w, entries, "")
}

// directories serves GET /config/acme/directories: the directories built
// into PBS, in its order.
func (a *fakeACME) directories(w http.ResponseWriter, _ *http.Request) {
	writeData(w, []map[string]string{
		{"name": "Let's Encrypt V2", "url": pbsclient.DefaultACMEDirectory},
		{"name": "Let's Encrypt V2 Staging", "url": pbsclient.ACMEStagingDirectory},
	}, "")
}

// challengeSchemas serves GET /config/acme/challenge-schema from
// challengeSchema.
func (a *fakeACME) challengeSchemas(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	writeFakeResponse(w, http.StatusOK, `{"data":`+a.challengeSchema+`}`)
}

// fakeChallengeSchema is a subset of what PBS 4.2 answers for
// /config/acme/challenge-schema: an entry per API of the schema file, by id,
// with the name PBS takes from the API's schema, or the id when it has none,
// and the API's schema as the file has it. Most APIs have an empty schema,
// as 1984hosting; Cloudflare's has a description and fields without
// optional; Hetzner Cloud's has optional fields with defaults, one of them
// an integer; AWS's fields have display names.
const fakeChallengeSchema = `[
	{"id": "1984hosting", "name": "1984hosting", "type": "dns", "schema": {}},
	{"id": "aws", "name": "Amazon Route53 (AWS)", "type": "dns", "schema": {
		"name": "Amazon Route53 (AWS)",
		"fields": {
			"AWS_ACCESS_KEY_ID": {"description": "The AWS access-key ID", "name": "ACCESS_KEY_ID", "type": "string"},
			"AWS_SECRET_ACCESS_KEY": {"description": "The AWS access-key secret", "name": "SECRET_ACCESS_KEY", "type": "string"}
		}
	}},
	{"id": "cf", "name": "Cloudflare Managed DNS", "type": "dns", "schema": {
		"name": "Cloudflare Managed DNS",
		"description": "Either provide global account key and email, or CF API token and Account ID.",
		"fields": {
			"CF_Account_ID": {"description": "The Cloudflare Account ID", "type": "string"},
			"CF_Email": {"description": "The Cloudflare Account EMail-Address", "type": "string"},
			"CF_Key": {"description": "The Cloudflare Global API Key", "type": "string"},
			"CF_Token": {"description": "The new Cloudflare API Token", "type": "string"},
			"CF_Zone_ID": {"description": "The Cloudflare Zone ID", "type": "string"}
		}
	}},
	{"id": "hetznercloud", "name": "Hetzner Cloud", "type": "dns", "schema": {
		"name": "Hetzner Cloud",
		"fields": {
			"HETZNER_API": {"default": "https://api.hetzner.cloud/v1", "description": "The Hetzner Cloud API endpoint", "optional": 1, "type": "string"},
			"HETZNER_TTL": {"default": 120, "description": "TTL of the TXT records, in seconds", "optional": 1, "type": "integer"}
		}
	}}
]`

func (a *fakeACME) pluginDigestLocked() string { return fakeDigest("acme/plugins.cfg", a.pluginGen) }

// pluginLocked returns a plugin as a read reports it, the built-in
// standalone one included.
func (a *fakeACME) pluginLocked(id string) (fakeProperties, bool) {
	if id == pbsclient.StandaloneACMEPlugin {
		return fakeProperties{"plugin": id, "type": pbsclient.StandaloneACMEPlugin}, true
	}
	props, ok := a.plugins[id]
	if !ok {
		return nil, false
	}
	props = cloneProperties(props)
	props["plugin"] = id
	return props, true
}

// decodeFakeData decodes data as PBS does, or fails like it.
func decodeFakeData(w http.ResponseWriter, encoded string) (string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		writeError(w, "parameter verification failed - 'data': invalid base64 %s", encoded)
		return "", false
	}
	return string(decoded), true
}

func (a *fakeACME) createPlugin(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "id", "type", "api", "data") {
		return
	}
	id := params.Get("id")
	if params.Get("type") != pbsclient.DNSACMEPluginType {
		writeError(w, "parameter verification failed - 'type': invalid ACME plugin type: %q", params.Get("type"))
		return
	}
	data, ok := decodeFakeData(w, params.Get("data"))
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.pluginLocked(id); exists {
		writeError(w, "parameter verification failed - 'id': ACME plugin ID %q already exists", id)
		return
	}
	props := fakeProperties{"type": pbsclient.DNSACMEPluginType}
	applyFakeForm(props, params, fakePluginInts, fakePluginBools, "id", "type", "data")
	props["data"] = data
	a.plugins[id] = props
	a.pluginGen++
	writeData(w, nil, "")
}

func (a *fakeACME) servePlugin(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/acme/plugins/")
	params := form(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	props, ok := a.pluginLocked(id)
	if !ok {
		writeFakeResponse(w, http.StatusNotFound, "no such plugin")
		return
	}
	switch req.Method {
	case http.MethodGet:
		writeData(w, props, a.pluginDigestLocked())
	case http.MethodPut:
		if staleDigest(params, a.pluginDigestLocked()) {
			writeError(w, "%s", fakeDigestConflict)
			return
		}
		if props["type"] != pbsclient.DNSACMEPluginType {
			writeError(w, "cannot update plugin of type %q", props["type"])
			return
		}
		if !checkDelete(w, params, fakePluginDeletable...) {
			return
		}
		section := a.plugins[id]
		for _, key := range params[pbsclient.DeleteParam] {
			delete(section, key)
		}
		if params.Has("data") {
			data, ok := decodeFakeData(w, params.Get("data"))
			if !ok {
				return
			}
			section["data"] = data
		}
		applyFakeForm(section, params, fakePluginInts, fakePluginBools, "data")
		a.pluginGen++
		writeData(w, nil, "")
	case http.MethodDelete:
		if id != pbsclient.StandaloneACMEPlugin {
			delete(a.plugins, id)
			a.pluginGen++
		}
		writeData(w, nil, "")
	}
}

func (a *fakeACME) nodeDigestLocked() string { return fakeDigest("node.cfg", a.nodeGen) }

func (a *fakeACME) getNode(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	writeData(w, fakeNodeConfigJSON(a.node), a.nodeDigestLocked())
}

func (a *fakeACME) updateNode(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.staleNodes > 0 {
		// Someone else wrote node.cfg just before.
		a.staleNodes--
		a.nodeGen++
	}
	if staleDigest(params, a.nodeDigestLocked()) {
		writeError(w, "%s", fakeDigestConflict)
		return
	}
	if !checkDelete(w, params, fakeNodeDeletable...) {
		return
	}
	updated := map[string]string{}
	for k, v := range a.node {
		updated[k] = v
	}
	for _, key := range params[pbsclient.DeleteParam] {
		delete(updated, key)
	}
	for key, values := range params {
		if key != pbsclient.DeleteParam && key != pbsclient.DigestParam {
			updated[key] = values[0]
		}
	}
	seen := map[string]bool{}
	for i := 0; i < pbsclient.MaxACMEDomains; i++ {
		raw, ok := updated[pbsclient.ACMEDomainProperty(i)]
		if !ok {
			continue
		}
		domain, err := pbsclient.ParseACMEDomain(raw)
		if err != nil {
			writeError(w, "parameter verification failed - 'acmedomain%d': %s", i, err)
			return
		}
		if seen[strings.ToLower(domain.Domain)] {
			writeError(w, "duplicate domain '%s' in ACME config", domain.Domain)
			return
		}
		seen[strings.ToLower(domain.Domain)] = true
	}
	if message := fakeNodeSettingsCheck(updated); message != "" {
		writeError(w, "%s", message)
		return
	}
	a.node = updated
	a.nodeGen++
	writeData(w, nil, "")
}

func (a *fakeACME) certificateInfo(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	writeData(w, []pbsclient.CertificateInfo{a.cert}, "")
}

func (a *fakeACME) order(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	upid := a.startTaskLocked("acme-new-cert", "", func() string {
		var domains []pbsclient.ACMEDomain
		for i := 0; i < pbsclient.MaxACMEDomains; i++ {
			if raw, ok := a.node[pbsclient.ACMEDomainProperty(i)]; ok {
				domain, _ := pbsclient.ParseACMEDomain(raw)
				domains = append(domains, domain)
			}
		}
		if len(domains) == 0 {
			return "OK"
		}
		account, err := pbsclient.NodeConfig{ACME: a.node["acme"]}.ACMEAccountName()
		if err != nil {
			return err.Error()
		}
		if _, ok := a.accounts[account]; !ok {
			return fmt.Sprintf("acme account '%s' does not exist", account)
		}
		var names []string
		for _, domain := range domains {
			plugin := domain.Plugin
			if plugin == "" {
				plugin = pbsclient.StandaloneACMEPlugin
			}
			if _, ok := a.pluginLocked(plugin); !ok {
				return fmt.Sprintf("plugin '%s' for domain '%s' not found!", plugin, domain.Domain)
			}
			names = append(names, strings.ToLower(domain.Domain))
		}
		if failure := a.orderFailure; failure != "" {
			a.orderFailure = ""
			return failure
		}
		if a.orderNothing {
			a.orderNothing = false
			return "OK"
		}
		a.cert = a.issueLocked(names)
		if failure := a.orderFailureAfterInstall; failure != "" {
			a.orderFailureAfterInstall = ""
			return failure
		}
		return "OK"
	})
	writeData(w, upid, "")
}

func (a *fakeACME) deleteCustom(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cert = a.selfSignedLocked()
	writeData(w, nil, "")
}

// fakeACMEDomains lists the node's ACME domain properties by slot, for
// assertions.
func (a *fakeACME) fakeACMEDomains() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var slots []string
	for i := 0; i < pbsclient.MaxACMEDomains; i++ {
		if raw, ok := a.node[pbsclient.ACMEDomainProperty(i)]; ok {
			slots = append(slots, strconv.Itoa(i)+":"+raw)
		}
	}
	slices.Sort(slots)
	return slots
}
