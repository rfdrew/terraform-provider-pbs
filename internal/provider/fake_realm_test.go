package provider

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeRealms keeps the realms of domains.cfg in memory and serves PBS's API
// for them through a fakePBS, with the behaviour read in PBS 4.2's source
// (see internal/pbsclient/realms.go):
//
//   - every realm, of every type, shares one namespace and one digest; pam,
//     the default, and pbs are there from the start, and /access/domains
//     lists them all, in no particular order, as PBS's hash map does;
//   - creating or changing an OpenID realm contacts nothing; reads answer
//     every property, the client key too, and leave out what is unset;
//   - default = true takes the flag from every other realm, and an update
//     that does not send default = true clears the realm's own;
//   - an update's delete accepts only the names PBS accepts, applied before
//     the values; username-claim is create-only and realm cannot change;
//   - a realm of another type answers GET and PUT with "got unexpected
//     type", while DELETE removes it all the same, and checks the digest.
//
// LDAP and Active Directory realms, under /config/access/ldap and
// /config/access/ad, follow the same rules, and besides:
//
//   - POST and PUT accept the parameters PBS's schema has — an Active
//     Directory realm has no user-attr, and needs no base-dn — and refuse the
//     values it refuses of mode, port, user-classes and the two property
//     strings, sync-attributes and sync-defaults-options;
//   - an update accepts capath, but ignores it, and trims comment, an empty
//     one removing it;
//   - before saving anything, POST and PUT check the connection as the realm
//     has it after the change, and answer PBS's 400 when that fails: nothing
//     is saved then, the default flag other realms lose included;
//   - the bind password is kept apart, as PBS keeps it in
//     ldap_passwords.json: reads never return it, a PUT without one binds
//     with the stored one, delete=password removes it at once — before the
//     check, for good, as PBS does — and DELETE removes it with the realm,
//     of either type;
//   - an Active Directory realm without base-dn gets the defaultNamingContext
//     of the server's root DSE, asked for over a connection of its own,
//     anonymously, before the check; "failed to determine base_dn: " goes
//     before a failure there.
//
// The check is proxmox-ldap's check_connection, against the directory servers
// the PBS host reaches, which tests add with addServer: a capath must be a
// file on the PBS host (addCAFile), whatever the mode, as PBS reads it on
// every connection; then PBS connects to server1, or else to server2, on
// port, or by default 389 — 636 with mode ldaps; a server it does not reach,
// or that does not listen on the port, refuses the connection; TLS fails for
// ldaps to a port that speaks plain LDAP, for plain LDAP to one that speaks
// ldaps, and, with TLS and verify, for a certificate signed by a CA other
// than the system's or capath's; with a bind-dn, the bind needs the
// password the server has for it; and a base-scope search must find base-dn
// among the server's entries. The texts are PBS's, those of TLS failures
// OpenSSL's, as examples of their kind.
//
// Tests set up state with addRealm, addServer, addCAFile, setBindPassword
// and setServerPassword, and look at it with realm, defaultRealm and
// bindPassword.
type fakeRealms struct {
	fake *fakePBS

	mu sync.Mutex
	// realms are the sections of domains.cfg: their type, and their
	// properties.
	types  map[string]string
	realms map[string]fakeProperties
	gen    int
	// passwords are the bind passwords of directory realms, by realm.
	passwords map[string]string
	// servers are the directory servers the PBS host reaches, by the host
	// name or address realms give them by, and caFiles the files on the PBS
	// host a capath can name.
	servers map[string]*fakeDirectory
	caFiles map[string]bool
}

// fakeDirectory is an LDAP server, or an Active Directory domain controller,
// as far as PBS's check of a realm sees it.
type fakeDirectory struct {
	// ports are the ports it listens on, with the protocol it speaks there:
	// "ldap", which StartTLS switches to TLS, or "ldaps". nil is 389 for
	// ldap and 636 for ldaps.
	ports map[int64]string
	// ca is the CA file that signed its certificate, which capath must name
	// for verify to pass; "" for a CA the system trusts.
	ca string
	// entries are the DNs a search finds, compared ignoring case.
	entries []string
	// binds are the DNs it lets bind, with their passwords.
	binds map[string]string
	// namingContext is the defaultNamingContext of its root DSE; "" when it
	// has none, as a server other than a domain controller.
	namingContext string
}

// The properties of OpenID realms that are not strings, and what PBS lets
// an update delete.
var (
	fakeOpenIDBools     = []string{"autocreate", "default"}
	fakeOpenIDDeletable = []string{"client-key", "comment", "default", "autocreate", "scopes", "prompt", "acr-values",
		"audiences"}
	// fakeOpenIDCreateParams and fakeOpenIDUpdateParams are what POST and
	// PUT accept; anything else PBS refuses.
	fakeOpenIDCreateParams = []string{"realm", "issuer-url", "client-id", "client-key", "scopes", "acr-values",
		"audiences", "prompt", "comment", "default", "autocreate", "username-claim"}
	fakeOpenIDUpdateParams = []string{"issuer-url", "client-id", "client-key", "scopes", "acr-values", "audiences",
		"prompt", "comment", "default", "autocreate", "delete", "digest"}
)

// The properties of LDAP and Active Directory realms that are not strings,
// and what PBS lets an update delete, the stored password included.
var (
	fakeDirectoryInts      = []string{"port"}
	fakeDirectoryBools     = []string{"verify", "default"}
	fakeDirectoryDeletable = []string{"server2", "port", "comment", "default", "verify", "mode", "bind-dn", "password",
		"filter", "sync-defaults-options", "sync-attributes", "user-classes"}
	// fakeDirectoryProperties are the parameters POST and PUT of either type
	// accept besides realm, user-attr, delete and digest.
	fakeDirectoryProperties = []string{"server1", "server2", "port", "mode", "verify", "capath", "base-dn", "bind-dn",
		"password", "filter", "user-classes", "sync-attributes", "sync-defaults-options", "comment", "default"}
)

// What a directory realm's check fails with.
const (
	fakeConnectionRefused = "I/O error: Connection refused (os error 111): Connection refused (os error 111)"
	fakeConnectionReset   = "I/O error: Connection reset by peer (os error 104): Connection reset by peer (os error 104)"
	fakeNoSuchFile        = "No such file or directory (os error 2)"
	fakeTLSWrongVersion   = "native TLS error: error:0A00010B:SSL routines:ssl3_get_record:wrong version number:" +
		"../ssl/record/ssl3_record.c:354:"
	fakeCertificateUntrusted = "native TLS error: error:0A000086:SSL routines:tls_post_process_server_certificate:" +
		"certificate verify failed:../ssl/statem/statem_clnt.c:2091: (unable to get local issuer certificate)"
	fakeBindFailed = `LDAP bind failed, bind_dn or password could be incorrect: LDAP operation result: rc=49 ` +
		`(invalidCredentials), dn: "", text: "": rc=49 (invalidCredentials), dn: "", text: ""`
	fakeSearchFailed = `Could not search LDAP realm, base_dn could be incorrect: LDAP operation result: rc=32 ` +
		`(noSuchObject), dn: "", text: "": rc=32 (noSuchObject), dn: "", text: ""`
	fakeNoNamingContext = "failed to determine base_dn: failed to retrieve root DSE attribute 'defaultNamingContext'"
)

// fakeOpenIDScopePattern is an item of an OpenID scope list as PBS checks it.
var fakeOpenIDScopePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// newFakeRealms serves the realm API from fake.
func newFakeRealms(fake *fakePBS) *fakeRealms {
	r := &fakeRealms{
		fake:      fake,
		types:     map[string]string{"pam": pbsclient.RealmTypePAM, "pbs": pbsclient.RealmTypePBS},
		realms:    map[string]fakeProperties{"pam": {"realm": "pam", "default": true}, "pbs": {"realm": "pbs"}},
		passwords: map[string]string{},
		servers:   map[string]*fakeDirectory{},
		caFiles:   map[string]bool{},
	}
	fake.handle("GET /access/domains", r.listRealms)
	fake.handle("POST /config/access/openid", r.createOpenIDRealm)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/access/openid/", r.serveOpenIDRealm)
	}
	for _, realmType := range []string{pbsclient.RealmTypeLDAP, pbsclient.RealmTypeAD} {
		fake.handle("POST /config/access/"+realmType, r.createDirectoryRealm(realmType))
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			fake.handlePrefix(method+" /config/access/"+realmType+"/", r.serveDirectoryRealm(realmType))
		}
	}
	return r
}

// --- test helpers -------------------------------------------------------------

func (r *fakeRealms) addRealm(name, realmType string, props fakeProperties) {
	r.mu.Lock()
	defer r.mu.Unlock()
	props = cloneProperties(props)
	props["realm"] = name
	if props["default"] == true {
		r.unsetDefaultLocked()
	}
	r.types[name] = realmType
	r.realms[name] = props
	r.gen++
}

func (r *fakeRealms) realm(name string) (fakeProperties, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	props, ok := r.realms[name]
	return cloneProperties(props), ok
}

// defaultRealm returns the realm whose default flag is set, or "".
func (r *fakeRealms) defaultRealm() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, props := range r.realms {
		if props["default"] == true {
			return name
		}
	}
	return ""
}

// addServer has the PBS host reach a directory server as host, the host name
// or address a realm gives.
func (r *fakeRealms) addServer(host string, dir fakeDirectory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.servers[host] = &dir
}

// setServerPassword changes the password a directory server has for a bind
// DN, as its administrator would.
func (r *fakeRealms) setServerPassword(host, bindDN, password string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.servers[host].binds[bindDN] = password
}

// addCAFile puts a file on the PBS host that a capath can name.
func (r *fakeRealms) addCAFile(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.caFiles[path] = true
}

// setBindPassword stores the bind password of a realm, as PBS does in
// ldap_passwords.json.
func (r *fakeRealms) setBindPassword(name, password string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passwords[name] = password
}

// bindPassword returns the bind password PBS has for a realm.
func (r *fakeRealms) bindPassword(name string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	password, ok := r.passwords[name]
	return password, ok
}

// --- serving ------------------------------------------------------------------

func (r *fakeRealms) digestLocked() string { return fakeDigest("domains.cfg", r.gen) }

func (r *fakeRealms) unsetDefaultLocked() {
	for _, props := range r.realms {
		delete(props, "default")
	}
}

func (r *fakeRealms) listRealms(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.realms))
	for name := range r.realms {
		names = append(names, name)
	}
	// Not in alphabetical order, as PBS's are not.
	slices.Sort(names)
	slices.Reverse(names)
	list := make([]fakeProperties, 0, len(names))
	for _, name := range names {
		entry := fakeProperties{"realm": name, "type": r.types[name]}
		for _, key := range []string{"comment", "default"} {
			if v, ok := r.realms[name][key]; ok {
				entry[key] = v
			}
		}
		list = append(list, entry)
	}
	writeData(w, list, r.digestLocked())
}

// checkOpenIDForm fails like PBS on parameters it does not take and on
// values its schema refuses.
func checkOpenIDForm(w http.ResponseWriter, params url.Values, allowed []string) bool {
	for key := range params {
		if !slices.Contains(allowed, key) {
			writeError(w, "parameter verification failed - '%s': schema does not allow additional properties.", key)
			return false
		}
	}
	if scopes, ok := params["scopes"]; ok {
		for _, scope := range pbsclient.SplitList(scopes[0]) {
			if !fakeOpenIDScopePattern.MatchString(scope) {
				writeError(w, "parameter verification failed - 'scopes': value does not match the regex pattern")
				return false
			}
		}
	}
	return true
}

func (r *fakeRealms) createOpenIDRealm(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "realm", "issuer-url", "client-id") || !checkOpenIDForm(w, params, fakeOpenIDCreateParams) {
		return
	}
	name := params.Get("realm")
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.realms[name]; exists {
		writeError(w, "parameter verification failed - 'realm': realm '%s' already exists.", name)
		return
	}
	props := fakeProperties{}
	applyFakeForm(props, params, nil, fakeOpenIDBools)
	if props["default"] == true {
		r.unsetDefaultLocked()
	}
	r.types[name] = pbsclient.RealmTypeOpenID
	r.realms[name] = props
	r.gen++
	writeData(w, nil, "")
}

// serveOpenIDRealm serves /config/access/openid/{realm}.
func (r *fakeRealms) serveOpenIDRealm(w http.ResponseWriter, req *http.Request) {
	name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/access/openid/")
	params := form(req)
	r.mu.Lock()
	defer r.mu.Unlock()
	props, exists := r.realms[name]

	if req.Method == http.MethodDelete {
		if staleDigest(params, r.digestLocked()) {
			writeError(w, fakeDigestConflict)
			return
		}
		if !exists {
			writeFakeResponse(w, http.StatusNotFound, "realm '"+name+"' does not exist.")
			return
		}
		delete(r.realms, name)
		delete(r.types, name)
		r.gen++
		writeData(w, nil, "")
		return
	}
	if !exists {
		writeError(w, "no such openid '%s'", name)
		return
	}
	if r.types[name] != pbsclient.RealmTypeOpenID {
		writeError(w, "got unexpected type '%s' for openid '%s'", r.types[name], name)
		return
	}

	switch req.Method {
	case http.MethodGet:
		writeData(w, props, r.digestLocked())
	case http.MethodPut:
		if !checkOpenIDForm(w, params, fakeOpenIDUpdateParams) || !checkDelete(w, params, fakeOpenIDDeletable...) {
			return
		}
		if staleDigest(params, r.digestLocked()) {
			writeError(w, fakeDigestConflict)
			return
		}
		for _, key := range params[pbsclient.DeleteParam] {
			delete(props, key)
		}
		// PBS clears the flag unless the update sets it again.
		setsDefault := fakeBool(params.Get("default"))
		if setsDefault {
			r.unsetDefaultLocked()
		}
		applyFakeForm(props, params, nil, fakeOpenIDBools, "default")
		if setsDefault {
			props["default"] = true
		} else {
			delete(props, "default")
		}
		if comment, ok := props["comment"].(string); ok && comment == "" {
			delete(props, "comment")
		}
		r.gen++
		writeData(w, nil, "")
	default:
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
	}
}

// fakeDirectoryParams returns the parameters POST, or PUT, of a realm of the
// type accepts.
func fakeDirectoryParams(realmType string, create bool) []string {
	params := slices.Clone(fakeDirectoryProperties)
	if realmType == pbsclient.RealmTypeLDAP {
		params = append(params, "user-attr")
	}
	if create {
		return append(params, "realm")
	}
	return append(params, pbsclient.DeleteParam, pbsclient.DigestParam)
}

// checkDirectoryForm fails like PBS on parameters it does not take, and on
// the values its schema refuses of those the provider builds.
func checkDirectoryForm(w http.ResponseWriter, params url.Values, allowed []string) bool {
	for key := range params {
		if !slices.Contains(allowed, key) {
			writeError(w, "parameter verification failed - '%s': schema does not allow additional properties.", key)
			return false
		}
	}
	refuse := func(key, problem string) bool {
		writeError(w, "parameter verification failed - '%s': %s", key, problem)
		return false
	}
	if mode, ok := params["mode"]; ok && !slices.Contains([]string{"ldap", "ldap+starttls", "ldaps"}, mode[0]) {
		return refuse("mode", "value '"+mode[0]+"' is not defined in the enumeration.")
	}
	if port, ok := params["port"]; ok {
		if n, err := strconv.ParseInt(port[0], 10, 64); err != nil || n < 0 || n > 65535 {
			return refuse("port", "value must be an integer between 0 and 65535")
		}
	}
	if classes, ok := params["user-classes"]; ok && len(pbsclient.SplitList(classes[0])) == 0 {
		return refuse("user-classes", "array must contain at least 1 element")
	}
	if s, ok := params["sync-attributes"]; ok {
		attributes, err := pbsclient.ParsePropertyString(s[0], "")
		if err != nil {
			return refuse("sync-attributes", err.Error())
		}
		for key := range attributes {
			if !slices.Contains([]string{"email", "firstname", "lastname"}, key) {
				return refuse("sync-attributes", "'"+key+"': schema does not allow additional properties.")
			}
		}
	}
	if s, ok := params["sync-defaults-options"]; ok {
		options, err := pbsclient.ParsePropertyString(s[0], "")
		if err != nil {
			return refuse("sync-defaults-options", err.Error())
		}
		for key, value := range options {
			switch key {
			case "enable-new":
				if _, err := parsePBSBool(value); err != nil {
					return refuse("sync-defaults-options", "'enable-new': value is not a boolean")
				}
			case "remove-vanished":
				items := pbsclient.SplitList(value)
				if len(items) == 0 {
					return refuse("sync-defaults-options", "'remove-vanished': array must contain at least 1 element")
				}
				for _, item := range items {
					if !slices.Contains([]string{"acl", "entry", "properties"}, item) {
						return refuse("sync-defaults-options",
							"'remove-vanished': value '"+item+"' is not defined in the enumeration.")
					}
				}
			default:
				return refuse("sync-defaults-options", "'"+key+"': schema does not allow additional properties.")
			}
		}
	}
	return true
}

// createDirectoryRealm serves POST /config/access/{ldap,ad}.
func (r *fakeRealms) createDirectoryRealm(realmType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		params := form(req)
		required := []string{"realm", "server1"}
		if realmType == pbsclient.RealmTypeLDAP {
			required = append(required, "base-dn", "user-attr")
		}
		if !checkRequired(w, params, required...) || !checkDirectoryForm(w, params, fakeDirectoryParams(realmType, true)) {
			return
		}
		name := params.Get("realm")
		r.mu.Lock()
		defer r.mu.Unlock()
		if _, exists := r.realms[name]; exists {
			writeError(w, "parameter verification failed - 'realm': realm '%s' already exists.", name)
			return
		}
		props := fakeProperties{}
		applyFakeForm(props, params, fakeDirectoryInts, fakeDirectoryBools, "password")
		// A new realm binds with the password it is given, or none: not with
		// one ldap_passwords.json may still hold under its name.
		var password *string
		if sent, ok := params["password"]; ok {
			password = &sent[0]
		}
		if failure := r.checkConnectionLocked(realmType, props, password); failure != "" {
			writeError(w, "%s", failure)
			return
		}
		if password != nil {
			r.passwords[name] = *password
		}
		if props["default"] == true {
			r.unsetDefaultLocked()
		}
		r.types[name] = realmType
		r.realms[name] = props
		r.gen++
		writeData(w, nil, "")
	}
}

// serveDirectoryRealm serves /config/access/{ldap,ad}/{realm}.
func (r *fakeRealms) serveDirectoryRealm(realmType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/access/"+realmType+"/")
		params := form(req)
		if req.Method == http.MethodPut &&
			(!checkDirectoryForm(w, params, fakeDirectoryParams(realmType, false)) ||
				!checkDelete(w, params, fakeDirectoryDeletable...)) {
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if req.Method != http.MethodGet && staleDigest(params, r.digestLocked()) {
			writeError(w, fakeDigestConflict)
			return
		}
		props, exists := r.realms[name]

		if req.Method == http.MethodDelete {
			// Of any type: the ad route shares the ldap route's delete.
			if !exists {
				writeFakeResponse(w, http.StatusNotFound, "realm '"+name+"' does not exist.")
				return
			}
			delete(r.realms, name)
			delete(r.types, name)
			delete(r.passwords, name)
			r.gen++
			writeData(w, nil, "")
			return
		}
		if !exists {
			writeError(w, "no such %s '%s'", realmType, name)
			return
		}
		if r.types[name] != realmType {
			writeError(w, "got unexpected type '%s' for %s '%s'", r.types[name], realmType, name)
			return
		}

		switch req.Method {
		case http.MethodGet:
			writeData(w, props, r.digestLocked())
		case http.MethodPut:
			r.updateDirectoryRealmLocked(w, realmType, name, props, params)
		default:
			writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		}
	}
}

// updateDirectoryRealmLocked applies a PUT to a copy of the realm's
// properties, and saves it when its connection checks out.
func (r *fakeRealms) updateDirectoryRealmLocked(w http.ResponseWriter, realmType, name string, props fakeProperties, params url.Values) {
	updated := cloneProperties(props)
	for _, key := range params[pbsclient.DeleteParam] {
		if key == "password" {
			delete(r.passwords, name)
			continue
		}
		delete(updated, key)
	}
	applyFakeForm(updated, params, fakeDirectoryInts, fakeDirectoryBools, "password", "default", "capath")
	if comment, ok := updated["comment"].(string); ok && comment == "" {
		delete(updated, "comment")
	}
	// PBS clears the flag unless the update sets it again.
	setsDefault := fakeBool(params.Get("default"))
	if setsDefault {
		updated["default"] = true
	} else {
		delete(updated, "default")
	}

	var password *string
	if sent, ok := params["password"]; ok {
		password = &sent[0]
	} else if stored, ok := r.passwords[name]; ok {
		password = &stored
	}
	if failure := r.checkConnectionLocked(realmType, updated, password); failure != "" {
		writeError(w, "%s", failure)
		return
	}
	if params.Has("password") {
		r.passwords[name] = *password
	}
	if setsDefault {
		r.unsetDefaultLocked()
	}
	r.realms[name] = updated
	r.gen++
	writeData(w, nil, "")
}

// checkConnectionLocked checks the connection of a realm with props as PBS
// does before it saves one, binding with password, when it is not nil, and
// returns the text PBS fails with, or "". An Active Directory realm without
// base-dn gets the server's naming context first, into props.
func (r *fakeRealms) checkConnectionLocked(realmType string, props fakeProperties, password *string) string {
	if _, ok := props["base-dn"]; !ok && realmType == pbsclient.RealmTypeAD {
		dir, failure := r.connectLocked(props)
		if failure != "" {
			// PBS writes this error with its outermost message only, not
			// the chain the check of the connection writes.
			if i := strings.LastIndex(failure, ": "); i > 0 && strings.HasSuffix(failure[:i], failure[i+2:]) {
				failure = failure[:i]
			}
			return "failed to determine base_dn: " + failure
		}
		if dir.namingContext == "" {
			return fakeNoNamingContext
		}
		props["base-dn"] = dir.namingContext
	}
	dir, failure := r.connectLocked(props)
	if failure != "" {
		return failure
	}
	if bindDN, ok := props["bind-dn"].(string); ok {
		if password == nil {
			return "Missing bind password for " + bindDN
		}
		if want, ok := dir.binds[bindDN]; !ok || want != *password {
			return fakeBindFailed
		}
	}
	baseDN, _ := props["base-dn"].(string)
	if !slices.ContainsFunc(dir.entries, func(dn string) bool { return strings.EqualFold(dn, baseDN) }) {
		return fakeSearchFailed
	}
	return ""
}

// connectLocked connects to server1, or else to server2, as props have the
// realm connect, and returns the server, or the failure of the last attempt.
func (r *fakeRealms) connectLocked(props fakeProperties) (*fakeDirectory, string) {
	mode, _ := props["mode"].(string)
	port, ok := props["port"].(int64)
	if !ok {
		port = 389
		if mode == "ldaps" {
			port = 636
		}
	}
	capath, _ := props["capath"].(string)
	verify := props["verify"] == true
	var failure string
	for _, key := range []string{"server1", "server2"} {
		host, ok := props[key].(string)
		if !ok {
			continue
		}
		var dir *fakeDirectory
		if dir, failure = r.tryConnectLocked(host, port, mode, verify, capath); failure == "" {
			return dir, ""
		}
	}
	return nil, failure
}

// tryConnectLocked connects to one server.
func (r *fakeRealms) tryConnectLocked(host string, port int64, mode string, verify bool, capath string) (*fakeDirectory, string) {
	if capath != "" && !r.caFiles[capath] {
		return nil, fakeNoSuchFile
	}
	dir := r.servers[host]
	if dir == nil {
		return nil, fakeConnectionRefused
	}
	ports := dir.ports
	if ports == nil {
		ports = map[int64]string{389: "ldap", 636: "ldaps"}
	}
	protocol, listening := ports[port]
	tls := mode == "ldaps" || mode == "ldap+starttls"
	switch {
	case !listening:
		return nil, fakeConnectionRefused
	case mode == "ldaps" && protocol != "ldaps":
		return nil, fakeTLSWrongVersion
	case mode != "ldaps" && protocol == "ldaps":
		return nil, fakeConnectionReset
	case tls && verify && dir.ca != "" && dir.ca != capath:
		return nil, fakeCertificateUntrusted
	}
	return dir, ""
}
