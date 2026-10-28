package provider

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
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
// Tests set up state with addRealm and look at it with realm and
// defaultRealm.
type fakeRealms struct {
	fake *fakePBS

	mu sync.Mutex
	// realms are the sections of domains.cfg: their type, and their
	// properties.
	types  map[string]string
	realms map[string]fakeProperties
	gen    int
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

// fakeOpenIDScopePattern is an item of an OpenID scope list as PBS checks it.
var fakeOpenIDScopePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// newFakeRealms serves the realm API from fake.
func newFakeRealms(fake *fakePBS) *fakeRealms {
	r := &fakeRealms{
		fake:   fake,
		types:  map[string]string{"pam": pbsclient.RealmTypePAM, "pbs": pbsclient.RealmTypePBS},
		realms: map[string]fakeProperties{"pam": {"realm": "pam", "default": true}, "pbs": {"realm": "pbs"}},
	}
	fake.handle("GET /access/domains", r.listRealms)
	fake.handle("POST /config/access/openid", r.createOpenIDRealm)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/access/openid/", r.serveOpenIDRealm)
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
