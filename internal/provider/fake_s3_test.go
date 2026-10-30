package provider

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeS3 keeps S3 endpoints in memory and serves PBS's API for them through
// a fakePBS, with the behaviour read in PBS 4.2's source (see
// internal/pbsclient/s3.go):
//
//   - creating or changing an endpoint contacts nothing. Reads leave out the
//     secret key and every property PBS was not sent, but answer one sent at
//     its default, such as path-style=false, since PBS stores what it is
//     sent;
//   - rate and burst limits read back in PBS's spelling, such as "10 MiB",
//     and provider quirks as a list in the order they were sent;
//   - PBS lists the endpoints in no particular order; the fake lists them by
//     ID, reversed, so that tests show whether the provider sorts them;
//   - a fingerprint without colons is refused;
//   - an update's delete accepts only the names PBS accepts, and PBS applies
//     the deletions before the values; it keeps the secret key when the
//     update has none, and ignores put-rate-limit;
//   - with datastores, deleting an endpoint a datastore's backend names is
//     refused, before PBS looks for the endpoint;
//   - a missing endpoint answers 400 "no such s3-endpoint 'x'" on GET and
//     PUT, and 404 "s3 client config 'x' do not exist." on DELETE;
//   - a bucket list answers the buckets a test set up with addBucket, in that
//     order, or fails with the outermost context of PBS's error alone:
//     "config lookup failed" for a missing endpoint, "failed to list
//     buckets" for one set unreachable.
//
// Tests set up state with addEndpoint, addBucket and setUnreachable, and look
// at it with endpoint and secretKey.
type fakeS3 struct {
	fake       *fakePBS
	datastores *fakeDatastores

	mu        sync.Mutex
	endpoints map[string]fakeProperties
	secrets   map[string]string
	// buckets are what a bucket list of each endpoint answers, and
	// unreachable the endpoints whose bucket lists fail as PBS's fail when
	// it cannot connect or sign in.
	buckets     map[string][]string
	unreachable map[string]bool
}

// The properties of S3 endpoints that are neither strings nor byte sizes.
var (
	fakeS3Ints  = []string{"port", "put-rate-limit", "limit-active-requests", "limit-passive-requests"}
	fakeS3Bools = []string{"path-style", "use-node-proxy"}
)

// fakeS3Deletable is what PBS lets an S3 endpoint update delete.
var fakeS3Deletable = []string{"port", "region", "fingerprint", "path-style", "rate-in", "burst-in", "rate-out",
	"burst-out", "limit-active-requests", "limit-passive-requests", "provider-quirks", "use-node-proxy"}

// newFakeS3 serves the S3 endpoint API from fake. With datastores, an
// endpoint a datastore uses cannot be deleted.
func newFakeS3(fake *fakePBS, datastores *fakeDatastores) *fakeS3 {
	s := &fakeS3{
		fake:        fake,
		datastores:  datastores,
		endpoints:   map[string]fakeProperties{},
		secrets:     map[string]string{},
		buckets:     map[string][]string{},
		unreachable: map[string]bool{},
	}
	fake.handle("GET /config/s3", s.listEndpoints)
	fake.handle("POST /config/s3", s.createEndpoint)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/s3/", s.serveEndpoint)
	}
	return s
}

// --- test helpers -------------------------------------------------------------

// addEndpoint adds an endpoint as PBS keeps it: props are what a read
// answers, besides the ID.
func (s *fakeS3) addEndpoint(id string, props fakeProperties, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	props = cloneProperties(props)
	props["id"] = id
	s.endpoints[id] = props
	s.secrets[id] = secret
}

// addBucket adds a bucket to what bucket lists of the endpoint answer.
func (s *fakeS3) addBucket(id, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buckets[id] = append(s.buckets[id], name)
}

func (s *fakeS3) setUnreachable(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unreachable[id] = true
}

func (s *fakeS3) endpoint(id string) (fakeProperties, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	props, ok := s.endpoints[id]
	return cloneProperties(props), ok
}

func (s *fakeS3) secretKey(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets[id]
}

// --- serving ------------------------------------------------------------------

func (s *fakeS3) listEndpoints(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := slices.Sorted(maps.Keys(s.endpoints))
	slices.Reverse(ids)
	list := make([]fakeProperties, 0, len(ids))
	for _, id := range ids {
		list = append(list, s.endpoints[id])
	}
	writeData(w, list, fakeDigest("s3.cfg", len(s.endpoints)))
}

// applyS3Form sets the properties a form carries, as PBS stores them; skip
// names parameters PBS does not store.
func applyS3Form(props fakeProperties, params url.Values, skip ...string) {
	applyFakeForm(props, params, fakeS3Ints, fakeS3Bools, append([]string{"secret-key", "provider-quirks"}, skip...)...)
	for _, key := range fakeByteSizes {
		if v, ok := params[key]; ok {
			props[key] = fakeHumanByte(v[0])
		}
	}
	if quirks, ok := params["provider-quirks"]; ok {
		props["provider-quirks"] = slices.Clone(quirks)
	}
}

func (s *fakeS3) createEndpoint(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "id", "endpoint", "access-key", "secret-key") || !checkRemoteForm(w, params) {
		return
	}
	id := params.Get("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.endpoints[id]; exists {
		writeError(w, "parameter verification failed - 'id': s3 client config '%s' already exists.", id)
		return
	}
	props := fakeProperties{}
	applyS3Form(props, params)
	s.endpoints[id] = props
	s.secrets[id] = params.Get("secret-key")
	writeData(w, nil, "")
}

// datastoreUsing returns the first datastore, by name, whose backend is on
// the S3 endpoint id, as PBS's in-use check finds it; "" when there is none.
// It takes the datastores' lock alone, never together with the endpoints'.
func (s *fakeS3) datastoreUsing(id string) string {
	if s.datastores == nil {
		return ""
	}
	s.datastores.mu.Lock()
	defer s.datastores.mu.Unlock()
	for _, name := range slices.Sorted(maps.Keys(s.datastores.datastores)) {
		backend, _ := s.datastores.datastores[name]["backend"].(string)
		parsed, err := pbsclient.ParsePropertyString(backend, "type")
		if err == nil && parsed["type"] == "s3" && parsed["client"] == id {
			return name
		}
	}
	return ""
}

// serveEndpoint serves /config/s3/{id} and the bucket list below it.
func (s *fakeS3) serveEndpoint(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/s3/"), "/")
	id := parts[0]
	params := form(req)
	usedBy := ""
	if req.Method == http.MethodDelete {
		usedBy = s.datastoreUsing(id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	props, exists := s.endpoints[id]

	switch {
	case req.Method == http.MethodGet && len(parts) == 2 && parts[1] == "list-buckets":
		switch {
		case !exists:
			writeError(w, "config lookup failed")
		case s.unreachable[id]:
			writeError(w, "failed to list buckets")
		default:
			list := []fakeProperties{}
			for _, name := range s.buckets[id] {
				list = append(list, fakeProperties{"name": name})
			}
			writeData(w, list, "")
		}
	case len(parts) != 1:
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
	case req.Method == http.MethodDelete:
		switch {
		case usedBy != "":
			writeError(w, "in-use by datastore %s", usedBy)
		case !exists:
			writeFakeResponse(w, http.StatusNotFound, fmt.Sprintf("s3 client config '%s' do not exist.", id))
		default:
			delete(s.endpoints, id)
			delete(s.secrets, id)
			writeData(w, nil, "")
		}
	case !exists:
		writeError(w, "no such s3-endpoint '%s'", id)
	case req.Method == http.MethodGet:
		writeData(w, props, fakeDigest("s3.cfg", len(s.endpoints)))
	case req.Method == http.MethodPut:
		if !checkDelete(w, params, fakeS3Deletable...) || !checkRemoteForm(w, params) {
			return
		}
		updated := cloneProperties(props)
		for _, key := range params[pbsclient.DeleteParam] {
			delete(updated, key)
		}
		applyS3Form(updated, params, "put-rate-limit")
		s.endpoints[id] = updated
		if secret, ok := params["secret-key"]; ok {
			s.secrets[id] = secret[0]
		}
		writeData(w, nil, "")
	}
}
