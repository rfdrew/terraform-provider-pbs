package provider

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeSync keeps remotes and sync jobs in memory and serves PBS's API for
// them through a fakePBS, with the behaviour read in PBS 4.2's source (see
// internal/pbsclient/remotes.go and sync.go):
//
//   - creating or changing a remote contacts nothing; reads leave out the
//     password, and every property at its default;
//   - a scan answers what a test set up with addRemoteDatastore and
//     addRemoteNamespace, or 500 for a remote set unreachable;
//   - deleting a remote a sync job uses is refused;
//   - the sync job list answers pull jobs only, unless sync-direction says
//     "all" or "push"; GET by ID reads either direction;
//   - creating a job refuses a push without a remote, a local pull into its
//     own source, resync-corrupt on a push and a max-depth below the deepest
//     namespace; an update checks resync-corrupt against the update's
//     direction only, and unmount-on-done against run-on-mount;
//   - an update's delete accepts only the names PBS accepts, and PBS applies
//     the deletions before the values; resync-corrupt is not among them;
//   - rate and burst limits read back in PBS's spelling, such as "10 MiB",
//     and group filters without an "include:" prefix;
//   - with datastores, deleting a datastore without keep-job-configs deletes
//     the sync jobs whose store it is.
//
// Tests set up state with addRemote, addSyncJob, addRemoteDatastore and
// addRemoteNamespace, and look at it with remote, remotePassword and
// syncJob.
type fakeSync struct {
	fake *fakePBS

	mu        sync.Mutex
	remotes   map[string]fakeProperties
	passwords map[string]string
	syncJobs  map[string]fakeProperties
	// scans are what a scan of each remote answers: datastores, and the
	// namespaces of each datastore.
	scanDatastores map[string][]fakeProperties
	scanNamespaces map[string]map[string][]string
	// unreachable are the remotes whose scans fail as PBS's fail when it
	// cannot connect or sign in.
	unreachable map[string]bool
}

// The properties of remotes and sync jobs that are not strings.
var (
	fakeRemoteInts   = []string{"port"}
	fakeRemoteBools  = []string{"use-node-proxy"}
	fakeSyncJobInts  = []string{"max-depth", "transfer-last", "worker-threads"}
	fakeSyncJobBools = []string{"remove-vanished", "resync-corrupt", "encrypted-only", "verified-only", "run-on-mount",
		"unmount-on-done"}
	fakeByteSizes = []string{"rate-in", "burst-in", "rate-out", "burst-out"}
)

// What PBS lets an update delete.
var (
	fakeRemoteDeletable  = []string{"comment", "fingerprint", "port", "use-node-proxy"}
	fakeSyncJobDeletable = []string{"remote", "owner", "comment", "schedule", "remove-vanished", "group-filter",
		"rate-in", "burst-in", "rate-out", "burst-out", "ns", "remote-ns", "max-depth", "transfer-last",
		"encrypted-only", "verified-only", "run-on-mount", "unmount-on-done", "sync-direction", "worker-threads",
		"active-encryption-key", "associated-key"}
)

// fakeFingerprintPattern is the fingerprint PBS takes: colon-separated hex
// pairs, in either case.
var fakeFingerprintPattern = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){31}$`)

// newFakeSync serves the remote and sync job API from fake. With datastores,
// deleting a datastore deletes its sync jobs too.
func newFakeSync(fake *fakePBS, datastores *fakeDatastores) *fakeSync {
	s := &fakeSync{
		fake:           fake,
		remotes:        map[string]fakeProperties{},
		passwords:      map[string]string{},
		syncJobs:       map[string]fakeProperties{},
		scanDatastores: map[string][]fakeProperties{},
		scanNamespaces: map[string]map[string][]string{},
		unreachable:    map[string]bool{},
	}
	fake.handle("GET /config/remote", s.listRemotes)
	fake.handle("POST /config/remote", s.createRemote)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/remote/", s.serveRemote)
		fake.handlePrefix(method+" /config/sync/", s.serveSyncJob)
	}
	fake.handle("GET /config/sync", s.listSyncJobs)
	fake.handle("POST /config/sync", s.createSyncJob)
	if datastores != nil {
		fake.handle("GET /config/prune", listFakeJobs(datastores, "prune.cfg", func() map[string]fakeProperties { return datastores.pruneJobs }))
		fake.handle("GET /config/verify", listFakeJobs(datastores, "verification.cfg", func() map[string]fakeProperties { return datastores.verifyJobs }))
		fake.handlePrefix("DELETE /config/datastore/", func(w http.ResponseWriter, req *http.Request) {
			name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/datastore/")
			if _, exists := datastores.datastore(name); exists && !fakeBool(form(req).Get("keep-job-configs")) {
				s.mu.Lock()
				for id, job := range s.syncJobs {
					if job["store"] == name {
						delete(s.syncJobs, id)
					}
				}
				s.mu.Unlock()
			}
			datastores.serveDatastore(w, req)
		})
	}
	return s
}

// --- test helpers -------------------------------------------------------------

func (s *fakeSync) addRemote(name string, props fakeProperties, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	props = cloneProperties(props)
	props["name"] = name
	s.remotes[name] = props
	s.passwords[name] = password
}

func (s *fakeSync) addSyncJob(id string, props fakeProperties) {
	s.mu.Lock()
	defer s.mu.Unlock()
	props = cloneProperties(props)
	props["id"] = id
	s.syncJobs[id] = props
}

// addRemoteDatastore adds a datastore to what scans of the remote answer.
func (s *fakeSync) addRemoteDatastore(remote string, props fakeProperties) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanDatastores[remote] = append(s.scanDatastores[remote], cloneProperties(props))
}

// addRemoteNamespace adds a namespace of a datastore to what scans of the
// remote answer; "" is the root.
func (s *fakeSync) addRemoteNamespace(remote, store, ns string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scanNamespaces[remote] == nil {
		s.scanNamespaces[remote] = map[string][]string{}
	}
	s.scanNamespaces[remote][store] = append(s.scanNamespaces[remote][store], ns)
}

func (s *fakeSync) setUnreachable(remote string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unreachable[remote] = true
}

func (s *fakeSync) remote(name string) (fakeProperties, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	props, ok := s.remotes[name]
	return cloneProperties(props), ok
}

func (s *fakeSync) remotePassword(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.passwords[name]
}

func (s *fakeSync) syncJob(id string) (fakeProperties, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	props, ok := s.syncJobs[id]
	return cloneProperties(props), ok
}

// --- remotes ------------------------------------------------------------------

func (s *fakeSync) listRemotes(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.remotes))
	for name := range s.remotes {
		names = append(names, name)
	}
	sort.Strings(names)
	list := make([]fakeProperties, 0, len(names))
	for _, name := range names {
		list = append(list, s.remotes[name])
	}
	writeData(w, list, fakeDigest("remote.cfg", len(s.remotes)))
}

// checkRemoteForm fails like PBS on a fingerprint without colons.
func checkRemoteForm(w http.ResponseWriter, params url.Values) bool {
	if fp, ok := params["fingerprint"]; ok && !fakeFingerprintPattern.MatchString(fp[0]) {
		writeError(w, "parameter verification failed - 'fingerprint': value does not match the regex pattern")
		return false
	}
	return true
}

func (s *fakeSync) createRemote(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "name", "host", "auth-id", "password") || !checkRemoteForm(w, params) {
		return
	}
	name := params.Get("name")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.remotes[name]; exists {
		writeError(w, "parameter verification failed - 'name': remote '%s' already exists.", name)
		return
	}
	props := fakeProperties{}
	applyFakeForm(props, params, fakeRemoteInts, fakeRemoteBools, "password")
	s.remotes[name] = props
	s.passwords[name] = params.Get("password")
	writeData(w, nil, "")
}

// serveRemote serves /config/remote/{name} and the scans below it.
func (s *fakeSync) serveRemote(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/remote/"), "/")
	name := parts[0]
	params := form(req)
	s.mu.Lock()
	defer s.mu.Unlock()
	props, exists := s.remotes[name]

	if req.Method == http.MethodDelete {
		for id, job := range s.syncJobs {
			if job["remote"] == name {
				writeError(w, "parameter verification failed - 'name': remote '%s' is used by sync job '%s' (datastore '%s')",
					name, id, job["store"])
				return
			}
		}
		if !exists {
			writeFakeResponse(w, http.StatusNotFound, fmt.Sprintf("remote '%s' does not exist.", name))
			return
		}
		delete(s.remotes, name)
		delete(s.passwords, name)
		writeData(w, nil, "")
		return
	}
	if !exists {
		writeError(w, "no such remote '%s'", name)
		return
	}

	switch {
	case req.Method == http.MethodGet && len(parts) == 1:
		writeData(w, props, fakeDigest("remote.cfg", len(s.remotes)))
	case req.Method == http.MethodGet && len(parts) == 2 && parts[1] == "scan":
		if s.unreachable[name] {
			writeFakeResponse(w, http.StatusInternalServerError, fmt.Sprintf(
				"failed to scan remote '%s' - remote connection to '%s' failed - connection refused", name, props["host"]))
			return
		}
		list := s.scanDatastores[name]
		if list == nil {
			list = []fakeProperties{}
		}
		writeData(w, list, "")
	case req.Method == http.MethodGet && len(parts) == 4 && parts[1] == "scan" && parts[3] == "namespaces":
		if s.unreachable[name] {
			writeFakeResponse(w, http.StatusInternalServerError, fmt.Sprintf(
				"failed to scan remote '%s' - remote connection to '%s' failed - connection refused", name, props["host"]))
			return
		}
		namespaces, known := s.scanNamespaces[name][parts[2]]
		if !known {
			writeFakeResponse(w, http.StatusInternalServerError, fmt.Sprintf(
				"failed to scan remote '%s' - no such datastore '%s'", name, parts[2]))
			return
		}
		list := []fakeProperties{}
		for _, ns := range namespaces {
			list = append(list, fakeProperties{"ns": ns})
		}
		writeData(w, list, "")
	case req.Method == http.MethodPut && len(parts) == 1:
		if !checkDelete(w, params, fakeRemoteDeletable...) || !checkRemoteForm(w, params) {
			return
		}
		for _, key := range params[pbsclient.DeleteParam] {
			delete(props, key)
		}
		applyFakeForm(props, params, fakeRemoteInts, fakeRemoteBools, "password")
		if comment, ok := props["comment"].(string); ok && comment == "" {
			delete(props, "comment")
		}
		if password, ok := params["password"]; ok {
			s.passwords[name] = password[0]
		}
		writeData(w, nil, "")
	default:
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
	}
}

// --- sync jobs ----------------------------------------------------------------

func (s *fakeSync) listSyncJobs(w http.ResponseWriter, req *http.Request) {
	direction := req.URL.Query().Get("sync-direction")
	if direction == "" {
		direction = pbsclient.SyncDirectionPull
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.syncJobs))
	for id := range s.syncJobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	list := []fakeProperties{}
	for _, id := range ids {
		if direction == pbsclient.SyncDirectionAll || fakeSyncDirection(s.syncJobs[id]) == direction {
			list = append(list, s.syncJobs[id])
		}
	}
	writeData(w, list, fakeDigest("sync.cfg", len(s.syncJobs)))
}

// fakeSyncDirection is a job's direction, pull when it has none.
func fakeSyncDirection(job fakeProperties) string {
	if d, ok := job["sync-direction"].(string); ok {
		return d
	}
	return pbsclient.SyncDirectionPull
}

// fakeHumanByte writes a byte size back as PBS does: the number, rounded to
// three decimals, a space and the unit.
func fakeHumanByte(size string) string {
	rest := strings.TrimSuffix(strings.TrimSuffix(size, "B"), "b")
	binary := strings.HasSuffix(rest, "i")
	rest = strings.TrimSuffix(rest, "i")
	unit := "B"
	if rest != "" {
		if letter := strings.ToUpper(rest[len(rest)-1:]); strings.Contains("KMGTP", letter) {
			unit = letter + "B"
			if binary {
				unit = letter + "iB"
			}
			rest = rest[:len(rest)-1]
		}
	}
	value, _ := strconv.ParseFloat(strings.TrimSpace(rest), 64)
	return strconv.FormatFloat(float64(int64(value*1000+0.5))/1000, 'f', -1, 64) + " " + unit
}

// applySyncJobForm sets the properties a form carries, as PBS stores them.
func applySyncJobForm(props fakeProperties, params url.Values) {
	applyFakeForm(props, params, fakeSyncJobInts, fakeSyncJobBools, "group-filter")
	for _, key := range fakeByteSizes {
		if v, ok := params[key]; ok {
			props[key] = fakeHumanByte(v[0])
		}
	}
	if filters, ok := params["group-filter"]; ok {
		stored := make([]string, 0, len(filters))
		for _, f := range filters {
			stored = append(stored, strings.TrimPrefix(f, "include:"))
		}
		props["group-filter"] = stored
	}
	if comment, ok := props["comment"].(string); ok && comment == "" {
		delete(props, "comment")
	}
}

// checkSyncJobLocked fails like PBS on what a job cannot be, after a create
// or an update; the caller holds the lock.
func checkSyncJobLocked(w http.ResponseWriter, job fakeProperties) bool {
	if fakeSyncDirection(job) == pbsclient.SyncDirectionPush && job["remote"] == nil {
		writeError(w, "permission check failed")
		return false
	}
	if depth, ok := job["max-depth"].(int64); ok {
		for _, key := range []string{"ns", "remote-ns"} {
			ns, _ := job[key].(string)
			if nsDepth := namespaceDepth(ns); nsDepth+depth > maxNamespaceDepth {
				writeError(w, "namespace '%s's depth and recursion depth exceed limit: %d + %d > 7", ns, nsDepth, depth)
				return false
			}
		}
	}
	return true
}

func (s *fakeSync) createSyncJob(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "id", "store", "remote-store") {
		return
	}
	id := params.Get("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	props := fakeProperties{}
	applySyncJobForm(props, params)
	if !checkSyncJobLocked(w, props) {
		return
	}
	if props["remote"] == nil && props["store"] == props["remote-store"] {
		writeError(w, "source and target datastore can't be the same")
		return
	}
	if fakeSyncDirection(props) == pbsclient.SyncDirectionPush && params.Has("resync-corrupt") {
		writeError(w, "push jobs do not support resync-corrupt option")
		return
	}
	if _, exists := s.syncJobs[id]; exists {
		writeError(w, "parameter verification failed - 'id': job '%s' already exists.", id)
		return
	}
	s.syncJobs[id] = props
	writeData(w, nil, "")
}

// serveSyncJob serves /config/sync/{id}.
func (s *fakeSync) serveSyncJob(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/sync/")
	params := form(req)
	s.mu.Lock()
	defer s.mu.Unlock()
	props, exists := s.syncJobs[id]

	switch req.Method {
	case http.MethodGet:
		if !exists {
			writeError(w, "no such sync '%s'", id)
			return
		}
		writeData(w, props, fakeDigest("sync.cfg", len(s.syncJobs)))
	case http.MethodPut:
		if !exists {
			writeError(w, "no such sync '%s'", id)
			return
		}
		if params.Get("sync-direction") == pbsclient.SyncDirectionPush && params.Has("resync-corrupt") {
			writeError(w, "push jobs do not support resync-corrupt option")
			return
		}
		if !checkDelete(w, params, fakeSyncJobDeletable...) {
			return
		}
		updated := cloneProperties(props)
		for _, key := range params[pbsclient.DeleteParam] {
			delete(updated, key)
		}
		applySyncJobForm(updated, params)
		if fakeBool(params.Get("unmount-on-done")) && updated["run-on-mount"] != true {
			writeError(w, "'unmount-on-done' can only be set when 'run-on-mount' is enabled")
			return
		}
		if !checkSyncJobLocked(w, updated) {
			return
		}
		s.syncJobs[id] = updated
		writeData(w, nil, "")
	case http.MethodDelete:
		if !exists {
			writeFakeResponse(w, http.StatusNotFound, fmt.Sprintf("job '%s' does not exist.", id))
			return
		}
		delete(s.syncJobs, id)
		writeData(w, nil, "")
	}
}

// listFakeJobs serves the list of the prune or verify jobs that jobs returns,
// which the datastores' fake keeps, by ID.
func listFakeJobs(d *fakeDatastores, file string, jobs func() map[string]fakeProperties) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		all := jobs()
		ids := make([]string, 0, len(all))
		for id := range all {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		list := make([]fakeProperties, 0, len(ids))
		for _, id := range ids {
			list = append(list, all[id])
		}
		writeData(w, list, fakeDigest(file, len(all)))
	}
}
