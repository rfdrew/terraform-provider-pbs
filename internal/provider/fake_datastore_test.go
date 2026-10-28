package provider

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeDatastores keeps datastores, prune jobs and verify jobs in memory and
// serves PBS's API for them through a fakePBS, with the behaviour observed on
// PBS 4.0 and 4.2 and read in its source (see internal/pbsclient/datastore.go
// and jobs.go):
//
//   - POST /config/datastore answers a UPID at once, and the task does the
//     work when it is first polled. Without reuse-datastore it fails on a
//     directory with backups in it, "datastore path not empty", and on one
//     with only a chunk store, when it creates .chunks; with
//     reuse-datastore, on a directory without a chunk store;
//   - DELETE answers a UPID too. The task removes the entry, and the
//     directory only with destroy-data; without keep-job-configs the
//     datastore's jobs are deleted at once. failDelete makes the task fail,
//     or end with warnings without removing the entry, as PBS does when it
//     cannot remove the data; both leave the datastore in maintenance mode
//     "delete", which PBS then refuses to change;
//   - reads leave out every property at its default. Property strings are
//     stored as sent, except maintenance-mode, which PBS writes back in its
//     own form;
//   - an update's delete accepts only the names PBS accepts, and PBS applies
//     the deletions before the values;
//   - missing objects answer the 400s and 404s PBS answers.
//
// Tests set up state with addDatastore, addPruneJob, addVerifyJob and
// addChunkStore, and look at it with datastore, pruneJob, verifyJob and
// hasChunkStore.
type fakeDatastores struct {
	fake *fakePBS

	mu         sync.Mutex
	datastores map[string]fakeProperties
	// chunkStores are the directories that hold a chunk store: those of
	// existing datastores, and those a deletion without destroy-data left.
	// backups are those of them with backups in them.
	chunkStores map[string]bool
	backups     map[string]bool
	pruneJobs   map[string]fakeProperties
	verifyJobs  map[string]fakeProperties
	// tasks are the worker tasks started and not yet polled, by UPID.
	tasks   map[string]func() string
	taskGen int
	// failDelete makes the next delete-datastore task fail as it does for a
	// datastore in use, with "error", or end with warnings, with "warnings",
	// as it does when it cannot remove the data.
	failDelete string
}

// fakeProperties are the properties of one section of a configuration file,
// as PBS keeps them: strings, int64s and bools.
type fakeProperties map[string]any

// fakeTaskNode is the node name the fake's UPIDs carry.
const fakeTaskNode = "pbs-test"

// The properties of each kind of section that are not strings.
var (
	fakeDatastoreBools = []string{"verify-new", "gc-on-unmount"}
	fakeJobInts        = []string{"max-depth", "keep-last", "keep-hourly", "keep-daily", "keep-weekly", "keep-monthly",
		"keep-yearly", "outdated-after", "read-threads", "verify-threads"}
	fakeJobBools = []string{"disable", "ignore-verified"}
)

// What PBS lets an update delete, beyond what the resources send.
var (
	fakeDatastoreDeletable = []string{"comment", "gc-schedule", "gc-on-unmount", "prune-schedule", "keep-last",
		"keep-hourly", "keep-daily", "keep-weekly", "keep-monthly", "keep-yearly", "verify-new", "notify-user",
		"notify", "notification-mode", "tuning", "maintenance-mode", "notification-thresholds", "counter-reset-schedule"}
	fakePruneJobDeletable = []string{"comment", "disable", "ns", "max-depth", "keep-last", "keep-hourly",
		"keep-daily", "keep-weekly", "keep-monthly", "keep-yearly"}
	fakeVerifyJobDeletable = []string{"ignore-verified", "comment", "schedule", "outdated-after", "ns", "max-depth",
		"read-threads", "verify-threads"}
)

// newFakeDatastores serves the datastore and job API from fake.
func newFakeDatastores(fake *fakePBS) *fakeDatastores {
	d := &fakeDatastores{
		fake:        fake,
		datastores:  map[string]fakeProperties{},
		chunkStores: map[string]bool{},
		backups:     map[string]bool{},
		pruneJobs:   map[string]fakeProperties{},
		verifyJobs:  map[string]fakeProperties{},
		tasks:       map[string]func() string{},
	}
	fake.handle("POST /config/datastore", d.createDatastore)
	fake.handle("POST /config/prune", d.createJob("prune"))
	fake.handle("POST /config/verify", d.createJob("verify"))
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/datastore/", d.serveDatastore)
		fake.handlePrefix(method+" /config/prune/", d.serveJob("prune"))
		fake.handlePrefix(method+" /config/verify/", d.serveJob("verify"))
	}
	fake.handlePrefix("GET /nodes/"+fakeTaskNode+"/tasks/", d.taskStatus)
	return d
}

// --- test helpers -------------------------------------------------------------

func (d *fakeDatastores) addDatastore(name string, props fakeProperties) {
	d.mu.Lock()
	defer d.mu.Unlock()
	props = cloneProperties(props)
	props["name"] = name
	d.datastores[name] = props
	if path, ok := props["path"].(string); ok {
		d.chunkStores[path] = true
	}
}

func (d *fakeDatastores) addPruneJob(id string, props fakeProperties) {
	d.mu.Lock()
	defer d.mu.Unlock()
	props = cloneProperties(props)
	props["id"] = id
	d.pruneJobs[id] = props
}

func (d *fakeDatastores) addVerifyJob(id string, props fakeProperties) {
	d.mu.Lock()
	defer d.mu.Unlock()
	props = cloneProperties(props)
	props["id"] = id
	d.verifyJobs[id] = props
}

// addChunkStore leaves a chunk store in a directory, with or without
// backups, as a datastore deleted without destroy-data does.
func (d *fakeDatastores) addChunkStore(path string, withBackups bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.chunkStores[path] = true
	d.backups[path] = withBackups
}

// setDatastoreProperty changes a datastore as PBS or another client would.
func (d *fakeDatastores) setDatastoreProperty(name, key string, value any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if value == nil {
		delete(d.datastores[name], key)
		return
	}
	d.datastores[name][key] = value
}

func (d *fakeDatastores) datastore(name string) (fakeProperties, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	props, ok := d.datastores[name]
	return cloneProperties(props), ok
}

func (d *fakeDatastores) pruneJob(id string) (fakeProperties, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	props, ok := d.pruneJobs[id]
	return cloneProperties(props), ok
}

func (d *fakeDatastores) verifyJob(id string) (fakeProperties, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	props, ok := d.verifyJobs[id]
	return cloneProperties(props), ok
}

func (d *fakeDatastores) hasChunkStore(path string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.chunkStores[path]
}

func cloneProperties(props fakeProperties) fakeProperties {
	out := make(fakeProperties, len(props))
	for k, v := range props {
		out[k] = v
	}
	return out
}

// --- serving ------------------------------------------------------------------

// startTaskLocked registers a worker task that run performs when it is first
// polled, returning its exit status, and returns its UPID.
func (d *fakeDatastores) startTaskLocked(workerType, workerID string, run func() string) string {
	d.taskGen++
	upid := fmt.Sprintf("UPID:%s:00000001:00000001:%08X:6AE11CDF:%s:%s:%s:", fakeTaskNode, d.taskGen, workerType, workerID, fakeTokenID)
	d.tasks[upid] = run
	return upid
}

// taskStatus serves GET /nodes/{node}/tasks/{upid}/status, running a task on
// its first poll. A task PBS does not know is "unknown", as PBS answers.
func (d *fakeDatastores) taskStatus(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/nodes/"+fakeTaskNode+"/tasks/")
	upid, ok := strings.CutSuffix(rest, "/status")
	if !ok {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	exit := "unknown"
	if run, ok := d.tasks[upid]; ok {
		exit = run()
		delete(d.tasks, upid)
	}
	writeData(w, map[string]any{"status": "stopped", "exitstatus": exit, "upid": upid}, "")
}

// applyFakeForm sets the properties a form carries, typed as PBS stores them;
// skip names parameters that are not properties.
func applyFakeForm(props fakeProperties, params url.Values, ints, bools []string, skip ...string) {
	for key, values := range params {
		if key == pbsclient.DeleteParam || key == pbsclient.DigestParam || slices.Contains(skip, key) {
			continue
		}
		switch {
		case slices.Contains(ints, key):
			n, _ := strconv.ParseInt(values[0], 10, 64)
			props[key] = n
		case slices.Contains(bools, key):
			props[key] = fakeBool(values[0])
		default:
			props[key] = strings.TrimSpace(values[0])
		}
	}
}

// checkRequired fails like PBS when a required parameter is missing.
func checkRequired(w http.ResponseWriter, params url.Values, names ...string) bool {
	for _, name := range names {
		if params.Get(name) == "" {
			writeError(w, "parameter verification failed - '%s': parameter is missing and it is not optional.", name)
			return false
		}
	}
	return true
}

func (d *fakeDatastores) createDatastore(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "name", "path") {
		return
	}
	name, path := params.Get("name"), params.Get("path")
	reuse := fakeBool(params.Get("reuse-datastore"))
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.datastores[name]; exists {
		writeError(w, "parameter verification failed - 'name': datastore '%s' already exists.", name)
		return
	}
	if !strings.HasPrefix(path, "/") {
		writeError(w, "parameter verification failed - 'path': expected an absolute path, '%s' is not", path)
		return
	}
	props := fakeProperties{}
	applyFakeForm(props, params, nil, fakeDatastoreBools, "reuse-datastore", "overwrite-in-use")
	upid := d.startTaskLocked("create-datastore", name, func() string {
		switch {
		case reuse && !d.chunkStores[path]:
			return fmt.Sprintf("unable to open existing chunk store path %q - ENOENT: No such file or directory", path+"/.chunks")
		case !reuse && d.backups[path]:
			return "datastore path not empty"
		case !reuse && d.chunkStores[path]:
			return fmt.Sprintf("unable to create chunk store '%s' subdir %q - EEXIST: File exists", name, path+"/.chunks")
		}
		d.chunkStores[path] = true
		d.datastores[name] = props
		return "OK"
	})
	writeData(w, upid, "")
}

// serveDatastore serves /config/datastore/{name}.
func (d *fakeDatastores) serveDatastore(w http.ResponseWriter, req *http.Request) {
	name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/datastore/")
	params := form(req)
	d.mu.Lock()
	defer d.mu.Unlock()
	props, exists := d.datastores[name]

	switch req.Method {
	case http.MethodGet:
		if !exists {
			writeError(w, "no such datastore '%s'", name)
			return
		}
		writeData(w, props, fakeDigest("datastore.cfg", len(d.datastores)))
	case http.MethodPut:
		if !exists {
			writeError(w, "no such datastore '%s'", name)
			return
		}
		if !checkDelete(w, params, fakeDatastoreDeletable...) {
			return
		}
		for _, key := range []string{"keep-last", "keep-hourly", "keep-daily", "keep-weekly", "keep-monthly", "keep-yearly", "prune-schedule"} {
			if params.Has(key) {
				writeError(w, "parameter verification failed - '%s': datastore prune settings have been replaced by prune jobs", key)
				return
			}
		}
		_, changesMode := params["maintenance-mode"]
		if slices.Contains(params[pbsclient.DeleteParam], "maintenance-mode") {
			changesMode = true
		}
		if current, _ := props["maintenance-mode"].(string); changesMode && fakeMaintenanceType(current) == pbsclient.MaintenanceDelete &&
			fakeMaintenanceType(params.Get("maintenance-mode")) != pbsclient.MaintenanceDelete {
			writeError(w, "datastore is being deleted")
			return
		}
		for _, key := range params[pbsclient.DeleteParam] {
			delete(props, key)
		}
		applyFakeForm(props, params, nil, fakeDatastoreBools)
		if comment, ok := props["comment"].(string); ok && comment == "" {
			delete(props, "comment")
		}
		if mode, ok := params["maintenance-mode"]; ok {
			props["maintenance-mode"] = fakeMaintenanceMode(mode[0])
		}
		writeData(w, nil, "")
	case http.MethodDelete:
		if !exists {
			writeFakeResponse(w, http.StatusNotFound, fmt.Sprintf("datastore '%s' does not exist.", name))
			return
		}
		if !fakeBool(params.Get("keep-job-configs")) {
			for _, jobs := range []map[string]fakeProperties{d.pruneJobs, d.verifyJobs} {
				for id, job := range jobs {
					if job["store"] == name {
						delete(jobs, id)
					}
				}
			}
		}
		destroy := fakeBool(params.Get("destroy-data"))
		upid := d.startTaskLocked("delete-datastore", name, func() string {
			props["maintenance-mode"] = pbsclient.MaintenanceDelete
			failure := d.failDelete
			d.failDelete = ""
			switch failure {
			case "error":
				return "datastore is currently in use"
			case "warnings":
				return "WARNINGS: 1"
			}
			delete(d.datastores, name)
			if destroy {
				delete(d.chunkStores, props["path"].(string))
				delete(d.backups, props["path"].(string))
			}
			return "OK"
		})
		writeData(w, upid, "")
	}
}

// fakeMaintenanceType is the type of a maintenance mode.
func fakeMaintenanceType(mode string) string {
	parsed, _ := pbsclient.ParsePropertyString(mode, "type")
	return parsed["type"]
}

// fakeMaintenanceMode writes a maintenance mode back as PBS does: the type
// bare, the message quoted only when it holds a quote, a backslash or a
// line break.
func fakeMaintenanceMode(mode string) string {
	parsed, _ := pbsclient.ParsePropertyString(mode, "type")
	out := parsed["type"]
	if message, ok := parsed["message"]; ok {
		if strings.ContainsAny(message, "\"\\\n") {
			message = strconv.Quote(message)
		}
		out += ",message=" + message
	}
	return out
}

// createJob serves POST /config/prune and /config/verify.
func (d *fakeDatastores) createJob(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		params := form(req)
		required := []string{"id", "store"}
		if kind == "prune" {
			required = append(required, "schedule")
		}
		if !checkRequired(w, params, required...) {
			return
		}
		id := params.Get("id")
		d.mu.Lock()
		defer d.mu.Unlock()
		jobs := d.jobsLocked(kind)
		if _, exists := jobs[id]; exists {
			writeError(w, "parameter verification failed - 'id': job '%s' already exists.", id)
			return
		}
		props := fakeProperties{}
		applyFakeForm(props, params, fakeJobInts, fakeJobBools)
		if disable, _ := props["disable"].(bool); !disable {
			delete(props, "disable")
		}
		jobs[id] = props
		writeData(w, nil, "")
	}
}

func (d *fakeDatastores) jobsLocked(kind string) map[string]fakeProperties {
	if kind == "prune" {
		return d.pruneJobs
	}
	return d.verifyJobs
}

// serveJob serves /config/prune/{id} and /config/verify/{id}.
func (d *fakeDatastores) serveJob(kind string) http.HandlerFunc {
	section, deletable := "prune", fakePruneJobDeletable
	if kind == "verify" {
		section, deletable = "verification", fakeVerifyJobDeletable
	}
	return func(w http.ResponseWriter, req *http.Request) {
		id := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/"+kind+"/")
		params := form(req)
		d.mu.Lock()
		defer d.mu.Unlock()
		jobs := d.jobsLocked(kind)
		props, exists := jobs[id]
		if !exists {
			writeError(w, "no such %s '%s'", section, id)
			return
		}

		switch req.Method {
		case http.MethodGet:
			writeData(w, props, fakeDigest(section+".cfg", len(jobs)))
		case http.MethodPut:
			if !checkDelete(w, params, deletable...) {
				return
			}
			for _, key := range params[pbsclient.DeleteParam] {
				delete(props, key)
			}
			// A verify job keeps its namespace when an update sends the
			// root; only delete=ns resets it.
			if kind == "verify" && params.Has("ns") && params.Get("ns") == "" {
				params.Del("ns")
			}
			applyFakeForm(props, params, fakeJobInts, fakeJobBools)
			if disable, _ := props["disable"].(bool); !disable {
				delete(props, "disable")
			}
			if ns, ok := props["ns"].(string); ok && ns == "" {
				delete(props, "ns")
			}
			writeData(w, nil, "")
		case http.MethodDelete:
			delete(jobs, id)
			writeData(w, nil, "")
		}
	}
}
