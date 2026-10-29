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
//   - missing objects answer the 400s and 404s PBS answers;
//   - a removable datastore, with a backing-device, has a path relative to
//     its device, which must be connected — in devices — for the create task
//     to mount it, and stays mounted after; destroy-data needs it mounted,
//     and gc-on-unmount is refused for a datastore that is not removable;
//   - a datastore on S3, with a backend "type=s3,client=<endpoint>,
//     bucket=<bucket>" in any key order, its type bare or not, keeps its
//     path as a local cache, and its backups in the bucket under its name,
//     as PBS 4.2.8's src/api2/config/datastore.rs and
//     pbs-datastore/src/datastore.rs have it. POST fails with 400 "no '<client>' in config" for an endpoint PBS does
//     not have, and "failed to access bucket: bucket does not exist or no
//     permission to access it" for a bucket the endpoint does not reach,
//     before any task. The task fails when the bucket marks the datastore in
//     use by a host, unless overwrite-in-use, and without reuse-datastore on
//     a local chunk store, with the EEXIST on .chunks: there is no check
//     that the directory is empty. With reuse-datastore, it saves the
//     datastore in maintenance mode s3-refresh, whatever mode was sent, and
//     refreshes it from the bucket, which clears the mode; when failRefresh
//     is set, the refresh fails and the mode stays. The task marks the
//     datastore in use by this host, fakeTaskNode. A PUT cannot change
//     backend, path or backing-device. The delete task needs the bucket
//     reachable — or it fails, in maintenance mode "delete" — and deletes
//     the in-use mark, and with destroy-data the backups in the bucket too.
//
// Tests set up state with addDatastore, addPruneJob, addVerifyJob,
// addChunkStore, connectDevice, setMounted, addS3Bucket, setBucketReachable,
// addS3Marker and addS3Backups, and look at it with datastore, pruneJob,
// verifyJob, hasChunkStore, isMounted, s3Marker and hasS3Backups.
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
	// devices are the file system UUIDs of the connected removable disks,
	// and mounted the removable datastores mounted.
	devices map[string]bool
	mounted map[string]bool
	// s3Buckets are the S3 endpoints PBS has, by ID, with the buckets each
	// knows: true for one it reaches, false for one that is gone or that
	// its access key may not use. s3Markers are the in-use marks of the
	// datastores in the buckets, with the host each names, and s3Backups
	// the datastores with backups in a bucket, both by s3ObjectKey.
	s3Buckets map[string]map[string]bool
	s3Markers map[string]string
	s3Backups map[string]bool
	// failRefresh makes the S3 refresh of the next create-datastore task
	// that reuses a datastore on S3 fail.
	failRefresh bool
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
		devices:     map[string]bool{},
		mounted:     map[string]bool{},
		s3Buckets:   map[string]map[string]bool{},
		s3Markers:   map[string]string{},
		s3Backups:   map[string]bool{},
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
	if _, ok := props["path"].(string); ok {
		d.chunkStores[chunkStoreKey(props)] = true
	}
}

// connectDevice connects a removable disk with a file system of the given
// UUID, or disconnects it.
func (d *fakeDatastores) connectDevice(uuid string, connected bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.devices[uuid] = connected
}

// setMounted mounts or unmounts a removable datastore, as PBS's mount and
// unmount tasks do.
func (d *fakeDatastores) setMounted(name string, mounted bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mounted[name] = mounted
}

func (d *fakeDatastores) isMounted(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mounted[name]
}

// chunkStoreKey is where a datastore's chunk store is: its path, or for a
// removable datastore its device and the path on it.
func chunkStoreKey(props fakeProperties) string {
	path, _ := props["path"].(string)
	if device, _ := props["backing-device"].(string); device != "" {
		return device + ":" + path
	}
	return path
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

// addS3Bucket gives PBS an S3 endpoint, if it does not have it yet, and a
// bucket the endpoint reaches.
func (d *fakeDatastores) addS3Bucket(endpoint, bucket string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.s3Buckets[endpoint] == nil {
		d.s3Buckets[endpoint] = map[string]bool{}
	}
	d.s3Buckets[endpoint][bucket] = true
}

// setBucketReachable makes a bucket of an endpoint reachable or not, as
// when it is deleted or the endpoint's access key loses the right to use it.
func (d *fakeDatastores) setBucketReachable(endpoint, bucket string, reachable bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.s3Buckets[endpoint][bucket] = reachable
}

// s3ObjectKey is where the objects of datastore name are: its name is the
// prefix of their keys in the bucket.
func s3ObjectKey(bucket, name string) string {
	return bucket + "/" + name
}

// addS3Marker marks datastore name in bucket in use by host, as PBS does
// when it creates the datastore.
func (d *fakeDatastores) addS3Marker(bucket, name, host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.s3Markers[s3ObjectKey(bucket, name)] = host
}

// s3Marker returns the host that marks datastore name in bucket in use.
func (d *fakeDatastores) s3Marker(bucket, name string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	host, ok := d.s3Markers[s3ObjectKey(bucket, name)]
	return host, ok
}

// addS3Backups puts backups of datastore name in bucket, as a datastore on
// S3 leaves when it is deleted without destroy-data.
func (d *fakeDatastores) addS3Backups(bucket, name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.s3Backups[s3ObjectKey(bucket, name)] = true
}

func (d *fakeDatastores) hasS3Backups(bucket, name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.s3Backups[s3ObjectKey(bucket, name)]
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
	name, path, device := params.Get("name"), params.Get("path"), params.Get("backing-device")
	reuse := fakeBool(params.Get("reuse-datastore"))
	// PBS verifies backend against its schema before the handler runs.
	backend, refusal := fakeParseBackend(params.Get("backend"))
	if refusal != "" {
		writeError(w, "parameter verification failed - 'backend': %s", refusal)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.datastores[name]; exists {
		writeError(w, "parameter verification failed - 'name': datastore '%s' already exists.", name)
		return
	}
	switch {
	case device == "" && !strings.HasPrefix(path, "/"):
		writeError(w, "parameter verification failed - 'path': expected an absolute path, '%s' is not", path)
		return
	case device != "" && strings.HasPrefix(path, "/"):
		writeError(w, "parameter verification failed - 'path': expected a relative on-device path, '%s' is not", path)
		return
	case device == "" && fakeBool(params.Get("gc-on-unmount")):
		writeError(w, "parameter verification failed - 'gc-on-unmount': only supported on removable datastores")
		return
	}
	// Before the task, PBS builds the S3 client of the endpoint and checks
	// that it reaches the bucket.
	if backend.s3 {
		buckets, ok := d.s3Buckets[backend.client]
		if !ok {
			writeError(w, "no '%s' in config", backend.client)
			return
		}
		if !buckets[backend.bucket] {
			writeError(w, "failed to access bucket: bucket does not exist or no permission to access it")
			return
		}
	}
	props := fakeProperties{}
	applyFakeForm(props, params, nil, fakeDatastoreBools, "reuse-datastore", "overwrite-in-use")
	key := chunkStoreKey(props)
	upid := d.startTaskLocked("create-datastore", name, func() string {
		if backend.s3 {
			return d.createS3DatastoreLocked(name, path, backend.bucket, props, reuse, fakeBool(params.Get("overwrite-in-use")))
		}
		switch {
		case device != "" && !d.devices[device]:
			return fmt.Sprintf("mounting to tmp path failed: command \"mount\" \"UUID=%s\" \"/run/proxmox-backup/mount/0a1b\" "+
				"failed - status code: 1 - mount: /run/proxmox-backup/mount/0a1b: can't find UUID=%s.", device, device)
		case reuse && !d.chunkStores[key]:
			return fmt.Sprintf("unable to open existing chunk store path %q - ENOENT: No such file or directory", path+"/.chunks")
		case !reuse && d.backups[key]:
			return "datastore path not empty"
		case !reuse && d.chunkStores[key]:
			return fmt.Sprintf("unable to create chunk store '%s' subdir %q - EEXIST: File exists", name, path+"/.chunks")
		}
		d.chunkStores[key] = true
		d.datastores[name] = props
		if device != "" {
			d.mounted[name] = true
		}
		return "OK"
	})
	writeData(w, upid, "")
}

// fakeBackend is a datastore's backend: on S3, with the endpoint and the
// bucket, or not, for a datastore in a directory or on a removable disk.
type fakeBackend struct {
	s3             bool
	client, bucket string
}

// fakeParseBackend reads a backend as PBS's schema does, with type as its
// default key and filesystem as the default type. It returns the text PBS
// refuses the backend with, or "".
func fakeParseBackend(s string) (fakeBackend, string) {
	if s == "" {
		return fakeBackend{}, ""
	}
	parsed, err := pbsclient.ParsePropertyString(s, "type")
	if err != nil {
		return fakeBackend{}, err.Error()
	}
	for key := range parsed {
		if !slices.Contains([]string{"type", "client", "bucket", "max-cache-size"}, key) {
			return fakeBackend{}, fmt.Sprintf("unknown key %q", key)
		}
	}
	switch typ := parsed["type"]; typ {
	case "", pbsclient.BackendFilesystem:
		for _, key := range []string{"client", "bucket", "max-cache-size"} {
			if _, ok := parsed[key]; ok {
				return fakeBackend{}, fmt.Sprintf("additional option %s, not allowed for backend type filesystem", key)
			}
		}
		return fakeBackend{}, ""
	case pbsclient.BackendS3:
		for _, key := range []string{"client", "bucket"} {
			if parsed[key] == "" {
				return fakeBackend{}, fmt.Sprintf("missing option %s, required for backend type s3", key)
			}
		}
		return fakeBackend{s3: true, client: parsed["client"], bucket: parsed["bucket"]}, ""
	default:
		return fakeBackend{}, fmt.Sprintf("unknown variant `%s`, expected `filesystem` or `s3`", typ)
	}
}

// createS3DatastoreLocked runs the create-datastore task of a datastore on
// S3 and returns its exit status. Reusing the datastore, PBS saves it, in
// maintenance mode s3-refresh, before it refreshes the local cache from the
// bucket, so that a failed refresh leaves it configured in that mode.
func (d *fakeDatastores) createS3DatastoreLocked(name, path, bucket string, props fakeProperties, reuse, overwrite bool) string {
	object := s3ObjectKey(bucket, name)
	if host, inUse := d.s3Markers[object]; inUse && !overwrite {
		return "Bucket already contains datastore in use by host " + host
	}
	// Reusing the datastore empties the local cache. Otherwise creating
	// .chunks fails on a chunk store left there, but nothing else in the
	// directory is in the way.
	if !reuse && d.chunkStores[path] {
		return fmt.Sprintf("unable to create chunk store '%s' subdir %q - EEXIST: File exists", name, path+"/.chunks")
	}
	d.chunkStores[path] = true
	d.s3Markers[object] = fakeTaskNode
	if !reuse {
		d.datastores[name] = props
		return "OK"
	}
	props["maintenance-mode"] = pbsclient.MaintenanceS3Refresh
	d.datastores[name] = props
	if d.failRefresh {
		d.failRefresh = false
		return "failed to list object: unexpected status code 503"
	}
	delete(props, "maintenance-mode")
	return "OK"
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
		// PBS sets these at creation only, so an update's schema does not
		// have them.
		for _, key := range []string{"backend", "path", "backing-device"} {
			if params.Has(key) {
				writeError(w, "parameter verification failed - '%s': schema does not allow additional properties.", key)
				return
			}
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
		if device, _ := props["backing-device"].(string); device == "" && fakeBool(params.Get("gc-on-unmount")) {
			writeError(w, "parameter verification failed - 'gc-on-unmount': only supported on removable datastores")
			return
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
		destroy := fakeBool(params.Get("destroy-data"))
		if device, _ := props["backing-device"].(string); device != "" && destroy && !d.mounted[name] {
			writeError(w, "cannot destroy data on '%s' unless the datastore is mounted", name)
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
			// On S3, PBS deletes the datastore's objects in the bucket with
			// destroy-data, and its in-use mark without, and fails when it
			// cannot reach the bucket.
			backendProperty, _ := props["backend"].(string)
			if backend, _ := fakeParseBackend(backendProperty); backend.s3 {
				buckets, ok := d.s3Buckets[backend.client]
				switch {
				case !ok:
					return fmt.Sprintf("no '%s' in config: no such s3-endpoint '%s'", backend.client, backend.client)
				case !buckets[backend.bucket] && destroy:
					return "deleting objects failed"
				case !buckets[backend.bucket]:
					return "failed to delete in-use marker: unexpected status code 403"
				}
				object := s3ObjectKey(backend.bucket, name)
				delete(d.s3Markers, object)
				if destroy {
					delete(d.s3Backups, object)
				}
			}
			delete(d.datastores, name)
			delete(d.mounted, name)
			if destroy {
				delete(d.chunkStores, chunkStoreKey(props))
				delete(d.backups, chunkStoreKey(props))
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
