package provider

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeDatastoreStatus serves the lists and states of a fakeDatastores'
// datastores through its fakePBS, as PBS 4.0 and 4.2 do (see
// internal/pbsclient/datastore_status.go):
//
//   - GET /config/datastore lists the datastores' configuration. PBS lists
//     datastores in no particular order, that of a hash map; the fake's
//     lists are in reverse order of name, so that the provider has to sort
//     them;
//   - GET /admin/datastore lists them with their mount status, maintenance
//     mode and backend type;
//   - GET /status/datastore-usage lists their size, use and free space, from
//     usage, with the status of the last garbage collection; a removable
//     datastore that is not mounted has no figures, and one in maintenance
//     mode "offline", or in one PBS sets itself, has the error PBS gets
//     opening it instead;
//   - GET /admin/gc/{store} answers the garbage collection status of one
//     datastore, its schedule from the configuration and the rest from gc,
//     as a list of one, or of none for a datastore in gcHidden; it fails
//     for a datastore that is missing, not mounted, offline, or in a
//     maintenance mode PBS sets itself;
//   - GET /admin/datastore/{store}/status answers the status of one
//     datastore, failing as the garbage collection status does: its
//     figures from usage, zeros for a datastore in figuresHidden, its
//     backend type, and for a datastore on S3 its request statistics,
//     zeros overlaid with s3Stats; with verbose, the counts of its backups,
//     PBS's null for each type overlaid with counts, and the figures of its
//     last garbage collection.
//
// A datastore in figuresHidden is listed without figures, as for a caller
// with a privilege on one of its namespaces only. setRelease has the fake
// answer as an older PBS: without backend-type before 4.1.6, and without
// s3-statistics before 4.1.7.
type fakeDatastoreStatus struct {
	datastores *fakeDatastores

	mu sync.Mutex
	// usage is the total, used and free bytes of each datastore's file
	// system; estimates when each is full.
	usage     map[string][3]int64
	estimates map[string]int64
	// gc is the garbage collection status of each datastore, as PBS answers
	// it, without store and schedule.
	gc       map[string]map[string]any
	gcHidden map[string]bool
	// s3Stats are the request statistics of datastores on S3, and counts
	// the backup counts of datastores, by type, as PBS answers them.
	s3Stats       map[string]map[string]any
	counts        map[string]map[string]any
	figuresHidden map[string]bool
	// noBackendType and noS3Statistics leave out what releases before
	// 4.1.6 and 4.1.7 do not answer; see setRelease.
	noBackendType  bool
	noS3Statistics bool
}

// newFakeDatastoreStatus serves the lists and states of the datastores of
// datastores.
func newFakeDatastoreStatus(datastores *fakeDatastores) *fakeDatastoreStatus {
	s := &fakeDatastoreStatus{
		datastores: datastores,
		usage:      map[string][3]int64{},
		estimates:  map[string]int64{},
		gc:         map[string]map[string]any{},
		gcHidden:   map[string]bool{},

		s3Stats:       map[string]map[string]any{},
		counts:        map[string]map[string]any{},
		figuresHidden: map[string]bool{},
	}
	fake := datastores.fake
	fake.handle("GET /config/datastore", s.listConfig)
	fake.handle("GET /admin/datastore", s.listStates)
	fake.handle("GET /status/datastore-usage", s.listUsage)
	fake.handlePrefix("GET /admin/gc/", s.gcStatus)
	datastores.handleAdmin(http.MethodGet, "status", s.datastoreStatus)
	return s
}

func (s *fakeDatastoreStatus) setUsage(store string, total, used, avail int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usage[store] = [3]int64{total, used, avail}
}

func (s *fakeDatastoreStatus) setEstimate(store string, fullDate int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.estimates[store] = fullDate
}

func (s *fakeDatastoreStatus) setGC(store string, status map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc[store] = status
}

func (s *fakeDatastoreStatus) hideGC(store string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcHidden[store] = true
}

// setS3Statistics sets the request statistics of a datastore on S3, such as
// {"put": 3, "uploaded": 2048}; the others are zero.
func (s *fakeDatastoreStatus) setS3Statistics(store string, stats map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.s3Stats[store] = stats
}

// setCounts sets the backup counts of a datastore, by type, such as
// {"vm": {"groups": 2, "snapshots": 10}}; the other types are null.
func (s *fakeDatastoreStatus) setCounts(store string, counts map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[store] = counts
}

// hideFigures has the lists leave out a datastore's figures, and its status
// answer zeros, as for a caller with a privilege on one of its namespaces
// only.
func (s *fakeDatastoreStatus) hideFigures(store string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.figuresHidden[store] = true
}

// setRelease has the fake answer as PBS release r: without backend-type in
// the usage list and the status of a datastore before 4.1.6, and without
// s3-statistics before 4.1.7.
func (s *fakeDatastoreStatus) setRelease(r pbsRelease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noBackendType = releaseBefore(r, pbs416)
	s.noS3Statistics = releaseBefore(r, pbs417)
}

// releaseBefore reports whether release r is older than threshold.
func releaseBefore(r, threshold pbsRelease) bool {
	return slices.Compare([]int{r.major, r.minor, r.release}, []int{threshold.major, threshold.minor, threshold.release}) < 0
}

// fakeDatastoreState is what the lists say about one datastore: its mount
// status, and the error PBS meets opening it.
type fakeDatastoreState struct {
	name, mountStatus, backendType, openError string
	props                                     fakeProperties
}

// states returns the datastores' states, in reverse order of name.
func (s *fakeDatastoreStatus) states() []fakeDatastoreState {
	d := s.datastores
	d.mu.Lock()
	defer d.mu.Unlock()
	names := make([]string, 0, len(d.datastores))
	for name := range d.datastores {
		names = append(names, name)
	}
	slices.Sort(names)
	slices.Reverse(names)
	states := make([]fakeDatastoreState, 0, len(names))
	for _, name := range names {
		props := cloneProperties(d.datastores[name])
		state := fakeDatastoreState{name: name, mountStatus: pbsclient.MountStatusNonRemovable, props: props,
			backendType: pbsclient.Datastore{Backend: stringProperty(props, "backend")}.BackendType()}
		if device, _ := props["backing-device"].(string); device != "" {
			state.mountStatus = pbsclient.MountStatusNotMounted
			if d.mounted[name] {
				state.mountStatus = pbsclient.MountStatusMounted
			}
		}
		// PBS checks the maintenance mode before the mount; "delete"
		// refuses even a lookup (pbs-api-types' MaintenanceMode::check).
		switch mode := fakeMaintenanceType(stringProperty(props, "maintenance-mode")); {
		case mode == pbsclient.MaintenanceDelete:
			state.openError = "datastore '" + name + "' is unavailable: datastore is being deleted"
		case mode == pbsclient.MaintenanceUnmount:
			state.openError = "datastore '" + name + "' is unavailable: datastore is being unmounted"
		case mode == pbsclient.MaintenanceS3Refresh:
			state.openError = "datastore '" + name + "' is unavailable: S3 refresh maintenance mode: "
		case mode == pbsclient.MaintenanceOffline:
			state.openError = "datastore '" + name + "' is unavailable: offline maintenance mode"
		case state.mountStatus == pbsclient.MountStatusNotMounted:
			state.openError = "datastore '" + name + "' is not mounted"
		}
		states = append(states, state)
	}
	return states
}

// stringProperty is a string property, "" when it is not set.
func stringProperty(props fakeProperties, key string) string {
	v, _ := props[key].(string)
	return v
}

func (s *fakeDatastoreStatus) listConfig(w http.ResponseWriter, _ *http.Request) {
	var list []fakeProperties
	for _, state := range s.states() {
		list = append(list, state.props)
	}
	writeData(w, list, fakeDigest("datastore.cfg", len(list)))
}

func (s *fakeDatastoreStatus) listStates(w http.ResponseWriter, _ *http.Request) {
	list := []map[string]any{}
	for _, state := range s.states() {
		item := map[string]any{"store": state.name, "mount-status": state.mountStatus, "backend-type": state.backendType}
		if comment := stringProperty(state.props, "comment"); comment != "" {
			item["comment"] = comment
		}
		if mode := stringProperty(state.props, "maintenance-mode"); mode != "" {
			item["maintenance"] = mode
		}
		list = append(list, item)
	}
	writeData(w, list, "")
}

func (s *fakeDatastoreStatus) listUsage(w http.ResponseWriter, _ *http.Request) {
	states := s.states()
	s.mu.Lock()
	defer s.mu.Unlock()
	list := []map[string]any{}
	for _, state := range states {
		item := map[string]any{"store": state.name, "mount-status": state.mountStatus}
		if !s.noBackendType {
			item["backend-type"] = state.backendType
		}
		switch {
		case state.mountStatus == pbsclient.MountStatusNotMounted, s.figuresHidden[state.name]:
		case state.openError != "":
			item["error"] = state.openError
		default:
			usage := s.usage[state.name]
			item["total"], item["used"], item["avail"] = usage[0], usage[1], usage[2]
			if estimate, ok := s.estimates[state.name]; ok {
				item["estimated-full-date"] = estimate
			}
			item["gc-status"] = s.gcFiguresLocked(state.name)
		}
		list = append(list, item)
	}
	writeData(w, list, "")
}

// gcFiguresLocked is the status of a datastore's last garbage collection:
// zeros before the first.
func (s *fakeDatastoreStatus) gcFiguresLocked(store string) map[string]any {
	figures := map[string]any{}
	for _, key := range []string{"index-file-count", "index-data-bytes", "disk-bytes", "disk-chunks", "removed-bytes",
		"removed-chunks", "pending-bytes", "pending-chunks", "removed-bad", "still-bad"} {
		figures[key] = 0
	}
	for key, value := range s.gc[store] {
		figures[key] = value
	}
	return figures
}

func (s *fakeDatastoreStatus) gcStatus(w http.ResponseWriter, req *http.Request) {
	store := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/admin/gc/")
	idx := slices.IndexFunc(s.states(), func(state fakeDatastoreState) bool { return state.name == store })
	if idx < 0 {
		writeError(w, "no such datastore '%s'", store)
		return
	}
	state := s.states()[idx]
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gcHidden[store] {
		writeData(w, []any{}, "")
		return
	}
	if state.openError != "" {
		writeError(w, "%s", state.openError)
		return
	}
	status := s.gcFiguresLocked(store)
	status["store"] = store
	if schedule := stringProperty(state.props, "gc-schedule"); schedule != "" {
		status["schedule"] = schedule
	}
	writeData(w, []any{status}, "")
}

// datastoreStatus serves GET /admin/datastore/{store}/status.
func (s *fakeDatastoreStatus) datastoreStatus(w http.ResponseWriter, req *http.Request) {
	store := adminStore(req)
	states := s.states()
	idx := slices.IndexFunc(states, func(state fakeDatastoreState) bool { return state.name == store })
	if idx < 0 {
		writeError(w, "no such datastore '%s'", store)
		return
	}
	state := states[idx]
	if state.openError != "" {
		writeError(w, "%s", state.openError)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	usage := s.usage[store]
	if s.figuresHidden[store] {
		usage = [3]int64{}
	}
	status := map[string]any{"total": usage[0], "used": usage[1], "avail": usage[2]}
	if !s.noBackendType {
		status["backend-type"] = state.backendType
	}
	if state.backendType == pbsclient.BackendS3 && !s.noS3Statistics {
		stats := map[string]any{}
		for _, key := range []string{"downloaded", "uploaded", "get", "post", "put", "head", "delete"} {
			stats[key] = 0
		}
		maps.Copy(stats, s.s3Stats[store])
		status["s3-statistics"] = stats
	}
	if fakeBool(req.URL.Query().Get("verbose")) {
		counts := map[string]any{"ct": nil, "host": nil, "vm": nil, "other": nil}
		maps.Copy(counts, s.counts[store])
		status["counts"] = counts
		status["gc-status"] = s.gcFiguresLocked(store)
	}
	writeData(w, status, "")
}
