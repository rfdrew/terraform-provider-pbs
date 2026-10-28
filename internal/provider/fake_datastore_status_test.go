package provider

import (
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
//     mode "offline" has the error PBS gets opening it instead;
//   - GET /admin/gc/{store} answers the garbage collection status of one
//     datastore, its schedule from the configuration and the rest from gc,
//     as a list of one, or of none for a datastore in gcHidden; it fails
//     for a datastore that is missing, not mounted or offline.
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
	}
	fake := datastores.fake
	fake.handle("GET /config/datastore", s.listConfig)
	fake.handle("GET /admin/datastore", s.listStates)
	fake.handle("GET /status/datastore-usage", s.listUsage)
	fake.handlePrefix("GET /admin/gc/", s.gcStatus)
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
		switch mode, _ := props["maintenance-mode"].(string); {
		case state.mountStatus == pbsclient.MountStatusNotMounted:
			state.openError = "datastore '" + name + "' is not mounted"
		case fakeMaintenanceType(mode) == pbsclient.MaintenanceOffline:
			state.openError = "datastore '" + name + "' is unavailable: offline maintenance mode"
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
		item := map[string]any{"store": state.name, "mount-status": state.mountStatus, "backend-type": state.backendType}
		switch {
		case state.mountStatus == pbsclient.MountStatusNotMounted:
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
