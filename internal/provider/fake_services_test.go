package provider

import (
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeServices serves the services of node localhost as PBS 4 does
// (src/api2/node/services.rs; see internal/pbsclient/services.go):
//
//   - GET /nodes/localhost/services/{service}/state answers a unit's state;
//     400 "unknown service name '<x>'" for a service not in PBS's list,
//     400 "systemctl show failed with exit status: 1" without systemd
//     (noSystemd), null for a unit systemctl describes without a
//     Description (nullState), 403 with stateForbidden.
//   - POST /nodes/localhost/services/{service}/{start,stop,restart,reload}
//     starts a task of fakeTasks, srv<command> with the service as its
//     worker ID — srvreload for a restart of proxmox-backup-proxy, as PBS
//     reloads its proxy instead —, which ends with exit. PBS checks no
//     service name here. Once the task ended OK, the unit is as systemctl
//     leaves it: started and restarted units run, a reload leaves a stopped
//     unit stopped; with crashes, it fails right after. 403 with
//     commandForbidden.
type fakeServices struct {
	tasks *fakeTasks

	mu    sync.Mutex
	units map[string]*fakeUnit

	noSystemd        bool
	nullState        bool
	stateForbidden   bool
	commandForbidden bool
	// exit is the exit status of the commands' tasks; "" is OK.
	exit string
	// running is how many status polls a command's task answers "running";
	// -1 keeps it running for good.
	running int
	// crashes makes a unit fail right after its command.
	crashes bool
	// onCommand runs when a command's task has ended, for its effects
	// elsewhere, such as a proxy that presents another certificate.
	onCommand func(service, command string)
	// commands are the commands PBS ran, "<command> <service>", in order.
	commands []string
}

// fakeUnit is the state of a service's unit.
type fakeUnit struct {
	state     string
	unitState string
}

func newFakeServices(fake *fakePBS) *fakeServices {
	s := &fakeServices{tasks: newFakeTasks(fake), units: map[string]*fakeUnit{}}
	for _, id := range pbsclient.ServiceIDs {
		s.units[id] = &fakeUnit{state: "running", unitState: "enabled"}
	}
	fake.handlePrefix("GET /nodes/localhost/services/", s.serveState)
	fake.handlePrefix("POST /nodes/localhost/services/", s.serveCommand)
	return s
}

// set changes the state of a service's unit.
func (s *fakeServices) set(service, state, unitState string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.units[service] = &fakeUnit{state: state, unitState: unitState}
}

// ran returns the commands PBS ran so far.
func (s *fakeServices) ran() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.commands)
}

// configure changes the fake's settings under its lock.
func (s *fakeServices) configure(change func(s *fakeServices)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	change(s)
}

func (s *fakeServices) serveState(w http.ResponseWriter, req *http.Request) {
	service, rest, _ := strings.Cut(strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/nodes/localhost/services/"), "/")
	if rest != "state" {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.stateForbidden:
		writeFakeResponse(w, http.StatusForbidden, "permission check failed")
	case !slices.Contains(pbsclient.ServiceIDs, service):
		writeError(w, "unknown service name '%s'", service)
	case s.noSystemd:
		writeError(w, "systemctl show failed with exit status: 1")
	case s.nullState:
		writeData(w, nil, "")
	default:
		unit := s.units[service]
		writeData(w, map[string]any{
			"service": service, "name": service, "desc": "the " + service + " unit",
			"state": unit.state, "unit-state": unit.unitState,
		}, "")
	}
}

func (s *fakeServices) serveCommand(w http.ResponseWriter, req *http.Request) {
	service, command, _ := strings.Cut(strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/nodes/localhost/services/"), "/")
	if !slices.Contains([]string{"start", "stop", "restart", "reload"}, command) {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	s.mu.Lock()
	if s.commandForbidden {
		s.mu.Unlock()
		writeFakeResponse(w, http.StatusForbidden, "permission check failed")
		return
	}
	if service == pbsclient.ServiceProxy && command == "restart" {
		command = "reload"
	}
	s.commands = append(s.commands, command+" "+service)
	exit := s.exit
	if exit == "" {
		exit = "OK"
	}
	task := &fakeTask{workerType: "srv" + command, workerID: service, running: s.running, exit: exit}
	s.mu.Unlock()
	task.onStop = func() { s.finish(service, command, exit == "OK") }
	writeData(w, s.tasks.start(task), "")
}

// finish leaves the unit of service as command left it.
func (s *fakeServices) finish(service, command string, ok bool) {
	s.mu.Lock()
	if unit, known := s.units[service]; known && ok {
		stopped := pbsclient.Service{State: unit.state}.Stopped()
		switch {
		case command == "stop":
			unit.state = "dead"
		case command == "reload" && stopped:
			// try-reload-or-restart leaves it as it is.
		default:
			unit.state = "running"
		}
		if s.crashes && command != "stop" {
			unit.state = "failed"
		}
	}
	hook := s.onCommand
	s.mu.Unlock()
	if hook != nil {
		hook(service, command)
	}
}
