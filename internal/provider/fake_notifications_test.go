package provider

import (
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// fakeNotifications keeps SMTP endpoints and matchers in memory and serves
// PBS's notification API for them through a fakePBS, with the behaviour of
// proxmox-notify (see internal/pbsclient/notifications.go):
//
//   - endpoints and matchers share one namespace, the built-in mail-to-root
//     and default-matcher included, which always exist: DELETE resets one,
//     and a read reports "origin" builtin while it has its built-in
//     settings and modified-builtin once it differs;
//   - an SMTP endpoint needs a recipient, mailto or mailto-user, and keeps
//     its password apart, never returned; PBS refuses to delete one a
//     matcher targets;
//   - a matcher's targets must be endpoints; its match-field entries need
//     an exact: or regex: prefix, and PBS writes the values of exact: and
//     match-severity back without spaces around the commas;
//   - an update's delete accepts only the names PBS accepts;
//   - missing entries are 404 "endpoint 'x' not found" and "matcher 'x' not
//     found", on GET, PUT and DELETE.
//
// Tests set up state with addSMTP and addMatcher, and look at it with entry
// and password.
type fakeNotifications struct {
	fake *fakePBS

	mu sync.Mutex
	// entries are the sections notifications.cfg holds, by name; the
	// built-in ones only once they differ from their built-in settings.
	entries   map[string]fakeNotificationEntry
	passwords map[string]string
}

// fakeNotificationEntry is one section of notifications.cfg.
type fakeNotificationEntry struct {
	kind  string // smtp, sendmail or matcher
	props fakeProperties
}

// fakeBuiltinNotifications are PBS's built-in entries, as proxmox-notify's
// PBS context defines them.
var fakeBuiltinNotifications = map[string]fakeNotificationEntry{
	"mail-to-root": {kind: "sendmail", props: fakeProperties{
		"comment":     "Send mails to root@pam's email address",
		"mailto-user": []string{"root@pam"},
	}},
	defaultMatcher: {kind: "matcher", props: fakeProperties{
		"mode":           "all",
		"invert-match":   true,
		"match-field":    []string{"exact:type=prune"},
		"match-severity": []string{"info"},
		"target":         []string{"mail-to-root"},
		"comment":        "Route everything but successful prune job notifications to mail-to-root",
	}},
}

// What each kind of section stores as a list or a bool, and what its updates
// may delete.
var (
	fakeNotificationLists = []string{"mailto", "mailto-user", "target", "match-severity", "match-field", "match-calendar"}
	fakeNotificationBools = []string{"disable", "invert-match"}
	fakeNotificationInts  = []string{"port"}
	fakeSMTPDeletable     = []string{"author", "comment", "disable", "mailto", "mailto-user", "password", "port", "username"}
	fakeMatcherDeletable  = []string{"comment", "disable", "invert-match", "match-calendar", "match-field", "match-severity", "mode", "target"}
)

// newFakeNotifications serves the notification API from fake.
func newFakeNotifications(fake *fakePBS) *fakeNotifications {
	n := &fakeNotifications{fake: fake, entries: map[string]fakeNotificationEntry{}, passwords: map[string]string{}}
	fake.handle("POST /config/notifications/endpoints/smtp", n.create("smtp"))
	fake.handle("POST /config/notifications/matchers", n.create("matcher"))
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		fake.handlePrefix(method+" /config/notifications/endpoints/smtp/", n.serve("smtp"))
		fake.handlePrefix(method+" /config/notifications/matchers/", n.serve("matcher"))
	}
	return n
}

// --- test helpers -------------------------------------------------------------

func (n *fakeNotifications) addSMTP(name string, props fakeProperties, password string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.entries[name] = fakeNotificationEntry{kind: "smtp", props: cloneProperties(props)}
	if password != "" {
		n.passwords[name] = password
	}
}

func (n *fakeNotifications) addMatcher(name string, props fakeProperties) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.entries[name] = fakeNotificationEntry{kind: "matcher", props: cloneProperties(props)}
}

// entry returns an entry as a read reports it, with its origin.
func (n *fakeNotifications) entry(name string) (fakeProperties, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	e, ok := n.lookupLocked(name)
	return e.props, ok
}

func (n *fakeNotifications) password(name string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p, ok := n.passwords[name]
	return p, ok
}

// --- serving ------------------------------------------------------------------

// lookupLocked returns an entry as a read reports it: the section in the file,
// or the built-in one, with its origin.
func (n *fakeNotifications) lookupLocked(name string) (fakeNotificationEntry, bool) {
	builtin, isBuiltin := fakeBuiltinNotifications[name]
	e, inFile := n.entries[name]
	switch {
	case !inFile && !isBuiltin:
		return fakeNotificationEntry{}, false
	case !inFile:
		e = builtin
	}
	props := cloneProperties(e.props)
	switch {
	case !isBuiltin:
		props["origin"] = pbsclient.OriginUserCreated
	case reflect.DeepEqual(e.props, builtin.props):
		props["origin"] = pbsclient.OriginBuiltin
	default:
		props["origin"] = pbsclient.OriginModifiedBuiltin
	}
	props["name"] = name
	return fakeNotificationEntry{kind: e.kind, props: props}, true
}

// sectionLocked returns the section an update changes: the one in the file,
// or a copy of the built-in one.
func (n *fakeNotifications) sectionLocked(name string) fakeNotificationEntry {
	if e, ok := n.entries[name]; ok {
		return fakeNotificationEntry{kind: e.kind, props: cloneProperties(e.props)}
	}
	builtin := fakeBuiltinNotifications[name]
	return fakeNotificationEntry{kind: builtin.kind, props: cloneProperties(builtin.props)}
}

func notFoundText(kind, name string) string {
	if kind == "matcher" {
		return fmt.Sprintf("matcher '%s' not found", name)
	}
	return fmt.Sprintf("endpoint '%s' not found", name)
}

func (n *fakeNotifications) create(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		params := form(req)
		required := []string{"name"}
		if kind == "smtp" {
			required = append(required, "server", "from-address")
		}
		if !checkRequired(w, params, required...) {
			return
		}
		name := params.Get("name")
		n.mu.Lock()
		defer n.mu.Unlock()
		if _, exists := n.lookupLocked(name); exists {
			writeError(w, "Cannot create '%s', an entity with the same name already exists", name)
			return
		}
		e := fakeNotificationEntry{kind: kind, props: fakeProperties{}}
		if !n.applyLocked(w, &e, params) {
			return
		}
		n.entries[name] = e
		if kind == "smtp" {
			n.passwords[name] = params.Get("password")
			if !params.Has("password") {
				delete(n.passwords, name)
			}
		}
		writeData(w, nil, "")
	}
}

// applyLocked applies an update's or a create's parameters to e, after the
// checks PBS makes, and reports whether they passed.
func (n *fakeNotifications) applyLocked(w http.ResponseWriter, e *fakeNotificationEntry, params map[string][]string) bool {
	for _, key := range params[pbsclient.DeleteParam] {
		delete(e.props, key)
	}
	for key, values := range params {
		switch {
		case key == pbsclient.DeleteParam || key == pbsclient.DigestParam || key == "name" || key == "password" || key == "origin":
		case slices.Contains(fakeNotificationLists, key):
			e.props[key] = append([]string(nil), values...)
		case slices.Contains(fakeNotificationBools, key):
			e.props[key] = fakeBool(values[0])
		case slices.Contains(fakeNotificationInts, key):
			var port int64
			_, _ = fmt.Sscan(values[0], &port)
			e.props[key] = port
		default:
			e.props[key] = strings.TrimSpace(values[0])
		}
	}

	switch e.kind {
	case "smtp":
		if len(stringList(e.props["mailto"])) == 0 && len(stringList(e.props["mailto-user"])) == 0 {
			writeError(w, "must at least provide one recipient, either in mailto or in mailto-user")
			return false
		}
	case "matcher":
		var fields []string
		for _, field := range stringList(e.props["match-field"]) {
			kind, rest, ok := strings.Cut(field, ":")
			if !ok || (kind != "exact" && kind != "regex") {
				writeError(w, "invalid match-field statement: %s", field)
				return false
			}
			if kind == "exact" {
				name, values, _ := strings.Cut(rest, "=")
				parts := strings.Split(values, ",")
				for i := range parts {
					parts[i] = strings.TrimSpace(parts[i])
				}
				field = "exact:" + name + "=" + strings.Join(parts, ",")
			}
			fields = append(fields, field)
		}
		if fields != nil {
			e.props["match-field"] = fields
		}
		var severities []string
		for _, entry := range stringList(e.props["match-severity"]) {
			parts := strings.Split(entry, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			severities = append(severities, strings.Join(parts, ","))
		}
		if severities != nil {
			e.props["match-severity"] = severities
		}
		if _, sent := params["target"]; sent {
			for _, target := range stringList(e.props["target"]) {
				if t, ok := n.lookupLocked(target); !ok || t.kind == "matcher" {
					writeFakeResponse(w, http.StatusNotFound, fmt.Sprintf("endpoint '%s' does not exist", target))
					return false
				}
			}
		}
	}
	return true
}

func stringList(v any) []string {
	list, _ := v.([]string)
	return list
}

// serve serves /config/notifications/endpoints/smtp/{name} and
// /config/notifications/matchers/{name}.
func (n *fakeNotifications) serve(kind string) http.HandlerFunc {
	prefix, deletable := "/config/notifications/endpoints/smtp/", fakeSMTPDeletable
	if kind == "matcher" {
		prefix, deletable = "/config/notifications/matchers/", fakeMatcherDeletable
	}
	return func(w http.ResponseWriter, req *http.Request) {
		name := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+prefix)
		params := form(req)
		n.mu.Lock()
		defer n.mu.Unlock()
		e, exists := n.lookupLocked(name)
		if !exists || e.kind != kind {
			writeFakeResponse(w, http.StatusNotFound, notFoundText(kind, name))
			return
		}

		switch req.Method {
		case http.MethodGet:
			writeData(w, e.props, fakeDigest("notifications.cfg", len(n.entries)))
		case http.MethodPut:
			if !checkDelete(w, params, deletable...) {
				return
			}
			section := n.sectionLocked(name)
			if !n.applyLocked(w, &section, params) {
				return
			}
			n.entries[name] = section
			if kind == "smtp" {
				if slices.Contains(params[pbsclient.DeleteParam], "password") {
					delete(n.passwords, name)
				}
				if params.Has("password") {
					n.passwords[name] = params.Get("password")
				}
			}
			writeData(w, nil, "")
		case http.MethodDelete:
			if kind == "smtp" {
				var users []string
				for matcherName := range n.namesLocked() {
					if m, _ := n.lookupLocked(matcherName); m.kind == "matcher" && slices.Contains(stringList(m.props["target"]), name) {
						users = append(users, matcherName)
					}
				}
				if len(users) > 0 {
					sort.Strings(users)
					writeError(w, "cannot delete '%s', referenced by: %s", name, strings.Join(users, ", "))
					return
				}
				delete(n.passwords, name)
			}
			delete(n.entries, name)
			writeData(w, nil, "")
		}
	}
}

// namesLocked returns the names of every entry, built-in ones included.
func (n *fakeNotifications) namesLocked() map[string]bool {
	names := map[string]bool{}
	for name := range n.entries {
		names[name] = true
	}
	for name := range fakeBuiltinNotifications {
		names[name] = true
	}
	return names
}
