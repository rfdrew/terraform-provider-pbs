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

// fakeNotifications keeps notification endpoints — sendmail, SMTP, Gotify
// and webhook — and matchers in memory and serves PBS's notification API for
// them through a fakePBS, with the behaviour of proxmox-notify (see
// internal/pbsclient/notifications.go):
//
//   - endpoints and matchers share one namespace, the built-in mail-to-root
//     and default-matcher included, which always exist: DELETE resets one,
//     and a read reports "origin" builtin while it has its built-in
//     settings and modified-builtin once it differs;
//   - a sendmail or SMTP endpoint needs a recipient, mailto or mailto-user;
//     an SMTP password and a Gotify token are kept apart, never returned;
//     PBS refuses to delete an endpoint a matcher targets, unless it is
//     built in;
//   - a webhook's secrets are kept apart too, and a read returns their names
//     only. An update's secret replaces them all: an entry without a value
//     keeps the one the endpoint has, under the same name, and one the
//     endpoint does not have is refused, as is a name given twice. An
//     update's headers must have a base64 value; a create checks neither;
//   - a matcher's targets must be endpoints; its match-field entries need
//     an exact: or regex: prefix, and PBS writes the values of exact: and
//     match-severity back without spaces around the commas;
//   - an update's delete accepts only the names PBS accepts;
//   - missing entries are 404 "endpoint 'x' not found" and "matcher 'x' not
//     found", on GET, PUT and DELETE;
//   - GET /config/notifications/targets lists every endpoint; POST
//     .../targets/{name}/test records a test notification, sent even
//     through a disabled endpoint, and fails as testFailures says;
//   - the matcher fields and their values are fixed.
//
// Tests set up state with addSMTP, addEndpoint and addMatcher, and look at it
// with entry, password, secrets and tested.
type fakeNotifications struct {
	fake *fakePBS

	mu sync.Mutex
	// entries are the sections notifications.cfg holds, by name; the
	// built-in ones only once they differ from their built-in settings.
	entries map[string]fakeNotificationEntry
	// passwords are the SMTP passwords and Gotify tokens, by endpoint.
	passwords map[string]string
	// webhookSecrets are each webhook's secrets, as property strings with
	// their base64 values.
	webhookSecrets map[string][]string
	// tests are the endpoints test notifications went through, in order;
	// testFailures maps an endpoint to the error its test fails with.
	tests        []string
	testFailures map[string]string
}

// fakeNotificationEntry is one section of notifications.cfg.
type fakeNotificationEntry struct {
	kind  string // sendmail, smtp, gotify, webhook or matcher
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

// The kinds of endpoint, in the order PBS lists targets.
var fakeEndpointKinds = []string{"gotify", "sendmail", "smtp", "webhook"}

// What each kind of section stores as a list, a bool or an int; what its
// create requires; and what its updates may delete.
var (
	fakeNotificationLists    = []string{"mailto", "mailto-user", "target", "match-severity", "match-field", "match-calendar", "header"}
	fakeNotificationBools    = []string{"disable", "invert-match"}
	fakeNotificationInts     = []string{"port"}
	fakeNotificationRequired = map[string][]string{
		"sendmail": {"name"},
		"smtp":     {"name", "server", "from-address"},
		"gotify":   {"name", "server", "token"},
		"webhook":  {"name", "url", "method"},
		"matcher":  {"name"},
	}
	fakeNotificationDeletable = map[string][]string{
		"sendmail": {"author", "comment", "disable", "from-address", "mailto", "mailto-user"},
		"smtp":     {"author", "comment", "disable", "mailto", "mailto-user", "password", "port", "username"},
		"gotify":   {"comment", "disable"},
		"webhook":  {"body", "comment", "disable", "header", "secret"},
		"matcher":  {"comment", "disable", "invert-match", "match-calendar", "match-field", "match-severity", "mode", "target"},
	}
)

// newFakeNotifications serves the notification API from fake.
func newFakeNotifications(fake *fakePBS) *fakeNotifications {
	n := &fakeNotifications{
		fake: fake, entries: map[string]fakeNotificationEntry{}, passwords: map[string]string{},
		webhookSecrets: map[string][]string{}, testFailures: map[string]string{},
	}
	for _, kind := range append(slices.Clone(fakeEndpointKinds), "matcher") {
		fake.handle("POST "+fakeNotificationPath(kind), n.create(kind))
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			fake.handlePrefix(method+" "+fakeNotificationPath(kind)+"/", n.serve(kind))
		}
	}
	fake.handle("GET /config/notifications/targets", n.listTargets)
	fake.handlePrefix("POST /config/notifications/targets/", n.test)
	fake.handle("GET /config/notifications/matcher-fields", func(w http.ResponseWriter, _ *http.Request) {
		writeData(w, []map[string]string{{"name": "datastore"}, {"name": "hostname"}, {"name": "job-id"},
			{"name": "media-pool"}, {"name": "type"}}, "")
	})
	fake.handle("GET /config/notifications/matcher-field-values", func(w http.ResponseWriter, _ *http.Request) {
		writeData(w, []map[string]string{
			{"field": "datastore", "value": "store1", "comment": "Main datastore"},
			{"field": "hostname", "value": "pbs"},
			{"field": "job-id", "value": "daily-prune"},
			{"field": "type", "value": "gc"},
			{"field": "type", "value": "prune"},
		}, "")
	})
	return n
}

// fakeNotificationPath is where entries of a kind live.
func fakeNotificationPath(kind string) string {
	if kind == "matcher" {
		return "/config/notifications/matchers"
	}
	return "/config/notifications/endpoints/" + kind
}

// --- test helpers -------------------------------------------------------------

func (n *fakeNotifications) addSMTP(name string, props fakeProperties, password string) {
	n.addEndpoint("smtp", name, props, password)
}

// addEndpoint adds an endpoint of kind with its secret: the SMTP password
// or the Gotify token.
func (n *fakeNotifications) addEndpoint(kind, name string, props fakeProperties, secret string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.entries[name] = fakeNotificationEntry{kind: kind, props: cloneProperties(props)}
	if secret != "" {
		n.passwords[name] = secret
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

// password returns an SMTP endpoint's password or a Gotify endpoint's token.
func (n *fakeNotifications) password(name string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p, ok := n.passwords[name]
	return p, ok
}

// secrets returns a webhook's secrets, by name, with their values decoded.
func (n *fakeNotifications) secrets(name string) map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]string{}
	for _, s := range n.webhookSecrets[name] {
		secretName, value, _ := pbsclient.ParseNotificationKeyValue(s)
		out[secretName] = ""
		if value != nil {
			out[secretName] = *value
		}
	}
	return out
}

// tested returns the endpoints test notifications went through.
func (n *fakeNotifications) tested() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.tests)
}

// failTests makes the test notifications of endpoint fail with message, or
// succeed again for "".
func (n *fakeNotifications) failTests(endpoint, message string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.testFailures[endpoint] = message
	if message == "" {
		delete(n.testFailures, endpoint)
	}
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
		if !checkRequired(w, params, fakeNotificationRequired[kind]...) {
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
		switch kind {
		case "smtp":
			n.passwords[name] = params.Get("password")
			if !params.Has("password") {
				delete(n.passwords, name)
			}
		case "gotify":
			n.passwords[name] = params.Get("token")
		case "webhook":
			n.webhookSecrets[name] = slices.Clone(params["secret"])
		}
		writeData(w, nil, "")
	}
}

// applyLocked applies an update's or a create's parameters to e, after the
// checks PBS makes, and reports whether they passed. Secrets are not
// properties of the section.
func (n *fakeNotifications) applyLocked(w http.ResponseWriter, e *fakeNotificationEntry, params map[string][]string) bool {
	for _, key := range params[pbsclient.DeleteParam] {
		delete(e.props, key)
	}
	for key, values := range params {
		switch {
		case slices.Contains([]string{pbsclient.DeleteParam, pbsclient.DigestParam, "name", "password", "token", "secret", "origin"}, key):
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
	case "smtp", "sendmail":
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

// serve serves the entries of one kind under their path.
func (n *fakeNotifications) serve(kind string) http.HandlerFunc {
	prefix := fakeNotificationPath(kind) + "/"
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
			if kind == "webhook" {
				var names []string
				for _, s := range n.webhookSecrets[name] {
					secretName, _, _ := pbsclient.ParseNotificationKeyValue(s)
					names = append(names, pbsclient.FormatNotificationKeyValue(secretName, nil))
				}
				if names != nil {
					e.props["secret"] = names
				}
			}
			writeData(w, e.props, fakeDigest("notifications.cfg", len(n.entries)))
		case http.MethodPut:
			if !checkDelete(w, params, fakeNotificationDeletable[kind]...) {
				return
			}
			secrets, ok := n.updatedSecretsLocked(w, name, params)
			if !ok {
				return
			}
			section := n.sectionLocked(name)
			if !n.applyLocked(w, &section, params) {
				return
			}
			n.entries[name] = section
			switch kind {
			case "smtp":
				if slices.Contains(params[pbsclient.DeleteParam], "password") {
					delete(n.passwords, name)
				}
				if params.Has("password") {
					n.passwords[name] = params.Get("password")
				}
			case "gotify":
				if params.Has("token") {
					n.passwords[name] = params.Get("token")
				}
			case "webhook":
				n.webhookSecrets[name] = secrets
			}
			writeData(w, nil, "")
		case http.MethodDelete:
			if _, builtin := fakeBuiltinNotifications[name]; kind != "matcher" && !builtin {
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
			}
			delete(n.passwords, name)
			delete(n.webhookSecrets, name)
			delete(n.entries, name)
			writeData(w, nil, "")
		}
	}
}

// updatedSecretsLocked checks a webhook update's headers and works out its
// secrets as proxmox-notify does: delete=secret drops them all, and a
// secret parameter replaces them, an entry without a value keeping the old
// one of that name.
func (n *fakeNotifications) updatedSecretsLocked(w http.ResponseWriter, name string, params map[string][]string) ([]string, bool) {
	old := n.webhookSecrets[name]
	for _, h := range params["header"] {
		headerName, value, err := pbsclient.ParseNotificationKeyValue(h)
		switch {
		case err == nil && value == nil:
			writeError(w, "header '%s' has empty value", headerName)
			return nil, false
		case err != nil:
			writeError(w, "header '%s' does not have valid base64 encoded data", headerName)
			return nil, false
		}
	}
	secrets := old
	if slices.Contains(params[pbsclient.DeleteParam], "secret") {
		secrets = nil
	}
	sent, ok := params["secret"]
	if !ok {
		return secrets, true
	}
	secrets = nil
	seen := map[string]bool{}
	for _, s := range sent {
		secretName, value, err := pbsclient.ParseNotificationKeyValue(s)
		if err != nil {
			writeError(w, "secret '%s' does not have valid base64 encoded data", secretName)
			return nil, false
		}
		if value == nil {
			i := slices.IndexFunc(old, func(o string) bool {
				oldName, _, _ := pbsclient.ParseNotificationKeyValue(o)
				return oldName == secretName
			})
			if i < 0 {
				writeError(w, "secret '%s' not known", secretName)
				return nil, false
			}
			s = old[i]
		}
		if seen[secretName] {
			writeError(w, "secret '%s' defined multiple times", secretName)
			return nil, false
		}
		seen[secretName] = true
		secrets = append(secrets, s)
	}
	return secrets, true
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

// listTargets serves GET /config/notifications/targets: every endpoint, by
// kind and then by name.
func (n *fakeNotifications) listTargets(w http.ResponseWriter, _ *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	names := make([]string, 0, len(n.entries))
	for name := range n.namesLocked() {
		names = append(names, name)
	}
	sort.Strings(names)
	targets := []map[string]any{}
	for _, kind := range fakeEndpointKinds {
		for _, name := range names {
			e, _ := n.lookupLocked(name)
			if e.kind != kind {
				continue
			}
			target := map[string]any{"name": name, "type": kind, "origin": e.props["origin"]}
			for _, key := range []string{"disable", "comment"} {
				if v, ok := e.props[key]; ok {
					target[key] = v
				}
			}
			targets = append(targets, target)
		}
	}
	writeData(w, targets, "")
}

// test serves POST /config/notifications/targets/{name}/test.
func (n *fakeNotifications) test(w http.ResponseWriter, req *http.Request) {
	name, ok := strings.CutSuffix(strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/notifications/targets/"), "/test")
	if !ok {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if e, exists := n.lookupLocked(name); !exists || e.kind == "matcher" {
		writeFakeResponse(w, http.StatusNotFound, fmt.Sprintf("endpoint '%s' does not exist", name))
		return
	}
	n.tests = append(n.tests, name)
	if message, fails := n.testFailures[name]; fails {
		writeFakeResponse(w, http.StatusInternalServerError, "Could not test target: "+message)
		return
	}
	writeData(w, nil, "")
}
