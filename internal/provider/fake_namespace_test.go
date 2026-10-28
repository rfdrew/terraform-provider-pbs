package provider

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// fakeNamespaces keeps the namespaces of a fakeDatastores' datastores, with
// the backups in them, and serves /admin/datastore/{store}/namespace through
// its fakePBS, with the behaviour of PBS 4.0 and 4.2 (see
// internal/pbsclient/namespace.go):
//
//   - a list starts with the parent asked for — whether it exists or not —
//     followed by the namespaces below it, depth first, down to max-depth
//     levels below the parent and never below the seventh level. PBS lists
//     siblings in directory order; the fake lists them in reverse order, so
//     that the provider has to sort them;
//   - creating a namespace that exists succeeds, and one below a missing
//     parent fails;
//   - deleting works bottom up through the namespace and those below it:
//     with delete-groups it deletes the backups, except groups with
//     protected snapshots; it removes the namespaces left empty, and fails
//     unless error-on-protected=false when it could not remove all of them;
//     deleting a namespace that does not exist succeeds without
//     delete-groups and fails with ENOENT with it;
//   - a missing datastore is 400 "no such datastore 'x'", and one in
//     unavailable — a removable datastore not mounted, say — 400 with its
//     message;
//   - namespaces in hidden are left out of lists, as PBS leaves out those the
//     caller has no privilege on.
//
// Tests set up namespaces with addNamespace and backups with addGroups and
// look at them with has and groupCount.
type fakeNamespaces struct {
	datastores *fakeDatastores

	mu sync.Mutex
	// namespaces are the namespaces below the root of each datastore, by
	// store and namespace.
	namespaces map[string]map[string]bool
	// groups and protected count the backup groups, and the protected
	// snapshots in them, of a namespace, keyed by store:namespace.
	groups    map[string]int
	protected map[string]int
	// unavailable is the error PBS answers for a datastore it cannot open.
	unavailable map[string]string
	// hidden are the namespaces, as store:namespace, lists leave out.
	hidden map[string]bool
}

// newFakeNamespaces serves the namespace API of the datastores of datastores.
func newFakeNamespaces(datastores *fakeDatastores) *fakeNamespaces {
	n := &fakeNamespaces{
		datastores:  datastores,
		namespaces:  map[string]map[string]bool{},
		groups:      map[string]int{},
		protected:   map[string]int{},
		unavailable: map[string]string{},
		hidden:      map[string]bool{},
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		datastores.fake.handlePrefix(method+" /admin/datastore/", n.serve)
	}
	return n
}

// --- test helpers -------------------------------------------------------------

func (n *fakeNamespaces) addNamespace(store, ns string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.storeLocked(store)[ns] = true
}

// addGroups puts backup groups into a namespace, with protected snapshots
// in them.
func (n *fakeNamespaces) addGroups(store, ns string, groups, protected int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.groups[namespaceID(store, ns)] = groups
	n.protected[namespaceID(store, ns)] = protected
}

func (n *fakeNamespaces) has(store, ns string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.namespaces[store][ns]
}

func (n *fakeNamespaces) groupCount(store, ns string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.groups[namespaceID(store, ns)]
}

func (n *fakeNamespaces) setUnavailable(store, message string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if message == "" {
		delete(n.unavailable, store)
		return
	}
	n.unavailable[store] = message
}

func (n *fakeNamespaces) hide(store, ns string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hidden[namespaceID(store, ns)] = true
}

func (n *fakeNamespaces) storeLocked(store string) map[string]bool {
	if n.namespaces[store] == nil {
		n.namespaces[store] = map[string]bool{}
	}
	return n.namespaces[store]
}

// --- serving ------------------------------------------------------------------

// namespaceDepth is how many levels below the root a namespace is.
func namespaceDepth(ns string) int {
	if ns == "" {
		return 0
	}
	return strings.Count(ns, "/") + 1
}

// below reports whether ns is below ancestor, the root included.
func below(ns, ancestor string) bool {
	return ancestor == "" || strings.HasPrefix(ns, ancestor+"/")
}

func (n *fakeNamespaces) serve(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/admin/datastore/")
	store, ok := strings.CutSuffix(rest, "/namespace")
	if !ok || strings.Contains(store, "/") {
		writeFakeResponse(w, http.StatusNotFound, "Path '"+req.URL.Path+"' not found.")
		return
	}
	if _, exists := n.datastores.datastore(store); !exists {
		writeError(w, "no such datastore '%s'", store)
		return
	}
	params := form(req)
	n.mu.Lock()
	defer n.mu.Unlock()
	if message, ok := n.unavailable[store]; ok {
		writeError(w, "%s", message)
		return
	}
	namespaces := n.storeLocked(store)

	switch req.Method {
	case http.MethodGet:
		parent := params.Get("parent")
		maxDepth := maxNamespaceDepth
		if raw := params.Get("max-depth"); raw != "" {
			d, err := strconv.Atoi(raw)
			if err != nil || d < 0 || d > maxNamespaceDepth {
				writeError(w, "parameter verification failed - 'max-depth': value must be between 0 and 7")
				return
			}
			maxDepth = d
		}
		maxDepth = min(maxDepth, maxNamespaceDepth-namespaceDepth(parent))
		var found []string
		for ns := range namespaces {
			if below(ns, parent) && namespaceDepth(ns)-namespaceDepth(parent) <= maxDepth && !n.hidden[namespaceID(store, ns)] {
				found = append(found, ns)
			}
		}
		// Depth first, each namespace before those below it, and siblings
		// in reverse order.
		slices.SortFunc(found, func(a, b string) int {
			partsA, partsB := strings.Split(a, "/"), strings.Split(b, "/")
			for i := 0; i < len(partsA) && i < len(partsB); i++ {
				if c := strings.Compare(partsB[i], partsA[i]); c != 0 {
					return c
				}
			}
			return len(partsA) - len(partsB)
		})
		items := []map[string]any{{"ns": parent}}
		for _, ns := range found {
			items = append(items, map[string]any{"ns": ns})
		}
		writeData(w, items, "")

	case http.MethodPost:
		if !checkRequired(w, params, "name") {
			return
		}
		parent, name := params.Get("parent"), params.Get("name")
		if parent != "" && !namespaces[parent] {
			writeError(w, "cannot create new namespace, parent %s doesn't already exists", parent)
			return
		}
		if depth := namespaceDepth(parent); depth >= maxNamespaceDepth {
			writeError(w, "namespace too deep, %d >= max %d", depth, maxNamespaceDepth)
			return
		}
		ns := name
		if parent != "" {
			ns = parent + "/" + name
		}
		namespaces[ns] = true
		writeData(w, ns, "")

	case http.MethodDelete:
		ns := params.Get("ns")
		deleteGroups := fakeBool(params.Get("delete-groups"))
		errorOnProtected := params.Get("error-on-protected") == "" || fakeBool(params.Get("error-on-protected"))
		// PBS reads the groups of the namespace first, which fails for one
		// that does not exist.
		if deleteGroups && ns != "" && !namespaces[ns] {
			writeError(w, "ENOENT: No such file or directory")
			return
		}
		var subtree []string
		for candidate := range namespaces {
			if candidate == ns || below(candidate, ns) {
				subtree = append(subtree, candidate)
			}
		}
		// Deepest first, so that a namespace sees its children gone.
		slices.SortFunc(subtree, func(a, b string) int { return namespaceDepth(b) - namespaceDepth(a) })
		removedAll := true
		stats := map[string]int{"removed-groups": 0, "removed-snapshots": 0, "protected-snapshots": 0}
		for _, candidate := range subtree {
			key := namespaceID(store, candidate)
			if deleteGroups && n.groups[key] > 0 {
				kept := 0
				if n.protected[key] > 0 {
					kept = 1
					removedAll = false
					stats["protected-snapshots"] += n.protected[key]
				}
				stats["removed-groups"] += n.groups[key] - kept
				stats["removed-snapshots"] += n.groups[key] - kept
				n.groups[key] = kept
			}
			hasChildren := slices.ContainsFunc(subtree, func(other string) bool {
				return namespaces[other] && other != candidate && below(other, candidate)
			})
			if n.groups[key] > 0 || hasChildren {
				removedAll = false
				continue
			}
			delete(namespaces, candidate)
		}
		if !removedAll && errorOnProtected {
			if deleteGroups {
				writeError(w, "group only partially deleted due to protected snapshots")
			} else {
				writeError(w, "only partially deleted due to existing groups but `delete-groups` not true")
			}
			return
		}
		writeData(w, stats, "")
	}
}

// fakeNamespaceRoute is the namespace route of a datastore, for counting and
// inspecting calls.
func fakeNamespaceRoute(method, store string) string {
	return fmt.Sprintf("%s /admin/datastore/%s/namespace", method, store)
}
