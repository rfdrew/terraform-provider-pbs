package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Namespaces divide a datastore's backups into a tree, such as dept1 and
// dept1/hosts, up to seven levels deep. A namespace is a
// directory in the datastore and has no configuration of its own: PBS can
// create, list and delete one, and nothing else. What PBS 4.0 and 4.2 do, as
// observed on real servers and read in its source (src/api2/admin/namespace.rs,
// pbs-datastore's hierarchy.rs):
//
//   - POST /admin/datastore/{store}/namespace takes the parent and the new
//     name and answers the new namespace. Creating one that exists answers
//     200 as well, and one below a missing parent 400 "cannot create new
//     namespace, parent x doesn't already exists".
//   - GET lists the namespaces at and below a parent, the parent itself
//     first — the root, "", when there is none — then the ones below, depth
//     first, in directory order. A parent that does not exist is still
//     listed, as if it did, so whether a namespace exists is read from its
//     parent's list, never from its own. Only the namespaces the caller has
//     a privilege on are listed.
//   - DELETE deletes a namespace and the namespaces below it, deepest first.
//     Without delete-groups it removes only empty namespaces, answers 200
//     for one that does not exist, and fails, with 400 "only partially
//     deleted due to existing groups but `delete-groups` not true", when one
//     holds backup groups — after removing the empty ones below. With
//     delete-groups it deletes the backups too, except protected snapshots,
//     whose namespaces stay: 400 "group only partially deleted due to
//     protected snapshots"; for a namespace that does not exist it fails
//     with 400 "ENOENT: No such file or directory", reading its groups.
//     error-on-protected=false turns the first two failures into a 200 that
//     leaves those namespaces in place.
//   - Every call opens the datastore, and fails — with 400 "datastore 'x' is
//     not mounted" or "datastore 'x' is unavailable: ..." — while a removable
//     datastore is not mounted or a maintenance mode forbids the operation;
//     IsDatastoreUnavailable reports that. A missing datastore is 400 "no
//     such datastore 'x'", which IsNotFound covers.

// SplitNamespace splits a namespace into its parent and its own name: "a/b/c"
// into "a/b" and "c", "a" into "" — the root — and "a".
func SplitNamespace(ns string) (parent, name string) {
	if i := strings.LastIndexByte(ns, '/'); i >= 0 {
		return ns[:i], ns[i+1:]
	}
	return "", ns
}

// NamespaceDeleteStats is what deleting a namespace with its backups
// removed, and what it kept.
type NamespaceDeleteStats struct {
	RemovedGroups      int64 `json:"removed-groups"`
	RemovedSnapshots   int64 `json:"removed-snapshots"`
	ProtectedSnapshots int64 `json:"protected-snapshots"`
}

// NamespaceDeletion says what DeleteNamespace deletes besides empty
// namespaces.
type NamespaceDeletion struct {
	// DeleteGroups deletes the backups in the namespaces too.
	DeleteGroups bool
	// KeepOnProtected has PBS answer success when it cannot delete
	// everything — backups without DeleteGroups, protected snapshots with
	// it — instead of an error; it removes what it can either way.
	KeepOnProtected bool
}

// ListNamespaces lists the namespaces of store at and below parent, "" for
// the root, maxDepth levels deep, or all of them when maxDepth is negative:
// parent itself first, then the namespaces below it, as PBS answers. PBS lists
// a parent that does not exist too.
func (c *Client) ListNamespaces(ctx context.Context, store, parent string, maxDepth int) ([]string, error) {
	params := url.Values{}
	if parent != "" {
		params.Set("parent", parent)
	}
	if maxDepth >= 0 {
		params.Set("max-depth", strconv.Itoa(maxDepth))
	}
	var items []struct {
		NS string `json:"ns"`
	}
	if _, err := c.Get(ctx, Path("admin", "datastore", store, "namespace"), params, &items); err != nil {
		return nil, err
	}
	namespaces := make([]string, len(items))
	for i, item := range items {
		namespaces[i] = item.NS
	}
	return namespaces, nil
}

// NamespaceExists reports whether namespace ns exists in store, looking for
// it in its parent's list: PBS lists a namespace asked for as the parent
// whether it exists or not. The root always exists.
func (c *Client) NamespaceExists(ctx context.Context, store, ns string) (bool, error) {
	if ns == "" {
		return true, nil
	}
	parent, _ := SplitNamespace(ns)
	namespaces, err := c.ListNamespaces(ctx, store, parent, 1)
	if err != nil {
		return false, err
	}
	for _, found := range namespaces {
		if found == ns {
			return true, nil
		}
	}
	return false, nil
}

// CreateNamespace creates namespace ns in store, below its parent, which
// must exist. Creating a namespace that exists succeeds.
func (c *Client) CreateNamespace(ctx context.Context, store, ns string) error {
	parent, name := SplitNamespace(ns)
	params := url.Values{"name": {name}}
	if parent != "" {
		params.Set("parent", parent)
	}
	_, err := c.Post(ctx, Path("admin", "datastore", store, "namespace"), params, nil)
	return err
}

// DeleteNamespace deletes namespace ns of store and the namespaces below it,
// as deletion says. Deleting a namespace that does not exist succeeds: with
// delete-groups, PBS fails on it with ENOENT, and the namespace is then looked
// up to tell that from a directory PBS could not read — but not for a
// maintenance mode's refusal, whose free-text message may say ENOENT too.
func (c *Client) DeleteNamespace(ctx context.Context, store, ns string, deletion NamespaceDeletion) (NamespaceDeleteStats, error) {
	params := url.Values{"ns": {ns}}
	if deletion.DeleteGroups {
		params.Set("delete-groups", "true")
	}
	if deletion.KeepOnProtected {
		params.Set("error-on-protected", "false")
	}
	var stats NamespaceDeleteStats
	_, err := c.Delete(ctx, Path("admin", "datastore", store, "namespace"), params, &stats)
	if apiErr, ok := asError(err); ok && deletion.DeleteGroups && !IsDatastoreUnavailable(err) && strings.Contains(apiErr.Message, "ENOENT") {
		if exists, lookupErr := c.NamespaceExists(ctx, store, ns); lookupErr == nil && !exists {
			return NamespaceDeleteStats{}, nil
		}
	}
	return stats, err
}

// IsDatastoreUnavailable reports whether PBS refused to open a datastore
// because it is a removable datastore that is not mounted, or because its
// maintenance mode forbids the operation: IsDatastoreNotMounted or
// IsDatastoreInMaintenance.
//
// Every call that opens a datastore does so through lookup_datastore
// (pbs-datastore datastore.rs; proxmox-backup 7c86c5ad5, after 4.2.11),
// which checks the maintenance mode first, answering 400 "datastore 'x' is
// unavailable: <reason>", and only then whether a removable datastore is
// mounted, answering 400 "datastore 'x' is not mounted": a datastore that is
// both reports its maintenance mode. Only an unmount answers "Datastore 'x'
// is not mounted", with a capital D, from its own check before it opens
// anything.
//
// The reason of a maintenance refusal ends with the free-text message a user
// gave the mode, which may hold anything: "not found", "already running",
// "due to existing groups". Callers must test this before any check that
// looks for words in PBS's message, such as IsTaskAlreadyRunning or a match
// of "due to existing groups"; IsNotFound leaves these refusals out itself.
func IsDatastoreUnavailable(err error) bool {
	return IsDatastoreInMaintenance(err) || IsDatastoreNotMounted(err)
}

// datastoreInMaintenancePattern is the start of lookup_datastore's refusal
// for a maintenance mode, up to the reason.
var datastoreInMaintenancePattern = regexp.MustCompile(`^datastore '` + datastoreNameInError + `' is unavailable: `)

// IsDatastoreInMaintenance reports whether PBS refused to open a datastore
// because its maintenance mode forbids the operation: 400 "datastore 'x' is
// unavailable: <reason>", which lookup_datastore (pbs-datastore datastore.rs)
// answers with the error of MaintenanceMode::check (pbs-api-types
// maintenance.rs). Its reasons, unchanged since pbs-api-types 1.0.2, which
// PBS 4.0.11 uses:
//
//   - "datastore is being deleted", for any operation, even one that only
//     looks the datastore up;
//   - "datastore is being unmounted";
//   - "offline maintenance mode: <message>";
//   - "S3 refresh maintenance mode: <message>";
//   - "read-only maintenance mode: <message>", for an operation that writes.
//
// Every mode but read-only thus refuses reading too. <message> is the mode's
// free text, percent-decoded, up to 64 characters on one line: it may
// contain anything, quotes included, so only the start of the message is
// matched. DatastoreMaintenanceType tells the modes apart.
func IsDatastoreInMaintenance(err error) bool {
	apiErr, ok := asError(err)
	return ok && apiErr.StatusCode == http.StatusBadRequest && datastoreInMaintenancePattern.MatchString(apiErr.Message)
}

// datastoreMaintenanceReasons maps the start of each reason of
// MaintenanceMode::check (pbs-api-types maintenance.rs) to its mode: without
// the colon and the message that follow a mode's name, since the message
// may be empty and the provider trims the space after the colon then.
var datastoreMaintenanceReasons = []struct{ prefix, mode string }{
	{"datastore is being deleted", MaintenanceDelete},
	{"datastore is being unmounted", MaintenanceUnmount},
	{"offline maintenance mode", MaintenanceOffline},
	{"S3 refresh maintenance mode", MaintenanceS3Refresh},
	{"read-only maintenance mode", MaintenanceReadOnly},
}

// DatastoreMaintenanceType returns the maintenance mode with which PBS
// refused to open a datastore — MaintenanceReadOnly, MaintenanceOffline,
// MaintenanceUnmount, MaintenanceS3Refresh or MaintenanceDelete —, read from
// the reason of an error IsDatastoreInMaintenance reports. It returns "" for
// any other error, and for a reason a later release words differently.
func DatastoreMaintenanceType(err error) string {
	if !IsDatastoreInMaintenance(err) {
		return ""
	}
	apiErr, _ := asError(err)
	reason := apiErr.Message[len(datastoreInMaintenancePattern.FindString(apiErr.Message)):]
	for _, r := range datastoreMaintenanceReasons {
		if strings.HasPrefix(reason, r.prefix) {
			return r.mode
		}
	}
	return ""
}
