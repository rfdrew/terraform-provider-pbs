package pbsclient

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestSplitNamespace(t *testing.T) {
	for ns, want := range map[string][2]string{
		"":        {"", ""},
		"a":       {"", "a"},
		"a/b":     {"a", "b"},
		"a/b/c.d": {"a/b", "c.d"},
	} {
		parent, name := SplitNamespace(ns)
		if parent != want[0] || name != want[1] {
			t.Errorf("SplitNamespace(%q) = %q, %q, want %q, %q", ns, parent, name, want[0], want[1])
		}
	}
}

// PBS lists the parent first, then the namespaces below it; the list keeps
// that order. The parent and the depth are sent only when given.
func TestListNamespaces(t *testing.T) {
	const route = "GET /admin/datastore/store1/namespace"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":[{"ns":"dept1"},{"ns":"dept1/hosts"},{"ns":"dept1/hosts/web","comment":"x"}]}`)
	client := fake.client(t)

	got, err := client.ListNamespaces(context.Background(), "store1", "dept1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dept1", "dept1/hosts", "dept1/hosts/web"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ListNamespaces() = %v, want %v", got, want)
	}
	if query := fake.lastCall(t, route).query; query.Get("parent") != "dept1" || query.Get("max-depth") != "2" {
		t.Errorf("query = %v", query)
	}

	if _, err := client.ListNamespaces(context.Background(), "store1", "", -1); err != nil {
		t.Fatal(err)
	}
	if query := fake.lastCall(t, route).query; len(query) != 0 {
		t.Errorf("query for the root and all depths = %v, want none", query)
	}
}

// A namespace exists when its parent's list has it. PBS lists the parent
// asked for whether it exists or not, so a namespace is never looked up as a
// parent of its own; the root needs no lookup.
func TestNamespaceExists(t *testing.T) {
	const route = "GET /admin/datastore/store1/namespace"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":[{"ns":"dept1"},{"ns":"dept1/hosts"}]}`)
	client := fake.client(t)
	ctx := context.Background()

	for _, tc := range []struct {
		ns, parent string
		want       bool
	}{
		{"dept1/hosts", "dept1", true},
		{"dept1/web", "dept1", false},
		{"dept1/hosts/x", "dept1/hosts", false},
	} {
		got, err := client.NamespaceExists(ctx, "store1", tc.ns)
		if err != nil || got != tc.want {
			t.Errorf("NamespaceExists(%q) = %t, %v, want %t", tc.ns, got, err, tc.want)
		}
		if query := fake.lastCall(t, route).query; query.Get("parent") != tc.parent || query.Get("max-depth") != "1" {
			t.Errorf("query for %q = %v, want its parent and one level", tc.ns, query)
		}
	}

	n := fake.count(route)
	if ok, err := client.NamespaceExists(ctx, "store1", ""); !ok || err != nil {
		t.Errorf("NamespaceExists(root) = %t, %v", ok, err)
	}
	if fake.count(route) != n {
		t.Error("the root was looked up")
	}

	// A missing datastore is the error PBS answers, which IsNotFound covers.
	fake.reply(route, http.StatusBadRequest, "no such datastore 'store1'")
	if _, err := client.NamespaceExists(ctx, "store1", "dept1"); !IsNotFound(err) {
		t.Errorf("NamespaceExists() on a missing datastore = %v, want a not-found error", err)
	}
}

func TestCreateNamespace(t *testing.T) {
	const route = "POST /admin/datastore/store1/namespace"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":"dept1/hosts"}`)
	client := fake.client(t)

	if err := client.CreateNamespace(context.Background(), "store1", "dept1/hosts"); err != nil {
		t.Fatal(err)
	}
	if form := fake.lastCall(t, route).form; form.Get("parent") != "dept1" || form.Get("name") != "hosts" || len(form) != 2 {
		t.Errorf("form = %v", form)
	}

	if err := client.CreateNamespace(context.Background(), "store1", "dept1"); err != nil {
		t.Fatal(err)
	}
	if form := fake.lastCall(t, route).form; form.Get("name") != "dept1" || form.Has("parent") {
		t.Errorf("form below the root = %v, want no parent", form)
	}
}

// Delete-time options are sent only when they differ from PBS's defaults,
// and the statistics PBS answers are returned.
func TestDeleteNamespace(t *testing.T) {
	const route = "DELETE /admin/datastore/store1/namespace"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":{"removed-groups":2,"removed-snapshots":5,"protected-snapshots":1}}`)
	client := fake.client(t)

	stats, err := client.DeleteNamespace(context.Background(), "store1", "dept1", NamespaceDeletion{})
	if err != nil {
		t.Fatal(err)
	}
	if want := (NamespaceDeleteStats{RemovedGroups: 2, RemovedSnapshots: 5, ProtectedSnapshots: 1}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
	if query := fake.lastCall(t, route).query; query.Get("ns") != "dept1" || len(query) != 1 {
		t.Errorf("query = %v, want ns alone", query)
	}

	if _, err := client.DeleteNamespace(context.Background(), "store1", "dept1", NamespaceDeletion{DeleteGroups: true, KeepOnProtected: true}); err != nil {
		t.Fatal(err)
	}
	if query := fake.lastCall(t, route).query; query.Get("delete-groups") != "true" || query.Get("error-on-protected") != "false" {
		t.Errorf("query = %v", query)
	}
}

// With delete-groups, PBS fails on a namespace that does not exist, reading
// its groups; that is a namespace already gone, once its parent's list says
// so, and an error while the list still has it.
func TestDeleteNamespaceGone(t *testing.T) {
	const route = "DELETE /admin/datastore/store1/namespace"
	const list = "GET /admin/datastore/store1/namespace"
	fake := newFakePBS()
	fake.reply(route, http.StatusBadRequest, "ENOENT: No such file or directory")
	fake.reply(list, http.StatusOK, `{"data":[{"ns":"dept1"}]}`)
	client := fake.client(t)
	ctx := context.Background()

	if _, err := client.DeleteNamespace(ctx, "store1", "dept1/hosts", NamespaceDeletion{DeleteGroups: true}); err != nil {
		t.Errorf("DeleteNamespace() of a namespace that is gone = %v", err)
	}
	fake.reply(list, http.StatusOK, `{"data":[{"ns":"dept1"},{"ns":"dept1/hosts"}]}`)
	if _, err := client.DeleteNamespace(ctx, "store1", "dept1/hosts", NamespaceDeletion{DeleteGroups: true}); err == nil {
		t.Error("DeleteNamespace() hid an ENOENT for a namespace that exists")
	}
	// Without delete-groups, an error is PBS's, and nothing is looked up.
	lookups := fake.count(list)
	if _, err := client.DeleteNamespace(ctx, "store1", "dept1/hosts", NamespaceDeletion{}); err == nil || fake.count(list) != lookups {
		t.Errorf("DeleteNamespace() without delete-groups = %v, lookups %d -> %d", err, lookups, fake.count(list))
	}
}

func TestIsDatastoreUnavailable(t *testing.T) {
	for message, want := range map[string]bool{
		"datastore 'store1' is not mounted":                                 true,
		"Datastore 'store1' is not mounted":                                 true,
		"datastore 'store1' is unavailable: offline maintenance mode":       true,
		"datastore 'store1' is unavailable: read-only maintenance mode":     true,
		"no such datastore 'store1'":                                        false,
		"only partially deleted due to existing groups but `delete-groups`": false,
	} {
		err := error(&Error{StatusCode: http.StatusBadRequest, Message: message})
		if got := IsDatastoreUnavailable(err); got != want {
			t.Errorf("IsDatastoreUnavailable(%q) = %t, want %t", message, got, want)
		}
	}
	if IsDatastoreUnavailable(&Error{StatusCode: http.StatusForbidden, Message: "datastore 'x' is not mounted"}) {
		t.Error("a 403 counts as unavailable")
	}
	if IsDatastoreUnavailable(errors.New("datastore 'x' is not mounted")) {
		t.Error("an error that is not PBS's counts as unavailable")
	}

	// The maintenance message is free text, and does not make the
	// datastore a missing one.
	offline := &Error{StatusCode: http.StatusBadRequest, Message: "datastore 'store1' is unavailable: offline maintenance mode: USB disk not found"}
	if !IsDatastoreUnavailable(offline) || IsNotFound(offline) {
		t.Errorf("IsDatastoreUnavailable = %t, IsNotFound = %t, want true and false", IsDatastoreUnavailable(offline), IsNotFound(offline))
	}
}
