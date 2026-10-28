package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestNamespaceResourceSchemaIsValid(t *testing.T) {
	requireValidResourceSchema(t, &namespaceResource{})
}

// newNamespaceHarness is a fake PBS with the datastore store1, the namespace
// API and a provider signed in to it.
func newNamespaceHarness(t *testing.T) (*protocolHarness, *fakePBS, *fakeNamespaces) {
	t.Helper()
	h, fake, datastores := newDatastoreHarness(t)
	datastores.addDatastore("store1", fakeProperties{"path": "/mnt/datastore/store1"})
	return h, fake, newFakeNamespaces(datastores)
}

func TestNamespaceResourceLifecycle(t *testing.T) {
	h, fake, namespaces := newNamespaceHarness(t)

	parent := h.create(t, "pbs_namespace", h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1"}))
	created := fake.lastCall(t, fakeNamespaceRoute("POST", "store1"))
	if created.form.Get("name") != "dept1" || created.form.Has("parent") {
		t.Errorf("POST form = %v", created.form)
	}
	child := h.create(t, "pbs_namespace", h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1/hosts"}))
	if created := fake.lastCall(t, fakeNamespaceRoute("POST", "store1")); created.form.Get("parent") != "dept1" || created.form.Get("name") != "hosts" {
		t.Errorf("POST form = %v", created.form)
	}
	if !namespaces.has("store1", "dept1/hosts") {
		t.Fatal("PBS has no namespace dept1/hosts")
	}
	if stringAt(t, child.state, "id") != "store1:dept1/hosts" || boolAt(t, child.state, "delete_groups") || !boolAt(t, child.state, "error_on_protected") {
		t.Errorf("state = %s", child.state)
	}
	identity := h.identityValue(t, "pbs_namespace", child.identity)
	if stringAt(t, identity, "store") != "store1" || stringAt(t, identity, "namespace") != "dept1/hosts" {
		t.Errorf("identity = %s", identity)
	}

	// The namespace is looked up in its parent's list, one level deep, never
	// as a parent of its own.
	refreshed := h.refresh(t, child)
	if !refreshed.state.Equal(child.state) {
		t.Errorf("refresh changed the state to %s", refreshed.state)
	}
	if query := fake.lastCall(t, fakeNamespaceRoute("GET", "store1")).query; query.Get("parent") != "dept1" || query.Get("max-depth") != "1" {
		t.Errorf("lookup query = %v", query)
	}

	// A plan against the unchanged configuration changes nothing.
	config := h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1/hosts"})
	replan := h.plan(t, "pbs_namespace", child, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_namespace", replan.PlannedState); !planned.Equal(child.state) {
		diffs, _ := planned.Diff(child.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}
	if len(replan.RequiresReplace) != 0 {
		t.Errorf("RequiresReplace = %v", replan.RequiresReplace)
	}

	// The delete-time options change in state alone; anything else replaces
	// the namespace.
	posts := fake.count(fakeNamespaceRoute("POST", "store1"))
	child = h.update(t, child, h.resourceValue(t, "pbs_namespace", map[string]any{
		"store": "store1", "namespace": "dept1/hosts", "delete_groups": true, "error_on_protected": false,
	}))
	if fake.count(fakeNamespaceRoute("POST", "store1")) != posts || countPrefix(fake, "DELETE ") != 0 {
		t.Errorf("changing the delete-time options called PBS: %v", fake.routes())
	}
	if !boolAt(t, child.state, "delete_groups") || boolAt(t, child.state, "error_on_protected") {
		t.Errorf("state = %s", child.state)
	}
	moved := h.plan(t, "pbs_namespace", child, h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1/web"}))
	requireNoProtocolErrors(t, moved.Diagnostics)
	if len(moved.RequiresReplace) != 1 {
		t.Errorf("RequiresReplace = %v, want namespace", moved.RequiresReplace)
	}

	// Destroying sends the options from state.
	h.destroy(t, child)
	deleted := fake.lastCall(t, fakeNamespaceRoute("DELETE", "store1"))
	if deleted.query.Get("ns") != "dept1/hosts" || deleted.query.Get("delete-groups") != "true" || deleted.query.Get("error-on-protected") != "false" {
		t.Errorf("DELETE query = %v", deleted.query)
	}
	h.destroy(t, parent)
	if deleted := fake.lastCall(t, fakeNamespaceRoute("DELETE", "store1")); deleted.query.Get("ns") != "dept1" || len(deleted.query) != 1 {
		t.Errorf("DELETE query = %v, want the defaults left out", deleted.query)
	}
	if namespaces.has("store1", "dept1") || namespaces.has("store1", "dept1/hosts") {
		t.Error("the namespaces still exist")
	}
}

// Creating a namespace that exists takes it over, with a warning; PBS
// creates one only below a parent that exists.
func TestNamespaceResourceCreate(t *testing.T) {
	h, _, namespaces := newNamespaceHarness(t)
	namespaces.addNamespace("store1", "dept1")

	config := h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1"})
	planned := h.plan(t, "pbs_namespace", nil, config)
	applied := h.apply(t, "pbs_namespace", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "existed already")

	for attrs, want := range map[[2]string]string{
		{"store1", "missing/child"}: `has no namespace "missing"`,
		{"store9", "dept1"}:         `PBS has no datastore "store9"`,
	} {
		config := h.resourceValue(t, "pbs_namespace", map[string]any{"store": attrs[0], "namespace": attrs[1]})
		planned := h.plan(t, "pbs_namespace", nil, config)
		applied := h.apply(t, "pbs_namespace", nil, config, planned)
		requireProtocolErrorContaining(t, applied.Diagnostics, want)
		if state := h.decodeResource(t, "pbs_namespace", applied.NewState); !state.IsNull() {
			t.Errorf("a failed create left state %s", state)
		}
	}

	// A namespace the provider may not read is created, and recorded, but
	// would be planned again: that is a warning.
	namespaces.hide("store1", "dept2")
	config = h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept2"})
	planned = h.plan(t, "pbs_namespace", nil, config)
	applied = h.apply(t, "pbs_namespace", nil, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "Datastore.Audit, Datastore.Modify or Datastore.Backup on /datastore/store1/dept2")
	if state := h.decodeResource(t, "pbs_namespace", applied.NewState); state.IsNull() {
		t.Error("the created namespace is not in state")
	}
}

// A namespace, or its datastore, gone outside Terraform leaves state; one
// whose datastore PBS cannot open stays, with a warning.
func TestNamespaceResourceRead(t *testing.T) {
	h, _, namespaces := newNamespaceHarness(t)
	inst := h.create(t, "pbs_namespace", h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1"}))

	// A maintenance message is free text, and one that ends in "not found"
	// does not make the datastore a missing one.
	for _, message := range []string{
		"datastore 'store1' is not mounted",
		"datastore 'store1' is unavailable: offline maintenance mode: USB disk not found",
	} {
		namespaces.setUnavailable("store1", message)
		resp := h.read(t, inst)
		requireNoProtocolErrors(t, resp.Diagnostics)
		requireProtocolWarningContaining(t, resp.Diagnostics, "stays in state as it was")
		if state := h.decodeResource(t, "pbs_namespace", resp.NewState); !state.Equal(inst.state) {
			t.Errorf("state with %q = %s, want it unchanged", message, state)
		}

		// Neither imported nor destroyed: PBS cannot tell.
		imported := h.importResource(t, "pbs_namespace", "store1:typo", nil)
		requireNoProtocolErrors(t, imported.Diagnostics)
		read := h.read(t, &resourceInstance{typeName: "pbs_namespace",
			state: h.decodeResource(t, "pbs_namespace", imported.ImportedResources[0].State), identity: imported.ImportedResources[0].Identity})
		requireProtocolErrorContaining(t, read.Diagnostics, "Mount the datastore or end the maintenance, and import again")

		null := tftypes.NewValue(h.resourceType(t, "pbs_namespace"), nil)
		planned := h.plan(t, "pbs_namespace", inst, null)
		applied := h.apply(t, "pbs_namespace", inst, null, planned)
		requireProtocolErrorContaining(t, applied.Diagnostics, "terraform state rm")
	}
	namespaces.setUnavailable("store1", "")

	namespaces.mu.Lock()
	delete(namespaces.namespaces["store1"], "dept1")
	namespaces.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted namespace: %s", refreshed.state)
	}

	namespaces.datastores.mu.Lock()
	delete(namespaces.datastores.datastores, "store1")
	namespaces.datastores.mu.Unlock()
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept the namespace of a deleted datastore: %s", refreshed.state)
	}
	// Destroying it then is no error.
	h.destroy(t, inst)
}

// Without delete_groups, PBS refuses to delete a namespace with backups, after
// pruning the empty namespaces below it; with it, it deletes the backups but
// protected snapshots, and error_on_protected = false makes what is left a
// warning.
func TestNamespaceResourceDelete(t *testing.T) {
	h, _, namespaces := newNamespaceHarness(t)
	for _, ns := range []string{"dept1", "dept1/empty", "dept1/hosts"} {
		namespaces.addNamespace("store1", ns)
	}
	namespaces.addGroups("store1", "dept1/hosts", 2, 0)
	inst := h.importByID(t, "pbs_namespace", "store1:dept1")

	null := tftypes.NewValue(h.resourceType(t, "pbs_namespace"), nil)
	planned := h.plan(t, "pbs_namespace", inst, null)
	applied := h.apply(t, "pbs_namespace", inst, null, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "set delete_groups = true")
	if !namespaces.has("store1", "dept1/hosts") || namespaces.has("store1", "dept1/empty") || namespaces.groupCount("store1", "dept1/hosts") != 2 {
		t.Error("PBS did not keep the backups, or kept the empty namespace")
	}

	inst = h.update(t, inst, h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1", "delete_groups": true}))
	namespaces.addGroups("store1", "dept1/hosts", 2, 1)
	planned = h.plan(t, "pbs_namespace", inst, null)
	applied = h.apply(t, "pbs_namespace", inst, null, planned)
	requireProtocolErrorContaining(t, applied.Diagnostics, "protected snapshots")
	requireProtocolErrorContaining(t, applied.Diagnostics, "error_on_protected = false")

	inst = h.update(t, inst, h.resourceValue(t, "pbs_namespace", map[string]any{
		"store": "store1", "namespace": "dept1", "delete_groups": true, "error_on_protected": false,
	}))
	planned = h.plan(t, "pbs_namespace", inst, null)
	applied = h.apply(t, "pbs_namespace", inst, null, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	requireProtocolWarningContaining(t, applied.Diagnostics, "kept what it could not delete")
	if !namespaces.has("store1", "dept1") {
		t.Error("PBS removed the namespace that holds protected snapshots")
	}

	// Once nothing is protected, destroying removes it all without a warning.
	namespaces.addGroups("store1", "dept1/hosts", 1, 0)
	inst = h.importByID(t, "pbs_namespace", "store1:dept1")
	inst = h.update(t, inst, h.resourceValue(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1", "delete_groups": true}))
	planned = h.plan(t, "pbs_namespace", inst, null)
	applied = h.apply(t, "pbs_namespace", inst, null, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	for _, d := range applied.Diagnostics {
		t.Errorf("unexpected diagnostic %q", d.Summary)
	}
	if namespaces.has("store1", "dept1") || namespaces.has("store1", "dept1/hosts") {
		t.Error("the namespaces still exist")
	}
}

// A namespace already gone — with its parent, destroyed in the same apply,
// say — is destroyed without an error, also with delete_groups, for which
// PBS answers ENOENT.
func TestNamespaceResourceDeleteGone(t *testing.T) {
	h, fake, namespaces := newNamespaceHarness(t)
	parent := h.create(t, "pbs_namespace", h.resourceValue(t, "pbs_namespace", map[string]any{
		"store": "store1", "namespace": "dept1", "delete_groups": true,
	}))
	child := h.create(t, "pbs_namespace", h.resourceValue(t, "pbs_namespace", map[string]any{
		"store": "store1", "namespace": "dept1/hosts", "delete_groups": true,
	}))
	h.destroy(t, parent)
	if namespaces.has("store1", "dept1/hosts") {
		t.Fatal("destroying the parent kept the child")
	}
	h.destroy(t, child)
	if got := fake.lastCall(t, fakeNamespaceRoute("DELETE", "store1")).query.Get("ns"); got != "dept1/hosts" {
		t.Errorf("last DELETE was for %q", got)
	}
}

// Both import forms read the namespace, with the delete-time options at their
// defaults; malformed IDs are refused.
func TestNamespaceResourceImport(t *testing.T) {
	h, _, namespaces := newNamespaceHarness(t)
	namespaces.addNamespace("store1", "dept1")
	namespaces.addNamespace("store1", "dept1/hosts")

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_namespace", "store1:dept1/hosts"),
		"identity": h.importByIdentity(t, "pbs_namespace", map[string]any{"store": "store1", "namespace": "dept1/hosts"}),
	} {
		if stringAt(t, inst.state, "id") != "store1:dept1/hosts" || stringAt(t, inst.state, "namespace") != "dept1/hosts" ||
			boolAt(t, inst.state, "delete_groups") || !boolAt(t, inst.state, "error_on_protected") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
	}

	for _, id := range []string{"store1", "store1:", "store1:/dept1", "s1:dept1", "store1:dept1/", "store1:a/b/c/d/e/f/g/h"} {
		resp := h.importResource(t, "pbs_namespace", id, nil)
		requireProtocolErrorContaining(t, resp.Diagnostics, "Import a PBS namespace by <store>:<namespace>")
	}

	// A namespace that does not exist imports nothing.
	resp := h.importResource(t, "pbs_namespace", "store1:missing", nil)
	requireNoProtocolErrors(t, resp.Diagnostics)
	imported := resp.ImportedResources[0]
	refreshed := h.refresh(t, &resourceInstance{typeName: "pbs_namespace", state: h.decodeResource(t, "pbs_namespace", imported.State), identity: imported.Identity})
	if !refreshed.state.IsNull() {
		t.Errorf("imported a missing namespace: %s", refreshed.state)
	}
}

func TestNamespaceResourceValidation(t *testing.T) {
	h, _, _ := newNamespaceHarness(t)
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"leading slash": {map[string]any{"store": "store1", "namespace": "/dept1"}, "up to seven names"},
		"too deep":      {map[string]any{"store": "store1", "namespace": "a/b/c/d/e/f/g/h"}, "up to seven names"},
		"long name":     {map[string]any{"store": "store1", "namespace": "dept1/" + strings.Repeat("x", 33)}, "at most 32 characters each"},
		"bad store":     {map[string]any{"store": "s1", "namespace": "dept1"}, "store"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_namespace", h.resourceValue(t, "pbs_namespace", tc.attrs)), tc.want)
		})
	}
	requireNoProtocolErrors(t, h.validateResource(t, "pbs_namespace", h.resourceValue(t, "pbs_namespace", map[string]any{
		"store": "store1", "namespace": "a/b/c/d/e/f/g",
	})))
}
