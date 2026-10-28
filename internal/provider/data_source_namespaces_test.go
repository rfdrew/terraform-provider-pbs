package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// The list has the namespaces below the parent, or the root, sorted, without
// the parent, down to max_depth levels.
func TestNamespacesDataSource(t *testing.T) {
	h, fake, namespaces := newNamespaceHarness(t)
	for _, ns := range []string{"dept2", "dept1", "dept1/hosts", "dept1/hosts/web", "dept1/vms"} {
		namespaces.addNamespace("store1", ns)
	}

	state := h.readDataSource(t, "pbs_namespaces", h.dataSourceValue(t, "pbs_namespaces", map[string]any{"store": "store1"}))
	want := h.dataSourceValue(t, "pbs_namespaces", map[string]any{
		"store":      "store1",
		"namespaces": []any{"dept1", "dept1/hosts", "dept1/hosts/web", "dept1/vms", "dept2"},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
	if query := fake.lastCall(t, fakeNamespaceRoute("GET", "store1")).query; len(query) != 0 {
		t.Errorf("query = %v, want none", query)
	}

	state = h.readDataSource(t, "pbs_namespaces", h.dataSourceValue(t, "pbs_namespaces", map[string]any{
		"store": "store1", "parent": "dept1", "max_depth": 1,
	}))
	want = h.dataSourceValue(t, "pbs_namespaces", map[string]any{
		"store": "store1", "parent": "dept1", "max_depth": 1, "namespaces": []any{"dept1/hosts", "dept1/vms"},
	})
	if !state.Equal(want) {
		t.Errorf("state = %s, want %s", state, want)
	}
	if query := fake.lastCall(t, fakeNamespaceRoute("GET", "store1")).query; query.Get("parent") != "dept1" || query.Get("max-depth") != "1" {
		t.Errorf("query = %v", query)
	}

	// A namespace without namespaces below has an empty list, not null.
	state = h.readDataSource(t, "pbs_namespaces", h.dataSourceValue(t, "pbs_namespaces", map[string]any{"store": "store1", "parent": "dept2"}))
	if isNullAt(t, state, "namespaces") || lengthAt(t, state, "namespaces") != 0 {
		t.Errorf("state = %s, want an empty list", state)
	}
}

// PBS would list a missing parent as if it existed; the data source says
// it does not. A missing or unavailable datastore is an error too.
func TestNamespacesDataSourceErrors(t *testing.T) {
	h, _, namespaces := newNamespaceHarness(t)
	namespaces.addNamespace("store1", "dept1")

	for attrs, want := range map[[2]string]string{
		{"store1", "missing"}:     `has no namespace "missing"`,
		{"store1", "dept1/typo"}:  `has no namespace "dept1/typo"`,
		{"store9", ""}:            `PBS has no datastore "store9"`,
		{"store9", "dept1/hosts"}: `PBS has no datastore "store9"`,
	} {
		config := map[string]any{"store": attrs[0]}
		if attrs[1] != "" {
			config["parent"] = attrs[1]
		}
		resp := h.readDataSourceResponse(t, "pbs_namespaces", h.dataSourceValue(t, "pbs_namespaces", config))
		requireProtocolErrorContaining(t, resp.Diagnostics, want)
	}

	namespaces.setUnavailable("store1", "datastore 'store1' is unavailable: offline maintenance mode")
	resp := h.readDataSourceResponse(t, "pbs_namespaces", h.dataSourceValue(t, "pbs_namespaces", map[string]any{"store": "store1"}))
	requireProtocolErrorContaining(t, resp.Diagnostics, "cannot open datastore")

	for name, config := range map[string]map[string]any{
		"depth 0":      {"store": "store1", "max_depth": 0},
		"depth 8":      {"store": "store1", "max_depth": 8},
		"slash parent": {"store": "store1", "parent": "/dept1"},
	} {
		t.Run(name, func(t *testing.T) {
			validated, err := h.server.ValidateDataResourceConfig(context.Background(), &tfprotov6.ValidateDataResourceConfigRequest{
				TypeName: "pbs_namespaces",
				Config:   dynamicValue(t, h.dataSourceValue(t, "pbs_namespaces", config)),
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(validated.Diagnostics) == 0 {
				t.Errorf("config %v was accepted", config)
			}
		})
	}
}
