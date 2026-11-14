package provider

import (
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestRemoteListResource(t *testing.T) {
	h, fake, syncs, _ := newSyncHarness(t)
	h.create(t, "pbs_remote", remoteConfig(t, h, map[string]any{
		"port": 8443, "fingerprint": testRemoteFingerprint, "comment": "Offsite copy",
		"password_wo": "remote-secret", "password_wo_version": 3,
	}))
	h.create(t, "pbs_remote", remoteConfig(t, h, map[string]any{
		"name": "backup2", "host": "2001:db8::2", "auth_id": "sync@pbs", "use_node_proxy": true,
		"password_wo": "other-secret", "password_wo_version": 1,
	}))

	// Without resources, the list costs one call and names every remote.
	before := len(fake.routes())
	results := h.listedObjects(t, "pbs_remote", listRequest{})
	if got, want := resultDisplayNames(results), []string{"backup2", "offsite — Offsite copy"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if got := fake.routes()[before:]; !slices.Equal(got, []string{"GET /config/remote"}) {
		t.Fatalf("calls %q", got)
	}

	// With resources, each is what importing it gives — without the
	// password, which PBS never shows — and the configuration generated
	// from it plans no change: an imported remote keeps the password PBS
	// has.
	results = h.listedObjects(t, "pbs_remote", listRequest{includeResource: true})
	if len(results) != 2 {
		t.Fatalf("listed %d remotes with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_remote", result)
		if !isNullAt(t, result.resource, "password_wo") || !isNullAt(t, result.resource, "password_wo_version") {
			t.Fatalf("listed remote %s with a password: %s", result.displayName, result.resource)
		}
	}
	backup2, offsite := results[0].resource, results[1].resource
	if !boolAt(t, backup2, "use_node_proxy") || stringAt(t, backup2, "host") != "2001:db8::2" || !isNullAt(t, backup2, "port") {
		t.Fatalf("listed backup2: %s", backup2)
	}
	if stringAt(t, offsite, "fingerprint") != testRemoteFingerprint || int64At(t, offsite, "port") != 8443 {
		t.Fatalf("listed offsite: %s", offsite)
	}
	if syncs.remotePassword("offsite") != "remote-secret" {
		t.Fatal("listing changed a remote's password")
	}

	// A change of name, which replaces the remote, needs the password
	// again.
	generated := h.planGenerated(t, "pbs_remote", results[1])
	attrs := harnessObjectAttributes(t, generated.config)
	attrs["name"] = tftypes.NewValue(tftypes.String, "offsite2")
	planned := h.plan(t, "pbs_remote", generated.imported, tftypes.NewValue(generated.config.Type(), attrs))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Missing remote password")
}

func TestRemoteListResourceListFails(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/remote", 500, "remote.cfg is broken")
	h := newProtocolHarness(t, fake)
	results := h.listResources(t, "pbs_remote", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS remotes")
}
