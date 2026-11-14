package provider

import (
	"net/http"
	"slices"
	"testing"
)

func TestSyncEncryptionKeyListResource(t *testing.T) {
	// key-a, key-b, key-c and key-x in use, key-old archived.
	h, fake, _, keys := newSyncKeysHarness(t)
	keys.addKey("hidden", nil)
	keys.hide("hidden")

	// Archived keys are listed; those the caller may not audit PBS leaves
	// out. The list sorts what PBS lists in the order it stored the keys.
	results := h.listedObjects(t, "pbs_sync_encryption_key", listRequest{})
	if got, want := listedIdentities(t, results, "id"), []string{"key-a", "key-b", "key-c", "key-old", "key-x"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
	if results[0].displayName != "key-a" || results[3].displayName != "key-old — archived" {
		t.Fatalf("display names %q, %q", results[0].displayName, results[3].displayName)
	}
	if call := fake.lastCall(t, "GET /config/encryption-keys"); call.query.Get("include-archived") != "1" {
		t.Fatalf("listed with %v", call.query)
	}

	// With resources, each is what importing it gives, and the generated
	// configuration, without key_wo and key_wo_version, keeps the key.
	results = h.listedObjects(t, "pbs_sync_encryption_key", listRequest{includeResource: true})
	if len(results) != 5 {
		t.Fatalf("listed %d keys with resources", len(results))
	}
	for _, result := range results {
		h.requireListedLikeImport(t, "pbs_sync_encryption_key", result)
		if !isNullAt(t, result.resource, "key_wo_version") || !isNullAt(t, result.resource, "key_wo") {
			t.Fatalf("listed %s", result.resource)
		}
	}
	if !boolAt(t, results[3].resource, "archived") || isNullAt(t, results[3].resource, "archived_at") ||
		boolAt(t, results[0].resource, "archived") || stringAt(t, results[0].resource, "fingerprint") == "" {
		t.Fatalf("listed states: %s, %s", results[3].resource, results[0].resource)
	}

	if got := h.listedObjects(t, "pbs_sync_encryption_key", listRequest{limit: 2}); len(got) != 2 {
		t.Fatalf("a limit of 2 listed %d", len(got))
	}
}

// A key deleted between the listing and its read is left out without an
// error.
func TestSyncEncryptionKeyListResourceKeyGone(t *testing.T) {
	h, fake, _, keys := newSyncKeysHarness(t)
	listed := false
	fake.handle("GET /config/encryption-keys", func(w http.ResponseWriter, req *http.Request) {
		keys.list(w, req)
		if !listed {
			listed = true
			keys.deleteKey("key-b")
		}
	})
	results := h.listedObjects(t, "pbs_sync_encryption_key", listRequest{includeResource: true})
	if got, want := listedIdentities(t, results, "id"), []string{"key-a", "key-c", "key-old", "key-x"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
}

// On a server older than PBS 4.2, which pbs_sync_encryption_key refuses,
// the list is empty, with a warning, and asks PBS nothing — also on PBS
// 4.1.9, which has keys already, as the fake does.
func TestSyncEncryptionKeyListResourceBeforePBS42(t *testing.T) {
	h, fake, _, keys := newKeysHarness(t, fakeVersionBeforeKeys)
	keys.addKey("key-a", nil)
	results := h.listResources(t, "pbs_sync_encryption_key", listRequest{includeResource: true})
	if len(results) != 1 || !results[0].identity.IsNull() {
		t.Fatalf("got %d results", len(results))
	}
	requireNoProtocolErrors(t, results[0].diagnostics)
	requireProtocolWarningContaining(t, results[0].diagnostics, "Sync encryption keys need PBS 4.2")
	requireProtocolWarningContaining(t, results[0].diagnostics, "runs PBS 4.1.9, so the list is empty")
	if fake.count("GET /config/encryption-keys") != 0 {
		t.Fatal("the list asked an old PBS for its keys")
	}
}

// A server that reports a release with sync encryption keys but has no
// route for them — a build whose version the provider cannot tell — gets
// an empty list with a warning too; any other failure fails the list block.
func TestSyncEncryptionKeyListResourceErrors(t *testing.T) {
	fake := newFakePBS()
	h := newProtocolHarness(t, fake)
	results := h.listResources(t, "pbs_sync_encryption_key", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireNoProtocolErrors(t, results[0].diagnostics)
	requireProtocolWarningContaining(t, results[0].diagnostics, "PBS has no sync encryption keys")

	fake.reply("GET /config/encryption-keys", http.StatusInternalServerError, "unable to parse encryption-keys.cfg")
	results = h.listResources(t, "pbs_sync_encryption_key", listRequest{})
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	requireProtocolErrorContaining(t, results[0].diagnostics, "Unable to list PBS sync encryption keys")
}
