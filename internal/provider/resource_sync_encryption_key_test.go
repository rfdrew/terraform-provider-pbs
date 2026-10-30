package provider

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestSyncEncryptionKeySchemasAreValid(t *testing.T) {
	requireValidResourceSchema(t, &syncEncryptionKeyResource{})
	requireValidDataSourceSchema(t, &syncEncryptionKeysDataSource{})
}

// fakeVersionBeforeKeys is GET /version of PBS 4.1.9, which has sync
// encryption keys already, but is older than the 4.2 the provider needs for
// them.
const fakeVersionBeforeKeys = `{"data":{"release":"9","repoid":"0123456789abcdef","version":"4.1"}}`

// newKeysHarness is a fake PBS with the sync job and sync encryption key API
// and a provider signed in to it. version, when set, is what GET /version
// answers.
func newKeysHarness(t *testing.T, version ...string) (*protocolHarness, *fakePBS, *fakeSync, *fakeEncryptionKeys) {
	t.Helper()
	fake := newFakePBS()
	if len(version) > 0 {
		fake.reply("GET /version", http.StatusOK, version[0])
	}
	syncs := newFakeSync(fake, nil)
	keys := newFakeEncryptionKeys(fake, syncs)
	return newProtocolHarness(t, fake), fake, syncs, keys
}

// keyConfig is the configuration of a pbs_sync_encryption_key.
func keyConfig(t *testing.T, h *protocolHarness, attrs map[string]any) tftypes.Value {
	t.Helper()
	return h.resourceValue(t, "pbs_sync_encryption_key", attrs)
}

// testKey is the key of testKeyFile, 32 bytes, and testKeyCreated when it
// was created.
var testKey = []byte("0123456789abcdef0123456789abcdef")

const testKeyCreated = "2026-03-01T10:00:00+01:00"

// keyFileOmit marks a field testKeyFile leaves out.
type keyFileOmit struct{}

// testKeyFile is a key file of key without a password, as
// `proxmox-backup-client key create --kdf none` writes it, with edit's
// fields on top: keyFileOmit{} leaves a field out.
func testKeyFile(t *testing.T, key []byte, edit map[string]any) string {
	t.Helper()
	file := map[string]any{"kdf": nil, "created": testKeyCreated, "modified": testKeyCreated,
		"data": base64.StdEncoding.EncodeToString(key), "fingerprint": fakeKeyFingerprint(key)}
	for name, value := range edit {
		if _, omit := value.(keyFileOmit); omit {
			delete(file, name)
			continue
		}
		file[name] = value
	}
	text, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

// keyToggles counts the toggles of key id's archived state.
func keyToggles(fake *fakePBS, id string) int {
	return fake.count("POST /config/encryption-keys/" + id)
}

// A key PBS generates is created with its ID alone; state gets what the list
// says of it, never the key, which PBS answers once and the provider drops.
// Destroying it archives it first, as PBS deletes only archived keys.
func TestSyncEncryptionKeyGenerated(t *testing.T) {
	h, fake, _, keys := newKeysHarness(t)
	config := keyConfig(t, h, map[string]any{"id": "offsite-2026"})

	planned := h.decodeResource(t, "pbs_sync_encryption_key", h.plan(t, "pbs_sync_encryption_key", nil, config).PlannedState)
	if boolAt(t, planned, "archived") || !isNullAt(t, planned, "archived_at") || !isUnknownAt(t, planned, "fingerprint") ||
		!isUnknownAt(t, planned, "created") {
		t.Errorf("plan = %s, want archived false, archived_at null, fingerprint and created unknown", planned)
	}
	inst := h.create(t, "pbs_sync_encryption_key", config)
	if got := fake.lastCall(t, "POST /config/encryption-keys").form; len(got) != 1 || got.Get("id") != "offsite-2026" {
		t.Errorf("POST form = %v, want the ID alone", got)
	}
	stored, ok := keys.key("offsite-2026")
	if !ok {
		t.Fatal("PBS has no key offsite-2026")
	}
	if stringAt(t, inst.state, "fingerprint") != stored["fingerprint"] || int64At(t, inst.state, "created") != stored["created"] ||
		boolAt(t, inst.state, "archived") || !isNullAt(t, inst.state, "archived_at") || !isNullAt(t, inst.state, "key_wo") ||
		!isNullAt(t, inst.state, "key_wo_version") {
		t.Errorf("state = %s, want what PBS lists: %v", inst.state, stored)
	}
	if data := keys.keyData("offsite-2026"); data == "" || strings.Contains(inst.state.String(), data) {
		t.Errorf("state holds the generated key: %s", inst.state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_sync_encryption_key", inst.identity), "id"); got != "offsite-2026" {
		t.Errorf("identity id = %q", got)
	}
	if n := keyToggles(fake, "offsite-2026"); n != 0 {
		t.Errorf("a key that is not to be archived was toggled %d times", n)
	}
	replan := h.plan(t, "pbs_sync_encryption_key", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_sync_encryption_key", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}
	if refreshed := h.refresh(t, inst); !refreshed.state.Equal(inst.state) {
		t.Errorf("refresh = %s, want %s", refreshed.state, inst.state)
	}

	// A key that exists is imported, not created again.
	applied := h.apply(t, "pbs_sync_encryption_key", nil, config, h.plan(t, "pbs_sync_encryption_key", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "import it")

	before := len(fake.routes())
	h.destroy(t, inst)
	want := []string{"GET /config/encryption-keys", "POST /config/encryption-keys/offsite-2026", "DELETE /config/encryption-keys/offsite-2026"}
	if got := fake.routes()[before:]; !slices.Equal(got, want) {
		t.Errorf("destroy routes = %v, want %v", got, want)
	}
	if toggle := fake.lastCall(t, "POST /config/encryption-keys/offsite-2026"); toggle.form.Get("digest") == "" {
		t.Errorf("toggle form = %v, want the digest of the list", toggle.form)
	}
	if _, exists := keys.key("offsite-2026"); exists {
		t.Error("the key still exists")
	}
}

// A key of one's own is sent once, when the key is created, and kept out of
// state; PBS lists its own fingerprint and creation time. A new
// key_wo_version or ID replaces the key.
func TestSyncEncryptionKeyImported(t *testing.T) {
	h, fake, _, keys := newKeysHarness(t)
	file := testKeyFile(t, testKey, nil)
	config := keyConfig(t, h, map[string]any{"id": "own-key", "key_wo": file, "key_wo_version": 1})
	inst := h.create(t, "pbs_sync_encryption_key", config)

	created := fake.lastCall(t, "POST /config/encryption-keys")
	if created.form.Get("id") != "own-key" || created.form.Get("key") != file {
		t.Errorf("POST form = %v, want the ID and the key file", created.form)
	}
	if got := keys.keyData("own-key"); got != base64.StdEncoding.EncodeToString(testKey) {
		t.Errorf("PBS stored key %q, want the one given", got)
	}
	createdAt, err := time.Parse(time.RFC3339, testKeyCreated)
	if err != nil {
		t.Fatal(err)
	}
	if stringAt(t, inst.state, "fingerprint") != fakeKeyFingerprint(testKey) || int64At(t, inst.state, "created") != createdAt.Unix() ||
		!isNullAt(t, inst.state, "key_wo") || int64At(t, inst.state, "key_wo_version") != 1 {
		t.Errorf("state = %s", inst.state)
	}
	if strings.Contains(inst.state.String(), base64.StdEncoding.EncodeToString(testKey)) {
		t.Errorf("state holds the key: %s", inst.state)
	}
	replan := h.plan(t, "pbs_sync_encryption_key", inst, config)
	requireNoProtocolErrors(t, replan.Diagnostics)
	if planned := h.decodeResource(t, "pbs_sync_encryption_key", replan.PlannedState); !planned.Equal(inst.state) {
		diffs, _ := planned.Diff(inst.state)
		t.Fatalf("plan after apply changes %v", diffs)
	}

	for attribute, attrs := range map[string]map[string]any{
		"key_wo_version": {"id": "own-key", "key_wo": file, "key_wo_version": 2},
		"id":             {"id": "own-key-2", "key_wo": file, "key_wo_version": 1},
	} {
		planned := h.plan(t, "pbs_sync_encryption_key", inst, keyConfig(t, h, attrs))
		requireNoProtocolErrors(t, planned.Diagnostics)
		if len(planned.RequiresReplace) != 1 || !strings.Contains(planned.RequiresReplace[0].String(), attribute) {
			t.Errorf("a new %s: RequiresReplace = %v", attribute, planned.RequiresReplace)
		}
	}

	// archived changes in place, and the version stays.
	inst = h.update(t, inst, keyConfig(t, h, map[string]any{"id": "own-key", "key_wo": file, "key_wo_version": 1, "archived": true}))
	if int64At(t, inst.state, "key_wo_version") != 1 || !boolAt(t, inst.state, "archived") {
		t.Errorf("state = %s", inst.state)
	}
	// Removing key_wo and key_wo_version leaves the key as it is, as it
	// leaves the secret of the other write-only pairs: replacing it would
	// delete a key backups may need.
	removed := keyConfig(t, h, map[string]any{"id": "own-key", "archived": true})
	planned := h.plan(t, "pbs_sync_encryption_key", inst, removed)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 0 {
		t.Errorf("removing key_wo_version: RequiresReplace = %v", planned.RequiresReplace)
	}
	creates := fake.count("POST /config/encryption-keys")
	inst = h.update(t, inst, removed)
	if fake.count("POST /config/encryption-keys") != creates || fake.count("DELETE /config/encryption-keys/own-key") != 0 ||
		keys.keyData("own-key") != base64.StdEncoding.EncodeToString(testKey) || !isNullAt(t, inst.state, "key_wo_version") {
		t.Errorf("removing key_wo_version replaced the key, or kept the version: %s", inst.state)
	}

	// A key file without a fingerprint, its key in base64 without padding:
	// PBS stores no fingerprint.
	bare := testKeyFile(t, []byte("abcdefghijklmnopqrstuvwxyz012345"), map[string]any{
		"fingerprint": keyFileOmit{}, "kdf": keyFileOmit{},
		"data": base64.RawStdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345")),
	})
	inst = h.create(t, "pbs_sync_encryption_key", keyConfig(t, h, map[string]any{"id": "bare-key", "key_wo": bare, "key_wo_version": 1}))
	if !isNullAt(t, inst.state, "fingerprint") {
		t.Errorf("state = %s, want no fingerprint", inst.state)
	}

	// PBS refuses a key file whose fingerprint is another key's; the error
	// leaves the key out.
	wrong := testKeyFile(t, testKey, map[string]any{"fingerprint": fakeKeyFingerprint([]byte("another key, 32 bytes long......"))})
	config = keyConfig(t, h, map[string]any{"id": "wrong-key", "key_wo": wrong, "key_wo_version": 1})
	applied := h.apply(t, "pbs_sync_encryption_key", nil, config, h.plan(t, "pbs_sync_encryption_key", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "failed to load provided key")
	for _, d := range applied.Diagnostics {
		if strings.Contains(d.Detail, base64.StdEncoding.EncodeToString(testKey)) {
			t.Errorf("the error repeats the key: %s", d.Detail)
		}
	}
	if _, exists := keys.key("wrong-key"); exists {
		t.Error("PBS stored a key with a wrong fingerprint")
	}
}

// key_wo is checked before PBS sees it, as PBS takes only a key file without
// a password, and crashes on a key of another length; errors never show it.
func TestSyncEncryptionKeyValidation(t *testing.T) {
	h, _, _, _ := newKeysHarness(t)
	key := base64.StdEncoding.EncodeToString(testKey)
	for name, file := range map[string]string{
		"password": testKeyFile(t, testKey, map[string]any{"kdf": map[string]any{
			"Scrypt": map[string]any{"n": 65536, "r": 8, "p": 1, "salt": "c2FsdHNhbHRzYWx0c2FsdA=="}}}),
		"short key":   testKeyFile(t, testKey, map[string]any{"data": base64.StdEncoding.EncodeToString(testKey[:31])}),
		"long key":    testKeyFile(t, testKey, map[string]any{"data": base64.StdEncoding.EncodeToString(append(slices.Clone(testKey), 'x'))}),
		"not base64":  testKeyFile(t, testKey, map[string]any{"data": "not*base64!" + key}),
		"no created":  testKeyFile(t, testKey, map[string]any{"created": keyFileOmit{}}),
		"no modified": testKeyFile(t, testKey, map[string]any{"modified": keyFileOmit{}}),
		"no data":     testKeyFile(t, testKey, map[string]any{"data": keyFileOmit{}}),
		"not JSON":    "kdf: none\ndata: " + key,
		"paper key":   "-----BEGIN PROXMOX BACKUP KEY-----\n" + key + "\n-----END PROXMOX BACKUP KEY-----",
	} {
		t.Run(name, func(t *testing.T) {
			diags := h.validateResource(t, "pbs_sync_encryption_key", keyConfig(t, h, map[string]any{
				"id": "own-key", "key_wo": file, "key_wo_version": 1,
			}))
			requireProtocolErrorContaining(t, diags, "must be a key file without a password")
			for _, d := range diags {
				if strings.Contains(d.Detail, file) || strings.Contains(d.Detail, key) || strings.Contains(d.Detail, testKeyCreated) {
					t.Errorf("the error repeats the key file: %s", d.Detail)
				}
			}
		})
	}
	for name, file := range map[string]string{
		"kdf null":            testKeyFile(t, testKey, nil),
		"no kdf":              testKeyFile(t, testKey, map[string]any{"kdf": keyFileOmit{}}),
		"unpadded":            testKeyFile(t, testKey, map[string]any{"data": base64.RawStdEncoding.EncodeToString(testKey)}),
		"hint and extra keys": testKeyFile(t, testKey, map[string]any{"hint": "laptop", "comment": "ignored"}),
	} {
		t.Run("valid "+name, func(t *testing.T) {
			requireNoProtocolErrors(t, h.validateResource(t, "pbs_sync_encryption_key", keyConfig(t, h, map[string]any{
				"id": "own-key", "key_wo": file, "key_wo_version": 1,
			})))
		})
	}
	for name, tc := range map[string]struct {
		attrs map[string]any
		want  string
	}{
		"key without version": {map[string]any{"id": "own-key", "key_wo": testKeyFile(t, testKey, nil)}, "key_wo_version"},
		"version without key": {map[string]any{"id": "own-key", "key_wo_version": 1}, "key_wo"},
		"short ID":            {map[string]any{"id": "ab"}, "id"},
		"ID with a slash":     {map[string]any{"id": "keys/offsite"}, "id"},
	} {
		t.Run(name, func(t *testing.T) {
			requireProtocolErrorContaining(t, h.validateResource(t, "pbs_sync_encryption_key", keyConfig(t, h, tc.attrs)), tc.want)
		})
	}
}

// archived toggles the key only when PBS has it otherwise, which the provider
// reads first, as PBS only toggles; archived_at is planned null for a key in
// use, kept while the key stays archived, and unknown when it is archived
// now.
func TestSyncEncryptionKeyArchived(t *testing.T) {
	h, fake, _, keys := newKeysHarness(t)
	archived := keyConfig(t, h, map[string]any{"id": "old-key", "archived": true})
	active := keyConfig(t, h, map[string]any{"id": "old-key", "archived": false})

	planned := h.decodeResource(t, "pbs_sync_encryption_key", h.plan(t, "pbs_sync_encryption_key", nil, archived).PlannedState)
	if !isUnknownAt(t, planned, "archived_at") {
		t.Errorf("plan = %s, want archived_at unknown", planned)
	}
	inst := h.create(t, "pbs_sync_encryption_key", archived)
	stored, _ := keys.key("old-key")
	if keyToggles(fake, "old-key") != 1 || stored["archived-at"] == nil {
		t.Fatalf("toggles = %d, key = %v, want it archived once", keyToggles(fake, "old-key"), stored)
	}
	if !boolAt(t, inst.state, "archived") || int64At(t, inst.state, "archived_at") != stored["archived-at"] {
		t.Errorf("state = %s, want archived at %v", inst.state, stored["archived-at"])
	}

	// Archived it stays: archived_at is kept, and an apply toggles nothing.
	planned = h.decodeResource(t, "pbs_sync_encryption_key", h.plan(t, "pbs_sync_encryption_key", inst, archived).PlannedState)
	if !planned.Equal(inst.state) {
		t.Errorf("plan = %s, want state %s", planned, inst.state)
	}
	inst = h.update(t, inst, archived)
	if n := keyToggles(fake, "old-key"); n != 1 {
		t.Errorf("toggles = %d after an apply without changes, want 1", n)
	}

	planned = h.decodeResource(t, "pbs_sync_encryption_key", h.plan(t, "pbs_sync_encryption_key", inst, active).PlannedState)
	if !isNullAt(t, planned, "archived_at") {
		t.Errorf("plan = %s, want archived_at null", planned)
	}
	inst = h.update(t, inst, active)
	if stored, _ = keys.key("old-key"); keyToggles(fake, "old-key") != 2 || stored["archived-at"] != nil {
		t.Errorf("toggles = %d, key = %v, want it back in use", keyToggles(fake, "old-key"), stored)
	}

	planned = h.decodeResource(t, "pbs_sync_encryption_key", h.plan(t, "pbs_sync_encryption_key", inst,
		keyConfig(t, h, map[string]any{"id": "old-key", "archived": tfUnknown})).PlannedState)
	if !isUnknownAt(t, planned, "archived_at") {
		t.Errorf("plan = %s, want archived_at unknown while archived is", planned)
	}

	// Archived by someone else since state was read: the update finds it
	// archived and toggles nothing.
	keys.archiveKey("old-key")
	inst = h.update(t, inst, archived)
	stored, _ = keys.key("old-key")
	if keyToggles(fake, "old-key") != 2 || stored["archived-at"] == nil {
		t.Errorf("toggles = %d, key = %v, want the key left archived", keyToggles(fake, "old-key"), stored)
	}
	if int64At(t, inst.state, "archived_at") != stored["archived-at"] {
		t.Errorf("state = %s, want archived at %v", inst.state, stored["archived-at"])
	}

	// A key archived or deleted outside Terraform shows on refresh.
	inst = h.update(t, inst, active)
	keys.archiveKey("old-key")
	if refreshed := h.refresh(t, inst); !boolAt(t, refreshed.state, "archived") {
		t.Errorf("refresh = %s, want the key archived", refreshed.state)
	}
	keys.deleteKey("old-key")
	if refreshed := h.refresh(t, inst); !refreshed.state.IsNull() {
		t.Errorf("refresh kept a deleted key: %s", refreshed.state)
	}
}

// keyRaceTransport archives a key, as another client would, just before the
// provider first toggles it, so that the toggle's digest is stale.
type keyRaceTransport struct {
	fake *fakePBS
	keys *fakeEncryptionKeys
	id   string
	once sync.Once
}

func (r *keyRaceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/config/encryption-keys/"+r.id) {
		r.once.Do(func() { r.keys.archiveKey(r.id) })
	}
	return r.fake.RoundTrip(req)
}

// A toggle with a stale digest is refused, and the retry reads the key
// again: toggling blindly would bring back into use the key someone else
// archived meanwhile.
func TestSyncEncryptionKeyArchiveRetriesOnStaleDigest(t *testing.T) {
	fake := newFakePBS()
	syncs := newFakeSync(fake, nil)
	keys := newFakeEncryptionKeys(fake, syncs)
	keys.addKey("old-key", nil)
	h := newProtocolHarness(t, fake, withTransport(&keyRaceTransport{fake: fake, keys: keys, id: "old-key"}))

	inst := h.importByID(t, "pbs_sync_encryption_key", "old-key")
	inst = h.update(t, inst, keyConfig(t, h, map[string]any{"id": "old-key", "archived": true}))
	stored, _ := keys.key("old-key")
	if keyToggles(fake, "old-key") != 1 || stored["archived-at"] == nil {
		t.Errorf("toggles = %d, key = %v, want the stale toggle alone and the key archived", keyToggles(fake, "old-key"), stored)
	}
	if !boolAt(t, inst.state, "archived") {
		t.Errorf("state = %s", inst.state)
	}
}

// PBS archives no active key of a sync job, and deletes no key a sync job
// holds; a key the provider archived to delete it is brought back into use
// when the delete fails. A key already gone is no error.
func TestSyncEncryptionKeyDestroy(t *testing.T) {
	for name, tc := range map[string]struct {
		archived bool
		jobs     map[string]fakeProperties
		// toggles is how many times the destroy asks PBS to toggle the key,
		// refused requests included; wantError what it fails with, "" for
		// success.
		toggles   int
		wantError string
	}{
		"in use":   {toggles: 1},
		"archived": {archived: true},
		"active key of a job": {
			jobs:      map[string]fakeProperties{"push-offsite": {"sync-direction": "push", "active-encryption-key": "old-key"}},
			toggles:   1,
			wantError: "encryption key in use by sync job: 'push-offsite'",
		},
		"associated key of a job": {
			jobs:      map[string]fakeProperties{"push-offsite": {"sync-direction": "push", "associated-key": []string{"old-key"}}},
			toggles:   2,
			wantError: "encryption key in use by sync job: 'push-offsite'",
		},
		"associated key of jobs, archived": {
			archived: true,
			jobs: map[string]fakeProperties{
				"push-offsite": {"sync-direction": "push", "associated-key": []string{"other", "old-key"}},
				"pull-offsite": {"associated-key": []string{"old-key"}},
			},
			wantError: "encryption key in use by sync jobs: 'pull-offsite, push-offsite'",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, fake, syncs, keys := newKeysHarness(t)
			props := fakeProperties{}
			if tc.archived {
				props["archived-at"] = int64(1793000000)
			}
			keys.addKey("old-key", props)
			for id, job := range tc.jobs {
				job = cloneProperties(job)
				job["store"], job["remote"], job["remote-store"] = "store1", "offsite", "store2"
				syncs.addSyncJob(id, job)
			}
			inst := h.importByID(t, "pbs_sync_encryption_key", "old-key")

			resp := syncDestroyResponse(t, h, inst)
			if n := keyToggles(fake, "old-key"); n != tc.toggles {
				t.Errorf("toggles = %d, want %d", n, tc.toggles)
			}
			stored, exists := keys.key("old-key")
			if tc.wantError == "" {
				requireNoProtocolErrors(t, resp.Diagnostics)
				if exists {
					t.Errorf("the key still exists: %v", stored)
				}
				return
			}
			requireProtocolErrorContaining(t, resp.Diagnostics, tc.wantError)
			requireProtocolErrorContaining(t, resp.Diagnostics, "Set another active_encryption_key")
			if !exists || (stored["archived-at"] != nil) != tc.archived {
				t.Errorf("key = %v, exists %v, want it as it was", stored, exists)
			}
		})
	}

	// A key the list does not show is deleted all the same: PBS answers
	// success for a key that is gone, and refuses to delete one the caller
	// may not audit, which the list leaves out.
	h, fake, _, keys := newKeysHarness(t)
	keys.addKey("gone-key", nil)
	inst := h.importByID(t, "pbs_sync_encryption_key", "gone-key")
	keys.deleteKey("gone-key")
	requireNoProtocolErrors(t, syncDestroyResponse(t, h, inst).Diagnostics)
	if fake.count("DELETE /config/encryption-keys/gone-key") != 1 || keyToggles(fake, "gone-key") != 0 {
		t.Errorf("a key that is gone: %d deletions, %d toggles, want one deletion only",
			fake.count("DELETE /config/encryption-keys/gone-key"), keyToggles(fake, "gone-key"))
	}

	keys.addKey("hidden-key", nil)
	inst = h.importByID(t, "pbs_sync_encryption_key", "hidden-key")
	keys.hide("hidden-key")
	resp := syncDestroyResponse(t, h, inst)
	requireProtocolErrorContaining(t, resp.Diagnostics, "PBS does not list sync encryption key \"hidden-key\", and refuses")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Audit on /system/encryption-keys/hidden-key")
	if _, exists := keys.key("hidden-key"); !exists {
		t.Error("the hidden key was deleted")
	}
}

// A key_wo_version set on a key that has none in state — imported, or
// generated by PBS — replaces the key only when key_wo holds another key, as
// the fingerprints tell.
func TestSyncEncryptionKeyVersionAfterImport(t *testing.T) {
	h, fake, _, keys := newKeysHarness(t)
	file := testKeyFile(t, testKey, nil)
	h.create(t, "pbs_sync_encryption_key", keyConfig(t, h, map[string]any{"id": "own-key", "key_wo": file, "key_wo_version": 1}))
	inst := h.importByID(t, "pbs_sync_encryption_key", "own-key")
	if !isNullAt(t, inst.state, "key_wo_version") {
		t.Fatalf("imported state = %s", inst.state)
	}

	same := keyConfig(t, h, map[string]any{"id": "own-key", "key_wo": file, "key_wo_version": 1})
	planned := h.plan(t, "pbs_sync_encryption_key", inst, same)
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 0 {
		t.Errorf("the key PBS has: RequiresReplace = %v", planned.RequiresReplace)
	}
	posts, deletes := fake.count("POST /config/encryption-keys"), fake.count("DELETE /config/encryption-keys/own-key")
	inst = h.update(t, inst, same)
	if int64At(t, inst.state, "key_wo_version") != 1 || fake.count("POST /config/encryption-keys") != posts ||
		fake.count("DELETE /config/encryption-keys/own-key") != deletes {
		t.Errorf("recording the version of the key PBS has changed the key: %s", inst.state)
	}

	keys.addKey("generated-key", nil)
	generated := h.importByID(t, "pbs_sync_encryption_key", "generated-key")
	planned = h.plan(t, "pbs_sync_encryption_key", generated, keyConfig(t, h, map[string]any{
		"id": "generated-key", "key_wo": file, "key_wo_version": 1,
	}))
	requireNoProtocolErrors(t, planned.Diagnostics)
	if len(planned.RequiresReplace) != 1 || !strings.Contains(planned.RequiresReplace[0].String(), "key_wo_version") {
		t.Errorf("another key: RequiresReplace = %v", planned.RequiresReplace)
	}
	requireProtocolWarningContaining(t, planned.Diagnostics, "Replacing the key deletes it")
	requireProtocolWarningContaining(t, planned.Diagnostics, "Terraform never held this key")

	// A key_wo not known until apply cannot be compared: the plan fails
	// rather than have the action change at apply.
	planned = h.plan(t, "pbs_sync_encryption_key", generated, keyConfig(t, h, map[string]any{
		"id": "generated-key", "key_wo": tfUnknown, "key_wo_version": 1,
	}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "Key not known yet")

	// A new version, and a new ID, replace a key Terraform holds, with the
	// same warning.
	for name, attrs := range map[string]map[string]any{
		"version": {"id": "own-key", "key_wo": file, "key_wo_version": 2},
		"id":      {"id": "own-key-2", "key_wo": file, "key_wo_version": 1},
	} {
		planned = h.plan(t, "pbs_sync_encryption_key", inst, keyConfig(t, h, attrs))
		requireNoProtocolErrors(t, planned.Diagnostics)
		requireProtocolWarningContaining(t, planned.Diagnostics, "Replacing the key deletes it")
		if hasProtocolWarning(planned.Diagnostics, "Terraform never held this key") {
			t.Errorf("a new %s: the warning says Terraform never held the key", name)
		}
	}

	// Without a fingerprint to compare, the key stays, with a warning.
	keys.addKey("bare-key", fakeProperties{"fingerprint": nil})
	bare := h.importByID(t, "pbs_sync_encryption_key", "bare-key")
	planned = h.plan(t, "pbs_sync_encryption_key", bare, keyConfig(t, h, map[string]any{
		"id": "bare-key", "key_wo": file, "key_wo_version": 1,
	}))
	requireProtocolWarningContaining(t, planned.Diagnostics, "Key not compared")
	if len(planned.RequiresReplace) != 0 {
		t.Errorf("no fingerprint: RequiresReplace = %v", planned.RequiresReplace)
	}
}

// A key imports by ID, or by identity, with what PBS lists; the key itself
// cannot be imported.
func TestSyncEncryptionKeyImport(t *testing.T) {
	h, _, _, keys := newKeysHarness(t)
	keys.addKey("offsite-2025", fakeProperties{"archived-at": int64(1793300000)})
	stored, _ := keys.key("offsite-2025")

	for name, inst := range map[string]*resourceInstance{
		"id":       h.importByID(t, "pbs_sync_encryption_key", "offsite-2025"),
		"identity": h.importByIdentity(t, "pbs_sync_encryption_key", map[string]any{"id": "offsite-2025"}),
	} {
		if stringAt(t, inst.state, "id") != "offsite-2025" || !boolAt(t, inst.state, "archived") ||
			int64At(t, inst.state, "archived_at") != 1793300000 || stringAt(t, inst.state, "fingerprint") != stored["fingerprint"] ||
			int64At(t, inst.state, "created") != stored["created"] || !isNullAt(t, inst.state, "key_wo_version") {
			t.Errorf("import by %s = %s", name, inst.state)
		}
		planned := h.plan(t, "pbs_sync_encryption_key", inst, keyConfig(t, h, map[string]any{"id": "offsite-2025", "archived": true}))
		requireNoProtocolErrors(t, planned.Diagnostics)
		if got := h.decodeResource(t, "pbs_sync_encryption_key", planned.PlannedState); !got.Equal(inst.state) {
			diffs, _ := got.Diff(inst.state)
			t.Errorf("plan after import by %s changes %v", name, diffs)
		}
	}

	resp := h.importResource(t, "pbs_sync_encryption_key", "keys/offsite", nil)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unexpected import identifier")
}

// PBS lists only the keys the caller has Sys.Audit on: a key created but not
// listed is recorded, tainted, with an error naming the privilege.
func TestSyncEncryptionKeyCreatedButNotListed(t *testing.T) {
	h, _, _, keys := newKeysHarness(t)
	keys.hide("hidden-key")
	config := keyConfig(t, h, map[string]any{"id": "hidden-key"})
	applied := h.apply(t, "pbs_sync_encryption_key", nil, config, h.plan(t, "pbs_sync_encryption_key", nil, config))
	requireProtocolErrorContaining(t, applied.Diagnostics, "Sys.Audit on /system/encryption-keys/hidden-key")
	requireProtocolErrorContaining(t, applied.Diagnostics, "marked tainted")
	state := h.decodeResource(t, "pbs_sync_encryption_key", applied.NewState)
	if state.IsNull() || stringAt(t, state, "id") != "hidden-key" || !isNullAt(t, state, "fingerprint") {
		t.Errorf("state = %s, want the key recorded", state)
	}
	if got := stringAt(t, h.identityValue(t, "pbs_sync_encryption_key", applied.NewIdentity), "id"); got != "hidden-key" {
		t.Errorf("identity id = %q", got)
	}
	if _, exists := keys.key("hidden-key"); !exists {
		t.Error("PBS has no key hidden-key")
	}
}

// Sync encryption keys need PBS 4.2; destroying one does not.
func TestSyncEncryptionKeyNeedsPBS42(t *testing.T) {
	h, _, _, _ := newKeysHarness(t, fakeVersionBeforeKeys)
	planned := h.plan(t, "pbs_sync_encryption_key", nil, keyConfig(t, h, map[string]any{"id": "offsite-2026"}))
	requireProtocolErrorContaining(t, planned.Diagnostics, "pbs_sync_encryption_key needs PBS 4.2 or newer")

	inst := &resourceInstance{typeName: "pbs_sync_encryption_key", state: h.resourceValue(t, "pbs_sync_encryption_key",
		map[string]any{"id": "offsite-2026", "archived": false, "created": 1793260800})}
	planned = h.plan(t, "pbs_sync_encryption_key", inst, tftypes.NewValue(h.resourceType(t, "pbs_sync_encryption_key"), nil))
	requireNoProtocolErrors(t, planned.Diagnostics)
}

// The data source lists the keys the caller may audit, sorted, archived ones
// included.
func TestSyncEncryptionKeysDataSource(t *testing.T) {
	h, _, _, keys := newKeysHarness(t)
	empty := h.readDataSource(t, "pbs_sync_encryption_keys", h.dataSourceValue(t, "pbs_sync_encryption_keys", map[string]any{}))
	if lengthAt(t, empty, "keys") != 0 {
		t.Errorf("pbs_sync_encryption_keys = %s, want no keys", empty)
	}

	keys.addKey("zeta", nil)
	keys.addKey("alpha", fakeProperties{"archived-at": int64(1793300000)})
	keys.addKey("mid", fakeProperties{"fingerprint": nil})
	keys.addKey("secret", nil)
	keys.hide("secret")
	zeta, _ := keys.key("zeta")

	list := h.readDataSource(t, "pbs_sync_encryption_keys", h.dataSourceValue(t, "pbs_sync_encryption_keys", map[string]any{}))
	var ids []string
	for i := range lengthAt(t, list, "keys") {
		ids = append(ids, stringAt(t, list, "keys", i, "id"))
	}
	if strings.Join(ids, ",") != "alpha,mid,zeta" {
		t.Fatalf("ids = %v, want alpha, mid and zeta, sorted", ids)
	}
	if !boolAt(t, list, "keys", 0, "archived") || int64At(t, list, "keys", 0, "archived_at") != 1793300000 ||
		boolAt(t, list, "keys", 1, "archived") || !isNullAt(t, list, "keys", 1, "archived_at") ||
		!isNullAt(t, list, "keys", 1, "fingerprint") || stringAt(t, list, "keys", 2, "fingerprint") != zeta["fingerprint"] ||
		int64At(t, list, "keys", 2, "created") != zeta["created"] {
		t.Errorf("pbs_sync_encryption_keys = %s", list)
	}
}
