package pbsclient

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const testKeyFingerprint = "64:d3:ff:3a:50:38:53:5a:9e:2b:1f:6a:5a:1d:4a:42:7c:61:4b:01:f2:15:97:9a:2e:1d:ac:1b:7d:0e:aa:17"

// The list asks for archived keys too and answers its digest; a key reads
// from the list, which leaves out the key itself, and a key the list does
// not hold reads as a missing one, with the digest still.
func TestListAndGetEncryptionKeys(t *testing.T) {
	const digest = "1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014"
	fake := newFakePBS()
	fake.reply("GET /config/encryption-keys", http.StatusOK, `{"data":[`+
		`{"id":"offsite-2026","kdf":"none","created":1793260800,"modified":1793260800,`+
		`"path":"/etc/proxmox-backup/encryption-keys/offsite-2026.enc","fingerprint":"`+testKeyFingerprint+`"},`+
		`{"id":"imported","kdf":"none","created":1772355600,"modified":1772355660,`+
		`"path":"/etc/proxmox-backup/encryption-keys/imported.enc","hint":"old laptop","archived-at":1793264400}`+
		`],"digest":"`+digest+`"}`)
	c := fake.client(t)
	ctx := context.Background()

	keys, gotDigest, err := c.ListEncryptionKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	archivedAt := int64(1793264400)
	want := []EncryptionKey{
		{ID: "offsite-2026", KDF: "none", Created: 1793260800, Modified: 1793260800, Fingerprint: testKeyFingerprint},
		{ID: "imported", KDF: "none", Created: 1772355600, Modified: 1772355660, Hint: "old laptop", ArchivedAt: &archivedAt},
	}
	if !reflect.DeepEqual(keys, want) || gotDigest != digest {
		t.Fatalf("ListEncryptionKeys() = %+v, %q, want %+v, %q", keys, gotDigest, want, digest)
	}
	if keys[0].Archived() || !keys[1].Archived() {
		t.Errorf("Archived() = %v, %v, want false, true", keys[0].Archived(), keys[1].Archived())
	}
	if got := fake.lastCall(t, "GET /config/encryption-keys").query; !reflect.DeepEqual(got, url.Values{"include-archived": {"1"}}) {
		t.Errorf("list query = %v, want include-archived=1", got)
	}

	key, gotDigest, err := c.GetEncryptionKey(ctx, "imported")
	if err != nil || !reflect.DeepEqual(key, want[1]) || gotDigest != digest {
		t.Fatalf("GetEncryptionKey() = %+v, %q, %v", key, gotDigest, err)
	}
	_, gotDigest, err = c.GetEncryptionKey(ctx, "missing")
	if !IsNotFound(err) || !strings.Contains(err.Error(), "no such sync-key 'missing'") || gotDigest != digest {
		t.Fatalf("GetEncryptionKey(missing) = %q, %v, want a not-found error and the digest", gotDigest, err)
	}
	if got := fake.count("GET /config/encryption-keys/missing"); got != 0 {
		t.Errorf("a read of one key was sent %d times; PBS has no such route", got)
	}
}

// A create sends the ID, and the key only when there is one; PBS answers
// with the key file, which the client drops. A toggle sends the digest when
// there is one; a delete sends nothing but the ID in its path.
func TestEncryptionKeyCallsHitTheirRoutes(t *testing.T) {
	const keyFile = `{"kdf":null,"created":"2026-03-01T10:00:00+01:00","modified":"2026-03-01T10:00:00+01:00",` +
		`"data":"q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k="}`
	fake := newFakePBS()
	fake.reply("POST /config/encryption-keys", http.StatusOK, `{"data":{"kdf":null,"created":"2026-10-29T09:00:00+01:00",`+
		`"modified":"2026-10-29T09:00:00+01:00","data":"q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k=","fingerprint":"`+
		testKeyFingerprint+`"}}`)
	fake.reply("POST /config/encryption-keys/offsite-2026", http.StatusOK, `{"data":null}`)
	fake.reply("DELETE /config/encryption-keys/offsite-2026", http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	if err := c.CreateEncryptionKey(ctx, "offsite-2026", ""); err != nil {
		t.Fatalf("CreateEncryptionKey(generated) = %v", err)
	}
	if got := fake.lastCall(t, "POST /config/encryption-keys").form; !reflect.DeepEqual(got, url.Values{"id": {"offsite-2026"}}) {
		t.Errorf("generating form = %v, want the ID alone", got)
	}
	if err := c.CreateEncryptionKey(ctx, "offsite-2026", keyFile); err != nil {
		t.Fatalf("CreateEncryptionKey(imported) = %v", err)
	}
	if got := fake.lastCall(t, "POST /config/encryption-keys").form; !reflect.DeepEqual(got, url.Values{"id": {"offsite-2026"}, "key": {keyFile}}) {
		t.Errorf("importing form = %v, want the ID and the key file", got)
	}

	const digest = "1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014"
	if err := c.ToggleEncryptionKeyArchived(ctx, "offsite-2026", digest); err != nil {
		t.Fatalf("ToggleEncryptionKeyArchived() = %v", err)
	}
	if got := fake.lastCall(t, "POST /config/encryption-keys/offsite-2026").form; !reflect.DeepEqual(got, url.Values{"digest": {digest}}) {
		t.Errorf("toggle form = %v, want the digest", got)
	}
	if err := c.ToggleEncryptionKeyArchived(ctx, "offsite-2026", ""); err != nil {
		t.Fatalf("ToggleEncryptionKeyArchived() = %v", err)
	}
	if got := fake.lastCall(t, "POST /config/encryption-keys/offsite-2026").form; len(got) != 0 {
		t.Errorf("toggle form = %v, want nothing without a digest", got)
	}
	if err := c.DeleteEncryptionKey(ctx, "offsite-2026"); err != nil {
		t.Fatalf("DeleteEncryptionKey() = %v", err)
	}
	if call := fake.lastCall(t, "DELETE /config/encryption-keys/offsite-2026"); len(call.query) != 0 || len(call.form) != 0 {
		t.Errorf("DeleteEncryptionKey query = %v, form = %v, want neither", call.query, call.form)
	}
}

// The key is a secret the client does not otherwise hold, so a create keeps
// it out of PBS's error, should PBS quote it.
func TestCreateEncryptionKeyRedactsTheKey(t *testing.T) {
	const keyFile = `{"kdf":null,"data":"c2VjcmV0LWtleS1tYXRlcmlhbA=="}`
	fake := newFakePBS()
	fake.reply("POST /config/encryption-keys", http.StatusBadRequest,
		`failed to parse provided key: missing field 'created' in {"kdf":null,"data":"c2VjcmV0LWtleS1tYXRlcmlhbA=="}`)
	err := fake.client(t).CreateEncryptionKey(context.Background(), "offsite-2026", keyFile)
	apiErr, ok := asError(err)
	if !ok {
		t.Fatalf("error = %v, want an API error", err)
	}
	if strings.Contains(err.Error(), "c2VjcmV0") || strings.Contains(apiErr.Body, "c2VjcmV0") ||
		!strings.Contains(err.Error(), redactedMarker) || !strings.Contains(err.Error(), "failed to parse provided key") {
		t.Fatalf("error = %v, body = %q, want the key redacted", err, apiErr.Body)
	}
}

// What PBS answers about keys is recognised: a key in use when it is
// archived or deleted, a duplicate ID, a missing key and a stale digest.
// "no such key or cannot access key", a sync job's refusal of a key, reads as
// a missing object too, which the sync job resource guards against.
func TestEncryptionKeyErrorsAreRecognised(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		status            int
		message           string
		inUse, notFound   bool
		exists, conflicts bool
	}{
		{http.StatusBadRequest, "encryption key in use by sync job: 'push-offsite'", true, false, false, false},
		{http.StatusBadRequest, "encryption key in use by sync jobs: 'push-a, push-b'", true, false, false, false},
		{http.StatusInternalServerError, "encryption key in use by sync job: 'push-offsite'", false, false, false, false},
		{http.StatusBadRequest, "key still active, deleting is only possible for archived keys", false, false, false, false},
		{http.StatusBadRequest, "key with id 'offsite-2026' already exists.", false, false, true, false},
		{http.StatusBadRequest, "no such sync-key 'offsite-2026'", false, true, false, false},
		{http.StatusBadRequest, "detected modified configuration - file changed by other user? Try again.", false, false, false, true},
		{http.StatusBadRequest, "no such key or cannot access key 'offsite-2026'", false, true, false, false},
	} {
		fake := newFakePBS()
		fake.reply("POST /config/encryption-keys/offsite-2026", tc.status, tc.message)
		err := fake.client(t).ToggleEncryptionKeyArchived(ctx, "offsite-2026", "")
		if IsEncryptionKeyInUse(err) != tc.inUse || IsNotFound(err) != tc.notFound ||
			IsAlreadyExists(err) != tc.exists || IsDigestConflict(err) != tc.conflicts {
			t.Errorf("%d %q: in use %v, not found %v, exists %v, conflict %v; want %v, %v, %v, %v", tc.status, tc.message,
				IsEncryptionKeyInUse(err), IsNotFound(err), IsAlreadyExists(err), IsDigestConflict(err),
				tc.inUse, tc.notFound, tc.exists, tc.conflicts)
		}
	}
	if IsEncryptionKeyInUse(nil) || IsEncryptionKeyInUse(context.Canceled) {
		t.Error("IsEncryptionKeyInUse reports an error that is not PBS's")
	}
}

// The fingerprint of a key file is the one PBS lists: for the 32-byte key
// 0x00…0x1f, as PBS 4.2's CryptConfig computes it, which Python's hashlib
// computes alike (PBKDF2-HMAC-SHA256 with the salt "_id_key" and 10
// iterations, then SHA-256 over the fingerprint input and that ID key).
func TestKeyFileFingerprint(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	file := `{"kdf":null,"created":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z","data":"` +
		base64.StdEncoding.EncodeToString(key) + `"}`
	got, err := KeyFileFingerprint(file)
	if err != nil {
		t.Fatal(err)
	}
	const want = "0e:ab:d4:46:0b:6e:b9:ca:34:50:23:de:e2:b7:78:c7:90:e5:4a:16:83:b9:65:9c:0a:57:ae:19:90:90:15:9b"
	if got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
	unpadded := strings.Replace(file, base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key), 1)
	if again, err := KeyFileFingerprint(unpadded); err != nil || again != got {
		t.Errorf("unpadded base64: %q, %v, want %q", again, err, got)
	}
	for name, bad := range map[string]string{
		"not JSON":  "{",
		"password":  `{"kdf":{"Scrypt":{}},"data":"` + base64.StdEncoding.EncodeToString(key) + `"}`,
		"short key": `{"kdf":null,"data":"` + base64.StdEncoding.EncodeToString(key[:31]) + `"}`,
		"no key":    `{"kdf":null}`,
	} {
		if _, err := KeyFileFingerprint(bad); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
