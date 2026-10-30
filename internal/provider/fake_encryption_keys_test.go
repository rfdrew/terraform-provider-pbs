package provider

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// fakeEncryptionKeys keeps sync encryption keys in memory and serves PBS's
// API for them through a fakePBS, with the behaviour read in PBS 4.2.8's
// source (src/api2/config/encryption_keys.rs, pbs-config/src/encryption_keys.rs
// and pbs-key-config; see internal/pbsclient/encryption_keys.go):
//
//   - GET /config/encryption-keys lists the keys in the order they were
//     stored, without the key material, leaving out archived keys unless
//     include-archived is set, and the keys the caller has no Sys.Audit on
//     (hide); kdf, created, modified and path are always there, fingerprint
//     when the key file had one, archived-at while archived. The digest it
//     answers changes with every write. There is no GET of a single key.
//   - POST /config/encryption-keys stores the key file given in "key" or,
//     without one, generates a key; it answers the key file, key included,
//     with the times in the server's time zone. A key file must parse, with
//     created, modified and data ("failed to parse provided key: ..."), have
//     "kdf" null ("protected keys not supported") and carry the fingerprint
//     of its key, should it carry one ("failed to load provided key: ...");
//     a key that is not 32 bytes long crashes the handler, which the proxy
//     answers with its HTTP client's error, as 400. A duplicate ID is 400
//     "key with id 'x' already exists.", checked after the key.
//   - POST /config/encryption-keys/{id} toggles whether the key is archived,
//     after checking the digest, when given; it refuses to archive the active
//     key of a sync job, "encryption key in use by sync job: 'j'", and a
//     missing key is 400 "no such sync-key 'x'".
//   - DELETE checks the digest, then refuses a key a sync job holds as its
//     active or an associated key, missing or not, then a key that is not
//     archived, "key still active, deleting is only possible for archived
//     keys"; deleting a missing key succeeds.
//
// It is wired to a fakeSync and shares its lock: PBS reads the sync jobs to
// tell whether a key is in use, and checks the keys a sync job names against
// the keys.
//
// Tests set up keys with addKey, hide, archiveKey and deleteKey, and look at
// them with key and keyData.
type fakeEncryptionKeys struct {
	syncs *fakeSync

	// The fields below are guarded by syncs.mu.
	keys map[string]fakeProperties
	// order is the order the keys were stored in, which the list keeps.
	order []string
	// data is each key, base64-encoded, as its key file holds it.
	data map[string]string
	// hidden are the keys the caller has no Sys.Audit on.
	hidden map[string]bool
	// gen counts the writes to encryption-keys.cfg, for its digest.
	gen int
	// clock is the Unix time the next write happens at.
	clock int64
}

// fakeKeyEpoch is when the fake's first key is written: 2026-10-29 08:00
// UTC.
const fakeKeyEpoch = int64(1793260800)

// fakeKeyZone is the server's time zone, in which PBS writes the times of a
// key file.
var fakeKeyZone = time.FixedZone("CET", 3600)

// fakeKeyFingerprintInput is what PBS hashes, with a key's ID key, into the
// key's fingerprint.
var fakeKeyFingerprintInput = sha256.Sum256([]byte("Proxmox Backup Encryption Key Fingerprint"))

// fakeKeyFile is a key file, KeyConfig, as PBS writes it, in its field order.
type fakeKeyFile struct {
	KDF         json.RawMessage `json:"kdf"`
	Created     string          `json:"created"`
	Modified    string          `json:"modified"`
	Data        string          `json:"data"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Hint        string          `json:"hint,omitempty"`
}

// newFakeEncryptionKeys serves the sync encryption key API from fake and
// checks the keys of syncs' jobs against it.
func newFakeEncryptionKeys(fake *fakePBS, syncs *fakeSync) *fakeEncryptionKeys {
	k := &fakeEncryptionKeys{
		syncs:  syncs,
		keys:   map[string]fakeProperties{},
		data:   map[string]string{},
		hidden: map[string]bool{},
		clock:  fakeKeyEpoch,
	}
	syncs.mu.Lock()
	syncs.keys = k
	syncs.mu.Unlock()
	fake.handle("GET /config/encryption-keys", k.list)
	fake.handle("POST /config/encryption-keys", k.create)
	fake.handlePrefix("POST /config/encryption-keys/", k.toggle)
	fake.handlePrefix("DELETE /config/encryption-keys/", k.delete)
	return k
}

// fakeKeyFingerprint is the fingerprint of a key, as PBS computes it: SHA-256
// of a fixed input and the key's ID key, which PBKDF2 derives from the key,
// as colon-separated hex pairs.
func fakeKeyFingerprint(key []byte) string {
	idKey, err := pbkdf2.Key(sha256.New, string(key), []byte("_id_key"), 10, 32)
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	h.Write(fakeKeyFingerprintInput[:])
	h.Write(idKey)
	return fakeColonHex(h.Sum(nil))
}

// fakeColonHex writes bytes as PBS writes a fingerprint: lower-case hex
// pairs separated by colons.
func fakeColonHex(b []byte) string {
	pairs := make([]string, len(b))
	for i, c := range b {
		pairs[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(pairs, ":")
}

// fakeKeyTime writes a Unix time as PBS writes the times of a key file.
func fakeKeyTime(unix int64) string {
	return time.Unix(unix, 0).In(fakeKeyZone).Format(time.RFC3339)
}

// --- test helpers -------------------------------------------------------------

// addKey stores a generated key as PBS would, with props on top of what PBS
// lists: "archived-at", say, or a nil "fingerprint" for a key file without
// one.
func (k *fakeEncryptionKeys) addKey(id string, props fakeProperties) {
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	key := k.generateLocked(id)
	now := k.tickLocked()
	stored := fakeProperties{"id": id, "kdf": "none", "created": now, "modified": now,
		"path": "/etc/proxmox-backup/encryption-keys/" + id + ".enc", "fingerprint": fakeKeyFingerprint(key)}
	for name, value := range props {
		if value == nil {
			delete(stored, name)
			continue
		}
		stored[name] = value
	}
	k.storeLocked(id, stored, key)
}

// key returns a key as PBS stores it, archived or hidden alike.
func (k *fakeEncryptionKeys) key(id string) (fakeProperties, bool) {
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	props, ok := k.keys[id]
	return cloneProperties(props), ok
}

// keyData returns a key itself, base64-encoded, as its key file holds it.
func (k *fakeEncryptionKeys) keyData(id string) string {
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	return k.data[id]
}

// hide leaves a key out of the list, as PBS does for a caller without
// Sys.Audit on it.
func (k *fakeEncryptionKeys) hide(id string) {
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	k.hidden[id] = true
}

// archiveKey archives a key as another client would, which changes the
// digest.
func (k *fakeEncryptionKeys) archiveKey(id string) {
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	k.keys[id]["archived-at"] = k.tickLocked()
	k.gen++
}

// deleteKey deletes a key as another client would.
func (k *fakeEncryptionKeys) deleteKey(id string) {
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	k.removeLocked(id)
}

// --- serving ------------------------------------------------------------------

func (k *fakeEncryptionKeys) digestLocked() string {
	return fakeDigest("encryption-keys.cfg", k.gen)
}

// tickLocked returns the time of a write, a minute after the one before.
func (k *fakeEncryptionKeys) tickLocked() int64 {
	now := k.clock
	k.clock += 60
	return now
}

// generateLocked returns a new key: 32 bytes, which the fake derives from
// the ID and the configuration's generation instead of drawing at random.
func (k *fakeEncryptionKeys) generateLocked(id string) []byte {
	sum := sha256.Sum256([]byte("fake sync encryption key " + id + " " + strconv.Itoa(k.gen)))
	return sum[:]
}

func (k *fakeEncryptionKeys) storeLocked(id string, props fakeProperties, key []byte) {
	k.keys[id] = props
	k.order = append(k.order, id)
	k.data[id] = base64.StdEncoding.EncodeToString(key)
	k.gen++
}

func (k *fakeEncryptionKeys) removeLocked(id string) {
	delete(k.keys, id)
	delete(k.data, id)
	delete(k.hidden, id)
	k.order = slices.DeleteFunc(k.order, func(stored string) bool { return stored == id })
	k.gen++
}

// usableLocked reports whether a sync job may use key: it exists and, with
// failOnArchived, is not archived. Sys.Audit, which hides keys from the list,
// plays no part. The caller holds the lock.
func (k *fakeEncryptionKeys) usableLocked(id string, failOnArchived bool) bool {
	props, ok := k.keys[id]
	if !ok {
		return false
	}
	_, archived := props["archived-at"]
	return !failOnArchived || !archived
}

// fakeKeyInUse is PBS's refusal of a key that sync jobs use.
func fakeKeyInUse(jobs []string) string {
	if len(jobs) == 1 {
		return fmt.Sprintf("encryption key in use by sync job: '%s'", jobs[0])
	}
	return fmt.Sprintf("encryption key in use by sync jobs: '%s'", strings.Join(jobs, ", "))
}

func (k *fakeEncryptionKeys) list(w http.ResponseWriter, req *http.Request) {
	withArchived := fakeBool(req.URL.Query().Get("include-archived"))
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	list := []fakeProperties{}
	for _, id := range k.order {
		props := k.keys[id]
		if _, archived := props["archived-at"]; k.hidden[id] || (archived && !withArchived) {
			continue
		}
		list = append(list, props)
	}
	writeData(w, list, k.digestLocked())
}

// parseKeyFile reads a key file as PBS reads the "key" of a create, and
// returns what PBS stores, or PBS's error.
func parseKeyFile(text string) (file fakeKeyFile, key []byte, created, modified int64, failure string) {
	var parsed struct {
		KDF         json.RawMessage `json:"kdf"`
		Created     *string         `json:"created"`
		Modified    *string         `json:"modified"`
		Data        *string         `json:"data"`
		Fingerprint *string         `json:"fingerprint"`
		Hint        *string         `json:"hint"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return file, nil, 0, 0, "failed to parse provided key: " + err.Error()
	}
	for _, field := range []struct {
		name  string
		value *string
	}{{"created", parsed.Created}, {"modified", parsed.Modified}, {"data", parsed.Data}} {
		if field.value == nil {
			return file, nil, 0, 0, "failed to parse provided key: missing field `" + field.name + "`"
		}
	}
	times := make([]int64, 2)
	for i, value := range []string{*parsed.Created, *parsed.Modified} {
		t, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return file, nil, 0, 0, "failed to parse provided key: " + err.Error()
		}
		times[i] = t.Unix()
	}
	key, err := base64.StdEncoding.DecodeString(*parsed.Data)
	if err != nil {
		if key, err = base64.RawStdEncoding.DecodeString(*parsed.Data); err != nil {
			return file, nil, 0, 0, "failed to parse provided key: " + err.Error()
		}
	}
	fingerprint := ""
	if parsed.Fingerprint != nil {
		digits := strings.ToLower(strings.ReplaceAll(*parsed.Fingerprint, ":", ""))
		raw, err := hex.DecodeString(digits)
		if err != nil || len(raw) != 32 {
			return file, nil, 0, 0, "failed to parse provided key: invalid fingerprint"
		}
		fingerprint = fakeColonHex(raw)
	}
	if len(parsed.KDF) > 0 && string(parsed.KDF) != "null" {
		return file, nil, 0, 0, "protected keys not supported"
	}
	if len(key) != 32 {
		// PBS panics copying the key, and the proxy reports that it lost the
		// connection to the API daemon; the exact text is not known.
		return file, nil, 0, 0, "client error (SendRequest)"
	}
	if computed := fakeKeyFingerprint(key); fingerprint != "" && fingerprint != computed {
		return file, nil, 0, 0, fmt.Sprintf("failed to load provided key: KeyConfig contains wrong fingerprint %s, "+
			"contained key has fingerprint %s", fingerprint[:23], computed[:23])
	}
	file = fakeKeyFile{KDF: json.RawMessage("null"), Created: fakeKeyTime(times[0]), Modified: fakeKeyTime(times[1]),
		Data: base64.StdEncoding.EncodeToString(key), Fingerprint: fingerprint}
	if parsed.Hint != nil {
		file.Hint = *parsed.Hint
	}
	return file, key, times[0], times[1], ""
}

func (k *fakeEncryptionKeys) create(w http.ResponseWriter, req *http.Request) {
	params := form(req)
	if !checkRequired(w, params, "id") {
		return
	}
	id := params.Get("id")
	if !safeIDPattern.MatchString(id) || len(id) < minSafeIDLength || len(id) > maxSafeIDLength {
		writeError(w, "parameter verification failed - 'id': value does not match the regex pattern")
		return
	}
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()

	var file fakeKeyFile
	var key []byte
	var created, modified int64
	if text, given := params["key"]; given {
		var failure string
		if file, key, created, modified, failure = parseKeyFile(text[0]); failure != "" {
			writeError(w, "%s", failure)
			return
		}
	} else {
		key = k.generateLocked(id)
		created = k.tickLocked()
		modified = created
		file = fakeKeyFile{KDF: json.RawMessage("null"), Created: fakeKeyTime(created), Modified: fakeKeyTime(modified),
			Data: base64.StdEncoding.EncodeToString(key), Fingerprint: fakeKeyFingerprint(key)}
	}
	if _, exists := k.keys[id]; exists {
		writeError(w, "key with id '%s' already exists.", id)
		return
	}
	props := fakeProperties{"id": id, "kdf": "none", "created": created, "modified": modified,
		"path": "/etc/proxmox-backup/encryption-keys/" + id + ".enc"}
	if file.Fingerprint != "" {
		props["fingerprint"] = file.Fingerprint
	}
	if file.Hint != "" {
		props["hint"] = file.Hint
	}
	k.storeLocked(id, props, key)
	writeData(w, file, "")
}

// toggle serves POST /config/encryption-keys/{id}.
func (k *fakeEncryptionKeys) toggle(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/encryption-keys/")
	params := form(req)
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	if staleDigest(params, k.digestLocked()) {
		writeError(w, fakeDigestConflict)
		return
	}
	props, exists := k.keys[id]
	if !exists {
		writeError(w, "no such sync-key '%s'", id)
		return
	}
	if _, archived := props["archived-at"]; archived {
		delete(props, "archived-at")
	} else {
		if jobs := k.syncs.keyUsersLocked(id, false); len(jobs) > 0 {
			writeError(w, "%s", fakeKeyInUse(jobs))
			return
		}
		props["archived-at"] = k.tickLocked()
	}
	k.gen++
	writeData(w, nil, "")
}

// delete serves DELETE /config/encryption-keys/{id}.
func (k *fakeEncryptionKeys) delete(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, fakeAPIPrefix+"/config/encryption-keys/")
	params := form(req)
	k.syncs.mu.Lock()
	defer k.syncs.mu.Unlock()
	if staleDigest(params, k.digestLocked()) {
		writeError(w, fakeDigestConflict)
		return
	}
	if jobs := k.syncs.keyUsersLocked(id, true); len(jobs) > 0 {
		writeError(w, "%s", fakeKeyInUse(jobs))
		return
	}
	props, exists := k.keys[id]
	if !exists {
		writeData(w, nil, "")
		return
	}
	if _, archived := props["archived-at"]; !archived {
		writeError(w, "key still active, deleting is only possible for archived keys")
		return
	}
	k.removeLocked(id)
	writeData(w, nil, "")
}
