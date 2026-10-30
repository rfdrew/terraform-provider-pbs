package pbsclient

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Sync encryption keys, from PBS 4.2, encrypt the backups a push sync job
// copies to a remote; their list lives in encryption-keys.cfg, each key in a
// file of its own, /etc/proxmox-backup/encryption-keys/<id>.enc. What PBS
// 4.2 does, read in its source (src/api2/config/encryption_keys.rs,
// pbs-config/src/encryption_keys.rs):
//
//   - POST /config/encryption-keys stores the key given in "key" — a key file
//     as proxmox-backup-client writes it, JSON, without a password — or
//     generates one, and answers the key file with the key in it.
//   - The list leaves out archived keys unless include-archived is set, and
//     never holds key material. There is no read of a single key.
//   - POST /config/encryption-keys/{id} toggles whether the key is archived.
//     An archived key no longer encrypts; archiving the active key of a sync
//     job is refused, "encryption key in use by sync job: 'x'".
//   - DELETE refuses a key that is not archived, "key still active, deleting
//     is only possible for archived keys", and one a sync job uses, as its
//     active key or an associated one. Deleting a missing key succeeds.
//   - A duplicate ID is 400 "key with id 'x' already exists."; toggling a
//     missing key is 400 "no such sync-key 'x'".

// ConfigEncryptionKeys is the configuration file of sync encryption keys, as
// a name for WithConfigLock.
const ConfigEncryptionKeys = "encryption-keys.cfg"

// EncryptionKey is a sync encryption key as PBS lists it, without the key
// itself.
type EncryptionKey struct {
	ID string `json:"id"`
	// KDF is how the key file protects the key; "none" for the keys PBS
	// takes.
	KDF string `json:"kdf,omitempty"`
	// Created and Modified are Unix times from the key file.
	Created  int64 `json:"created"`
	Modified int64 `json:"modified"`
	// Fingerprint is the key's fingerprint, as colon-separated hex pairs,
	// which backups encrypted with it carry.
	Fingerprint string `json:"fingerprint,omitempty"`
	Hint        string `json:"hint,omitempty"`
	// ArchivedAt is when the key was archived, a Unix time; unset for a key
	// in use.
	ArchivedAt *int64 `json:"archived-at,omitempty"`
}

// Archived reports whether the key is archived.
func (k EncryptionKey) Archived() bool { return k.ArchivedAt != nil }

// ListEncryptionKeys lists the sync encryption keys the caller may audit,
// archived ones included, and the digest of their configuration.
func (c *Client) ListEncryptionKeys(ctx context.Context) ([]EncryptionKey, string, error) {
	var keys []EncryptionKey
	env, err := c.Get(ctx, "/config/encryption-keys", url.Values{"include-archived": {"1"}}, &keys)
	if err != nil {
		return nil, "", err
	}
	return keys, env.Digest, nil
}

// GetEncryptionKey looks a sync encryption key up in the list, which is the
// only read PBS has, and returns the list's digest; a key the list does not
// hold is reported as PBS reports a missing one.
func (c *Client) GetEncryptionKey(ctx context.Context, id string) (EncryptionKey, string, error) {
	keys, digest, err := c.ListEncryptionKeys(ctx)
	if err != nil {
		return EncryptionKey{}, "", err
	}
	for _, key := range keys {
		if key.ID == id {
			return key, digest, nil
		}
	}
	return EncryptionKey{}, digest, &Error{
		Method:     http.MethodGet,
		Path:       "/config/encryption-keys",
		StatusCode: http.StatusBadRequest,
		Message:    "no such sync-key '" + id + "'",
	}
}

// CreateEncryptionKey stores key, a key file without a password, as the sync
// encryption key id, or, when key is empty, has PBS generate one. PBS answers
// with the key file, which this client drops: a generated key stays on the
// server. key is kept out of any error.
func (c *Client) CreateEncryptionKey(ctx context.Context, id, key string) error {
	params := url.Values{"id": {id}}
	if key != "" {
		params.Set("key", key)
	}
	_, err := c.Post(ctx, "/config/encryption-keys", params, nil)
	return redactAPIError(err, key)
}

// ToggleEncryptionKeyArchived archives a sync encryption key in use, or
// brings an archived one back into use. digest, when not empty, makes PBS
// refuse the change should the keys have changed since it was read.
func (c *Client) ToggleEncryptionKeyArchived(ctx context.Context, id, digest string) error {
	params := url.Values{}
	if digest != "" {
		params.Set(DigestParam, digest)
	}
	_, err := c.Post(ctx, Path("config", "encryption-keys", id), params, nil)
	return err
}

// DeleteEncryptionKey deletes an archived sync encryption key and its file.
func (c *Client) DeleteEncryptionKey(ctx context.Context, id string) error {
	_, err := c.Delete(ctx, Path("config", "encryption-keys", id), nil, nil)
	return err
}

// IsEncryptionKeyInUse reports whether PBS refused to archive or delete a
// sync encryption key because a sync job uses it.
func IsEncryptionKeyInUse(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest &&
		strings.HasPrefix(apiErr.Message, "encryption key in use by sync job")
}

// keyFingerprintInput is what PBS hashes, with a key's derived ID key, into
// the key's fingerprint: the SHA-256 of "Proxmox Backup Encryption Key
// Fingerprint".
var keyFingerprintInput = sha256.Sum256([]byte("Proxmox Backup Encryption Key Fingerprint"))

// KeyFileFingerprint computes the fingerprint of the key in a key file
// without a password, as PBS lists it for a sync encryption key: colon-
// separated lower-case hex pairs of SHA-256 over the fingerprint input and
// the key's ID key, which PBKDF2-HMAC-SHA256 derives from the key with the
// salt "_id_key" and 10 iterations (pbs-tools crypt_config.rs).
func KeyFileFingerprint(keyFile string) (string, error) {
	var file struct {
		KDF  json.RawMessage `json:"kdf"`
		Data string          `json:"data"`
	}
	if err := json.Unmarshal([]byte(keyFile), &file); err != nil {
		return "", fmt.Errorf("not a key file: %w", err)
	}
	if len(file.KDF) > 0 && string(file.KDF) != "null" {
		return "", errors.New("the key file has a password")
	}
	key, err := base64.StdEncoding.DecodeString(file.Data)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(file.Data)
	}
	if err != nil || len(key) != 32 {
		return "", errors.New("the key file holds no 32-byte key")
	}
	idKey, err := pbkdf2.Key(sha256.New, string(key), []byte("_id_key"), 10, 32)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(keyFingerprintInput[:])
	h.Write(idKey)
	sum := h.Sum(nil)
	pairs := make([]string, len(sum))
	for i, b := range sum {
		pairs[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(pairs, ":"), nil
}
