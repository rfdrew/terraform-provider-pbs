package pbsclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// A remote is another Proxmox Backup Server that sync jobs pull from or push
// to; remotes live in remote.cfg. What PBS 4.2 does, read in its source
// (src/api2/config/remote.rs):
//
//   - Creating or changing a remote contacts nothing: PBS checks the
//     parameters against their schema and saves them. Only a scan or a sync
//     job signs in to the remote, and only then does a wrong host, port,
//     fingerprint, auth ID or password show.
//   - The password — that of auth-id, or the secret of an API token — is
//     never returned; reads answer the remote without it.
//   - A duplicate name is 400 "parameter verification failed - 'name':
//     remote 'x' already exists.". A missing remote is 400 "no such remote
//     'x'" on GET, PUT and scans, and 404 "remote 'x' does not exist." on
//     DELETE; IsNotFound covers them.
//   - PBS refuses to delete a remote a sync job uses, with 400 "parameter
//     verification failed - 'name': remote 'x' is used by sync job 'y'
//     (datastore 'z')"; IsRemoteInUse reports it.
//   - A scan that cannot reach the remote or sign in to it is 500 "failed
//     to scan remote 'x' - remote connection to 'host' failed - ...".

// DefaultRemotePort is the port PBS connects to when a remote sets none.
const DefaultRemotePort = 8007

// Remote is a remote as PBS reports it, without its password.
type Remote struct {
	Name string `json:"name"`
	Host string `json:"host"`
	// Port is unset for the default, DefaultRemotePort.
	Port   *int64 `json:"port,omitempty"`
	AuthID string `json:"auth-id"`
	// Fingerprint is the SHA-256 fingerprint of the remote's certificate, as
	// colon-separated hex pairs; empty when PBS verifies the certificate
	// against the system's CAs instead.
	Fingerprint  string `json:"fingerprint,omitempty"`
	UseNodeProxy *bool  `json:"use-node-proxy,omitempty"`
	Comment      string `json:"comment,omitempty"`
}

// RemoteDatastore is a datastore of a remote, as a scan of it lists it: one
// the remote's auth ID may see.
type RemoteDatastore struct {
	Store       string `json:"store"`
	Comment     string `json:"comment,omitempty"`
	Maintenance string `json:"maintenance,omitempty"`
	MountStatus string `json:"mount-status,omitempty"`
	BackendType string `json:"backend-type,omitempty"`
}

// RemoteNamespace is a namespace of a datastore of a remote, as a scan of it
// lists it. NS is empty for the datastore's root namespace.
type RemoteNamespace struct {
	NS      string `json:"ns"`
	Comment string `json:"comment,omitempty"`
}

// ListRemotes lists the remotes the caller may audit.
func (c *Client) ListRemotes(ctx context.Context) ([]Remote, error) {
	var remotes []Remote
	_, err := c.Get(ctx, "/config/remote", nil, &remotes)
	return remotes, err
}

// GetRemote reads one remote.
func (c *Client) GetRemote(ctx context.Context, name string) (Remote, error) {
	var remote Remote
	_, err := c.Get(ctx, Path("config", "remote", name), nil, &remote)
	return remote, err
}

// CreateRemote creates a remote from params, which must hold "name", "host",
// "auth-id" and "password". The password is kept out of any error.
func (c *Client) CreateRemote(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/remote", params, nil)
	return redactAPIError(err, params.Get("password"))
}

// UpdateRemote changes the properties params carries, the password among
// them, and deletes those named in its delete parameter. The password is
// kept out of any error.
func (c *Client) UpdateRemote(ctx context.Context, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "remote", name), params, nil)
	return redactAPIError(err, params.Get("password"))
}

// DeleteRemote deletes a remote.
func (c *Client) DeleteRemote(ctx context.Context, name string) error {
	_, err := c.Delete(ctx, Path("config", "remote", name), nil, nil)
	return err
}

// ScanRemoteDatastores signs in to a remote and lists the datastores its auth
// ID may see there.
func (c *Client) ScanRemoteDatastores(ctx context.Context, name string) ([]RemoteDatastore, error) {
	var datastores []RemoteDatastore
	_, err := c.Get(ctx, Path("config", "remote", name, "scan"), nil, &datastores)
	return datastores, err
}

// ScanRemoteNamespaces signs in to a remote and lists the namespaces of one
// of its datastores that its auth ID may see there, the root namespace
// among them.
func (c *Client) ScanRemoteNamespaces(ctx context.Context, name, store string) ([]RemoteNamespace, error) {
	var namespaces []RemoteNamespace
	_, err := c.Get(ctx, Path("config", "remote", name, "scan", store, "namespaces"), nil, &namespaces)
	return namespaces, err
}

// IsRemoteInUse reports whether PBS refused to delete a remote because a sync
// job uses it.
func IsRemoteInUse(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest &&
		strings.Contains(apiErr.Message, "is used by sync job")
}
