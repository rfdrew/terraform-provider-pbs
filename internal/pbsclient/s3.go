package pbsclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// An S3 endpoint is the connection to an S3-compatible object store that
// datastores on S3 keep their chunks in; endpoints live in s3.cfg. What PBS
// 4.2 does, read in its source (src/api2/config/s3.rs, proxmox-s3-client):
//
//   - Creating or changing an endpoint contacts nothing: PBS checks the
//     parameters against their schema and saves them. Only listing the
//     buckets, or a datastore that uses the endpoint, connects to it.
//   - Reads return the access key, but never the secret key.
//   - A duplicate ID is 400 "parameter verification failed - 'id': s3 client
//     config 'x' already exists.". A missing endpoint is 400 "no such
//     s3-endpoint 'x'" on GET and PUT, and 404 "s3 client config 'x' do not
//     exist." on DELETE; IsNotFound covers both.
//   - PBS refuses to delete an endpoint a datastore uses, with 400 "in-use by
//     datastore x"; IsS3EndpointInUse reports it.
//   - PBS answers a failed bucket list with the outermost context of its
//     error alone — "failed to list buckets", or "config lookup failed" for
//     an endpoint it does not have — so the cause is in its journal only.

// ConfigS3Endpoints is the configuration file of S3 endpoints, as a name for
// WithConfigLock.
const ConfigS3Endpoints = "s3.cfg"

// S3Endpoint is an S3 endpoint as PBS reports it, without its secret key.
type S3Endpoint struct {
	ID string `json:"id"`
	// Endpoint is the host name or IP address, possibly with the templates
	// {{bucket}} and {{region}}.
	Endpoint string `json:"endpoint"`
	// Port is unset for HTTPS's default, 443.
	Port   *int64 `json:"port,omitempty"`
	Region string `json:"region,omitempty"`
	// Fingerprint is the SHA-256 fingerprint of the endpoint's certificate,
	// as colon-separated hex pairs; empty when PBS verifies the certificate
	// against the system's CAs instead.
	Fingerprint    string   `json:"fingerprint,omitempty"`
	AccessKey      string   `json:"access-key"`
	PathStyle      *bool    `json:"path-style,omitempty"`
	ProviderQuirks []string `json:"provider-quirks,omitempty"`
	// PutRateLimit is the deprecated predecessor of LimitActiveRequests.
	PutRateLimit         *int64 `json:"put-rate-limit,omitempty"`
	LimitActiveRequests  *int64 `json:"limit-active-requests,omitempty"`
	LimitPassiveRequests *int64 `json:"limit-passive-requests,omitempty"`
	// RateIn, BurstIn, RateOut and BurstOut are byte sizes, in the spelling
	// PBS stores them in; SameByteSize compares them.
	RateIn       string `json:"rate-in,omitempty"`
	BurstIn      string `json:"burst-in,omitempty"`
	RateOut      string `json:"rate-out,omitempty"`
	BurstOut     string `json:"burst-out,omitempty"`
	UseNodeProxy *bool  `json:"use-node-proxy,omitempty"`
}

// S3Bucket is a bucket an S3 endpoint's access key may see.
type S3Bucket struct {
	Name string `json:"name"`
}

// ListS3Endpoints lists the S3 endpoints the caller may audit.
func (c *Client) ListS3Endpoints(ctx context.Context) ([]S3Endpoint, error) {
	var endpoints []S3Endpoint
	_, err := c.Get(ctx, "/config/s3", nil, &endpoints)
	return endpoints, err
}

// GetS3Endpoint reads one S3 endpoint.
func (c *Client) GetS3Endpoint(ctx context.Context, id string) (S3Endpoint, error) {
	var endpoint S3Endpoint
	_, err := c.Get(ctx, Path("config", "s3", id), nil, &endpoint)
	return endpoint, err
}

// CreateS3Endpoint creates an S3 endpoint from params, which must hold "id",
// "endpoint", "access-key" and "secret-key". The keys are kept out of any
// error.
func (c *Client) CreateS3Endpoint(ctx context.Context, params url.Values) error {
	_, err := c.Post(ctx, "/config/s3", params, nil)
	return redactAPIError(err, params.Get("secret-key"), params.Get("access-key"))
}

// UpdateS3Endpoint changes the properties params carries, the secret key
// among them, and deletes those named in its delete parameter. The keys are
// kept out of any error.
func (c *Client) UpdateS3Endpoint(ctx context.Context, id string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "s3", id), params, nil)
	return redactAPIError(err, params.Get("secret-key"), params.Get("access-key"))
}

// DeleteS3Endpoint deletes an S3 endpoint.
func (c *Client) DeleteS3Endpoint(ctx context.Context, id string) error {
	_, err := c.Delete(ctx, Path("config", "s3", id), nil, nil)
	return err
}

// ListS3Buckets connects to an S3 endpoint and lists the buckets its access
// key may see. The schema says the call returns nothing, but PBS answers the
// list.
func (c *Client) ListS3Buckets(ctx context.Context, id string) ([]S3Bucket, error) {
	var buckets []S3Bucket
	_, err := c.Get(ctx, Path("config", "s3", id, "list-buckets"), nil, &buckets)
	return buckets, err
}

// IsS3EndpointInUse reports whether PBS refused to delete an S3 endpoint
// because a datastore uses it.
func IsS3EndpointInUse(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest &&
		strings.HasPrefix(apiErr.Message, "in-use by datastore")
}
