package pbsclient

import (
	"context"
	"net/http"
	"net/url"
)

// What PBS 4.x does when asked to check an S3 endpoint, read in its source
// (src/api2/admin/s3.rs, proxmox-s3-client client.rs; proxmox-backup
// 7c86c5ad5, after 4.2.11):
//
//   - PUT /admin/s3/{id}/check takes bucket and, optionally, store-prefix,
//     and needs Sys.Modify on / (403 without). It answers null, at once, when
//     every step passed — no task.
//   - The steps, in order: look the endpoint up, set up an S3 client, HEAD
//     the bucket, PUT an empty object <store-prefix>/.s3-client-test
//     (.s3-client-test without a prefix, replacing one that exists), GET it,
//     and DELETE it. A failed step answers 400 with that step's text alone —
//     "config lookup failed" (also for an endpoint PBS does not have),
//     "client creation failed", "head object failed" (the HEAD of the
//     bucket, sic), "put object failed", "get object failed", "delete object
//     failed" — and the cause, such as "bucket does not exist or no
//     permission to access it", a TLS error or a status, is lost; the same
//     check from proxmox-backup-manager on the host prints it.
//   - Every request to the object store waits up to 10 s to connect and is
//     tried three times, 1 s and 3 s apart, so an object store that does not
//     answer takes about 34 s to fail, over the client's default request
//     timeout; one that accepts the connection and never answers holds a
//     request for up to 30 minutes. Callers set a longer request timeout with
//     WithRequestTimeout.
//   - The requests count in the S3 request counters of
//     <id>-<bucket>[-<store-prefix>]: those of a datastore on that bucket
//     when the prefix is its name.

// The steps of an S3 endpoint check, as PBS names the one that failed.
const (
	S3CheckConfigLookup   = "config lookup failed"
	S3CheckClientCreation = "client creation failed"
	S3CheckHeadBucket     = "head object failed"
	S3CheckPutObject      = "put object failed"
	S3CheckGetObject      = "get object failed"
	S3CheckDeleteObject   = "delete object failed"
)

// S3CheckObject is the name of the object an S3 endpoint check writes and
// deletes, after the store prefix and a slash when there is one.
const S3CheckObject = ".s3-client-test"

// CheckS3Endpoint asks PBS to check that it can use bucket through an S3
// endpoint: reach it, and write, read and delete a test object under
// storePrefix, or at the top of the bucket when storePrefix is empty.
// S3CheckFailedStep tells which step failed.
func (c *Client) CheckS3Endpoint(ctx context.Context, id, bucket, storePrefix string) error {
	params := url.Values{"bucket": {bucket}}
	if storePrefix != "" {
		params.Set("store-prefix", storePrefix)
	}
	_, err := c.Put(ctx, Path("admin", "s3", id, "check"), params, nil)
	return err
}

// S3CheckFailedStep returns the step of an S3 endpoint check that failed —
// one of the S3Check constants — or "" when err is not such a failure.
func S3CheckFailedStep(err error) string {
	apiErr, ok := asError(err)
	if !ok || apiErr.StatusCode != http.StatusBadRequest {
		return ""
	}
	switch apiErr.Message {
	case S3CheckConfigLookup, S3CheckClientCreation, S3CheckHeadBucket, S3CheckPutObject, S3CheckGetObject, S3CheckDeleteObject:
		return apiErr.Message
	}
	return ""
}
