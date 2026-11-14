package pbsclient

import (
	"context"
	"net/http"
	"testing"
)

// The bucket and the store prefix travel in the body of the PUT; without a
// prefix there is none.
func TestCheckS3Endpoint(t *testing.T) {
	fake := newFakePBS()
	const route = "PUT /admin/s3/ep1/check"
	fake.reply(route, http.StatusOK, `{"data":null}`)
	client := fake.client(t)
	ctx := context.Background()

	if err := client.CheckS3Endpoint(ctx, "ep1", "backups", "store1"); err != nil {
		t.Fatal(err)
	}
	call := fake.lastCall(t, route)
	if call.form.Get("bucket") != "backups" || call.form.Get("store-prefix") != "store1" {
		t.Fatalf("form = %v", call.form)
	}
	if err := client.CheckS3Endpoint(ctx, "ep1", "backups", ""); err != nil {
		t.Fatal(err)
	}
	if call := fake.lastCall(t, route); call.form.Has("store-prefix") {
		t.Fatalf("form = %v", call.form)
	}
}

func TestS3CheckFailedStep(t *testing.T) {
	for _, step := range []string{
		S3CheckConfigLookup, S3CheckClientCreation, S3CheckHeadBucket, S3CheckPutObject, S3CheckGetObject, S3CheckDeleteObject,
	} {
		fake := newFakePBS()
		fake.reply("PUT /admin/s3/ep1/check", http.StatusBadRequest, step+"\n")
		err := fake.client(t).CheckS3Endpoint(context.Background(), "ep1", "backups", "")
		if got := S3CheckFailedStep(err); got != step {
			t.Errorf("S3CheckFailedStep(%v) = %q, want %q", err, got, step)
		}
	}
	for _, err := range []error{
		nil,
		&Error{StatusCode: http.StatusForbidden, Message: "permission check failed"},
		&Error{StatusCode: http.StatusBadRequest, Message: "parameter verification failed - 'bucket': value does not match the regex pattern"},
		&Error{StatusCode: http.StatusInternalServerError, Message: S3CheckHeadBucket},
	} {
		if got := S3CheckFailedStep(err); got != "" {
			t.Errorf("S3CheckFailedStep(%v) = %q", err, got)
		}
	}
}
