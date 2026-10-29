package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// A read leaves out every property PBS was not sent, but has one sent at its
// default, and never the secret key; byte sizes come in PBS's spelling and
// quirks in the order they were sent.
func TestGetS3EndpointDecodesTheEndpoint(t *testing.T) {
	port, putLimit, active, passive := int64(7480), int64(100), int64(50), int64(200)
	yes, no := true, false
	const fingerprint = "3b:8e:21:0f:c4:5d:96:a7:12:e0:4f:6b:d9:33:a8:c1:70:5e:2d:9b:84:f6:1a:c3:07:bd:52:e9:6c:48:af:13"
	tests := map[string]struct {
		answer string
		want   S3Endpoint
	}{
		"defaults left out": {
			`{"data":{"id":"wasabi","endpoint":"s3.{{region}}.wasabisys.com","access-key":"WASABIACCESSKEY"},"digest":"9f86d081884c7d65"}`,
			S3Endpoint{ID: "wasabi", Endpoint: "s3.{{region}}.wasabisys.com", AccessKey: "WASABIACCESSKEY"},
		},
		"every property": {
			`{"data":{"id":"wasabi","endpoint":"172.16.0.200","port":7480,"region":"eu-central-2","fingerprint":"` + fingerprint +
				`","access-key":"WASABIACCESSKEY","path-style":true,"provider-quirks":["skip-if-none-match-header",` +
				`"delete-objects-via-delete-object"],"put-rate-limit":100,"limit-active-requests":50,"limit-passive-requests":200,` +
				`"rate-in":"10 MiB","burst-in":"20 MiB","rate-out":"1.5 GB","burst-out":"2 GB","use-node-proxy":false},` +
				`"digest":"9f86d081884c7d65"}`,
			S3Endpoint{ID: "wasabi", Endpoint: "172.16.0.200", Port: &port, Region: "eu-central-2", Fingerprint: fingerprint,
				AccessKey: "WASABIACCESSKEY", PathStyle: &yes,
				ProviderQuirks: []string{"skip-if-none-match-header", "delete-objects-via-delete-object"},
				PutRateLimit:   &putLimit, LimitActiveRequests: &active, LimitPassiveRequests: &passive,
				RateIn: "10 MiB", BurstIn: "20 MiB", RateOut: "1.5 GB", BurstOut: "2 GB", UseNodeProxy: &no},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/s3/wasabi", http.StatusOK, tc.answer)
			endpoint, err := fake.client(t).GetS3Endpoint(context.Background(), "wasabi")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(endpoint, tc.want) {
				t.Fatalf("GetS3Endpoint() = %+v, want %+v", endpoint, tc.want)
			}
		})
	}
}

// The writes send the caller's params as the form; the delete and the bucket
// list name the endpoint in their path and send nothing else.
func TestS3EndpointCallsHitTheirRoutes(t *testing.T) {
	const (
		listRoute    = "GET /config/s3"
		createRoute  = "POST /config/s3"
		updateRoute  = "PUT /config/s3/wasabi"
		bucketsRoute = "GET /config/s3/wasabi/list-buckets"
		deleteRoute  = "DELETE /config/s3/wasabi"
	)
	fake := newFakePBS()
	fake.reply(listRoute, http.StatusOK, `{"data":[{"id":"wasabi","endpoint":"s3.{{region}}.wasabisys.com","access-key":"W"},`+
		`{"id":"minio","endpoint":"172.16.0.200","port":9000,"access-key":"M","path-style":true}],"digest":"9f86d081884c7d65"}`)
	fake.reply(createRoute, http.StatusOK, `{"data":null}`)
	fake.reply(updateRoute, http.StatusOK, `{"data":null}`)
	fake.reply(bucketsRoute, http.StatusOK, `{"data":[{"name":"pbs-offsite"}]}`)
	fake.reply(deleteRoute, http.StatusOK, `{"data":null}`)
	c := fake.client(t)
	ctx := context.Background()

	endpoints, err := c.ListS3Endpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port := int64(9000)
	yes := true
	wantEndpoints := []S3Endpoint{
		{ID: "wasabi", Endpoint: "s3.{{region}}.wasabisys.com", AccessKey: "W"},
		{ID: "minio", Endpoint: "172.16.0.200", Port: &port, AccessKey: "M", PathStyle: &yes},
	}
	if !reflect.DeepEqual(endpoints, wantEndpoints) {
		t.Fatalf("ListS3Endpoints() = %+v, want %+v", endpoints, wantEndpoints)
	}

	create := url.Values{"id": {"wasabi"}, "endpoint": {"s3.{{region}}.wasabisys.com"}, "access-key": {"W"},
		"secret-key": {"s3cr3t"}, "provider-quirks": {"delete-objects-via-delete-object", "skip-if-none-match-header"}}
	if err := c.CreateS3Endpoint(ctx, create); err != nil {
		t.Fatalf("CreateS3Endpoint() = %v", err)
	}
	update := url.Values{"port": {"8443"}, "secret-key": {"n3w"}, "delete": {"fingerprint", "region"}}
	if err := c.UpdateS3Endpoint(ctx, "wasabi", update); err != nil {
		t.Fatalf("UpdateS3Endpoint() = %v", err)
	}
	buckets, err := c.ListS3Buckets(ctx, "wasabi")
	if err != nil {
		t.Fatal(err)
	}
	if want := []S3Bucket{{Name: "pbs-offsite"}}; !reflect.DeepEqual(buckets, want) {
		t.Fatalf("ListS3Buckets() = %+v, want %+v", buckets, want)
	}
	if err := c.DeleteS3Endpoint(ctx, "wasabi"); err != nil {
		t.Fatalf("DeleteS3Endpoint() = %v", err)
	}

	want := []string{listRoute, createRoute, updateRoute, bucketsRoute, deleteRoute}
	if got := fake.routes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if call := fake.lastCall(t, createRoute); !reflect.DeepEqual(call.form, create) {
		t.Errorf("CreateS3Endpoint form = %v, want %v", call.form, create)
	}
	if call := fake.lastCall(t, updateRoute); !reflect.DeepEqual(call.form, update) {
		t.Errorf("UpdateS3Endpoint form = %v, want %v", call.form, update)
	}
	for _, route := range []string{deleteRoute, bucketsRoute} {
		if call := fake.lastCall(t, route); len(call.query) != 0 || len(call.form) != 0 {
			t.Errorf("%s query = %v, form = %v, want neither", route, call.query, call.form)
		}
	}
}

// PBS's API schema says the bucket list returns nothing, but PBS answers the
// buckets, in the order the object store lists them.
func TestListS3BucketsDecodesTheList(t *testing.T) {
	tests := map[string]struct {
		answer string
		want   []S3Bucket
	}{
		"buckets":   {`{"data":[{"name":"pbs-offsite"},{"name":"archive"}]}`, []S3Bucket{{Name: "pbs-offsite"}, {Name: "archive"}}},
		"none":      {`{"data":[]}`, []S3Bucket{}},
		"as schema": {`{"data":null}`, nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply("GET /config/s3/wasabi/list-buckets", http.StatusOK, tc.answer)
			buckets, err := fake.client(t).ListS3Buckets(context.Background(), "wasabi")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(buckets, tc.want) {
				t.Fatalf("ListS3Buckets() = %#v, want %#v", buckets, tc.want)
			}
		})
	}
}

// The keys are secrets the client does not otherwise hold, so both writes
// keep them out of their errors.
func TestS3EndpointWritesRedactTheKeys(t *testing.T) {
	const (
		accessKey = "AKIA5EXAMPLEKEY"
		secretKey = `wJalr "XUtnFEMI"/K7MDENG`
		echo      = `writing "/etc/proxmox-backup/s3.cfg" failed: value "AKIA5EXAMPLEKEY" and "wJalr \"XUtnFEMI\"/K7MDENG" rejected`
	)
	tests := map[string]struct {
		route string
		write func(*Client, url.Values) error
	}{
		"create": {"POST /config/s3", func(c *Client, params url.Values) error {
			return c.CreateS3Endpoint(context.Background(), params)
		}},
		"update": {"PUT /config/s3/wasabi", func(c *Client, params url.Values) error {
			return c.UpdateS3Endpoint(context.Background(), "wasabi", params)
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newFakePBS()
			fake.reply(tc.route, http.StatusBadRequest, echo)
			err := tc.write(fake.client(t), url.Values{"id": {"wasabi"}, "access-key": {accessKey}, "secret-key": {secretKey}})
			apiErr, ok := asError(err)
			if !ok || apiErr.StatusCode != http.StatusBadRequest {
				t.Fatalf("error = %v, want PBS's 400", err)
			}
			for _, leaked := range []string{"AKIA5EXAMPLEKEY", "XUtnFEMI"} {
				if strings.Contains(err.Error(), leaked) || strings.Contains(apiErr.Body, leaked) {
					t.Fatalf("error = %v, body = %q", err, apiErr.Body)
				}
			}
			if !strings.Contains(err.Error(), redactedMarker) {
				t.Fatalf("error = %v, want the keys redacted", err)
			}
		})
	}
}

// A missing endpoint is a 400 on read and a 404 on delete; a taken ID and an
// endpoint a datastore uses are 400s the provider tells apart. A failed
// bucket list says neither.
func TestS3EndpointErrorsAreRecognised(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/s3/missing", http.StatusBadRequest, "no such s3-endpoint 'missing'")
	fake.reply("PUT /config/s3/missing", http.StatusBadRequest, "no such s3-endpoint 'missing'")
	fake.reply("DELETE /config/s3/missing", http.StatusNotFound, "s3 client config 'missing' do not exist.")
	fake.reply("DELETE /config/s3/used", http.StatusBadRequest, "in-use by datastore store1")
	fake.reply("POST /config/s3", http.StatusBadRequest, "parameter verification failed - 'id': s3 client config 'taken' already exists.")
	fake.reply("GET /config/s3/missing/list-buckets", http.StatusBadRequest, "config lookup failed")
	fake.reply("GET /config/s3/down/list-buckets", http.StatusBadRequest, "failed to list buckets")
	c := fake.client(t)
	ctx := context.Background()

	if endpoint, err := c.GetS3Endpoint(ctx, "missing"); !IsNotFound(err) || IsS3EndpointInUse(err) || !reflect.DeepEqual(endpoint, S3Endpoint{}) {
		t.Errorf("GetS3Endpoint() = %+v, %v, want only a not-found error", endpoint, err)
	}
	if err := c.UpdateS3Endpoint(ctx, "missing", url.Values{"port": {"443"}}); !IsNotFound(err) {
		t.Errorf("UpdateS3Endpoint(missing) = %v, want a not-found error", err)
	}
	if err := c.DeleteS3Endpoint(ctx, "missing"); !IsNotFound(err) || IsS3EndpointInUse(err) {
		t.Errorf("DeleteS3Endpoint(missing) = %v, want a not-found error", err)
	}
	if err := c.DeleteS3Endpoint(ctx, "used"); !IsS3EndpointInUse(err) || IsNotFound(err) {
		t.Errorf("DeleteS3Endpoint(used) = %v, want an in-use error", err)
	}
	if err := c.CreateS3Endpoint(ctx, url.Values{"id": {"taken"}}); !IsAlreadyExists(err) || IsS3EndpointInUse(err) {
		t.Errorf("CreateS3Endpoint() = %v, want an already-exists error", err)
	}
	for _, id := range []string{"missing", "down"} {
		if _, err := c.ListS3Buckets(ctx, id); err == nil || IsNotFound(err) || IsS3EndpointInUse(err) {
			t.Errorf("ListS3Buckets(%s) = %v, want an error that is neither not-found nor in-use", id, err)
		}
	}
	if IsS3EndpointInUse(nil) {
		t.Error("IsS3EndpointInUse(nil) = true")
	}
	if IsS3EndpointInUse(&Error{StatusCode: http.StatusInternalServerError, Message: "in-use by datastore store1"}) {
		t.Error("IsS3EndpointInUse(500) = true, want PBS's 400 only")
	}
}
