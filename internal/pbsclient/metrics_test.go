package pbsclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// metricsDigest is a digest of metricserver.cfg, as PBS answers it with every
// read and list.
const metricsDigest = "4d9e0a3c1b7f25e8a6c0d2f4b8e1a3c5d7f9b0e2a4c6d8f0b1e3a5c7d9f2b4e6"

// influxToken is an InfluxDB 2 API token as InfluxDB generates them: 64
// random bytes in URL-safe base64, with the padding, which URL-encoding
// changes.
const influxToken = "Uja5Qj1bCyOApYYTznKufcF7uEse9gmU5G2fq67yQWbsmepejJlIifkP5_tTXrRs8NskEEhgPixHkARN6nTj0g=="

// A read of an InfluxDB HTTP server decodes what PBS stores and leaves out
// what it does not, and returns the digest of metricserver.cfg; a list
// decodes every server, in PBS's order. Neither sends a parameter.
func TestInfluxDBHTTPServerReads(t *testing.T) {
	const (
		listRoute = "GET /config/metrics/influxdb-http"
		getRoute  = "GET /config/metrics/influxdb-http/influx"
	)
	fake := newFakePBS()
	fake.reply(listRoute, http.StatusOK, `{"data":[{"name":"local","url":"http://127.0.0.1:8086"},`+
		`{"name":"influx","url":"https://influx.example.com:8086","organization":"ops","bucket":"pbs",`+
		`"max-body-size":1000000,"verify-tls":false,"enable":false,"comment":"Metrics"}],"digest":"`+metricsDigest+`"}`)
	fake.reply(getRoute, http.StatusOK, `{"data":{"name":"influx","url":"https://influx.example.com:8086/influx",`+
		`"organization":"ops","bucket":"pbs","max-body-size":1000000,"verify-tls":true,"enable":false,`+
		`"comment":"Metrics"},"digest":"`+metricsDigest+`"}`)
	c := fake.client(t)
	ctx := context.Background()

	no, yes, maxBodySize := false, true, int64(1000000)
	servers, err := c.ListInfluxDBHTTPServers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantServers := []InfluxDBHTTPServer{
		{Name: "local", URL: "http://127.0.0.1:8086"},
		{Name: "influx", URL: "https://influx.example.com:8086", Organization: "ops", Bucket: "pbs",
			MaxBodySize: &maxBodySize, VerifyTLS: &no, Enable: &no, Comment: "Metrics"},
	}
	if !reflect.DeepEqual(servers, wantServers) {
		t.Errorf("ListInfluxDBHTTPServers() = %+v, want %+v", servers, wantServers)
	}

	server, digest, err := c.GetInfluxDBHTTPServer(ctx, "influx")
	if err != nil {
		t.Fatal(err)
	}
	want := InfluxDBHTTPServer{Name: "influx", URL: "https://influx.example.com:8086/influx", Organization: "ops",
		Bucket: "pbs", MaxBodySize: &maxBodySize, VerifyTLS: &yes, Enable: &no, Comment: "Metrics"}
	if !reflect.DeepEqual(server, want) || digest != metricsDigest {
		t.Errorf("GetInfluxDBHTTPServer() = %+v, %q, want %+v, %q", server, digest, want, metricsDigest)
	}

	// Everything PBS leaves out stays unset: the provider tells PBS's
	// defaults from values set by that.
	fake.reply(getRoute, http.StatusOK, `{"data":{"name":"influx","url":"http://influx.example.com:8086"},"digest":"`+metricsDigest+`"}`)
	server, _, err = c.GetInfluxDBHTTPServer(ctx, "influx")
	if err != nil {
		t.Fatal(err)
	}
	if bare := (InfluxDBHTTPServer{Name: "influx", URL: "http://influx.example.com:8086"}); !reflect.DeepEqual(server, bare) {
		t.Errorf("GetInfluxDBHTTPServer() of a bare server = %+v, want %+v", server, bare)
	}

	fake.reply(listRoute, http.StatusOK, `{"data":[],"digest":"`+metricsDigest+`"}`)
	if servers, err := c.ListInfluxDBHTTPServers(ctx); err != nil || len(servers) != 0 {
		t.Errorf("ListInfluxDBHTTPServers() of none = %+v, %v", servers, err)
	}

	wantRoutes := []string{listRoute, getRoute, getRoute, listRoute}
	if got := fake.routes(); !reflect.DeepEqual(got, wantRoutes) {
		t.Fatalf("routes = %v, want %v", got, wantRoutes)
	}
	for _, route := range []string{listRoute, getRoute} {
		if call := fake.lastCall(t, route); len(call.query) != 0 || len(call.form) != 0 {
			t.Errorf("%s query = %v, form = %v, want neither", route, call.query, call.form)
		}
	}
}

// The same for an InfluxDB UDP server, whose host may be an IPv6 address in
// brackets.
func TestInfluxDBUDPServerReads(t *testing.T) {
	const (
		listRoute = "GET /config/metrics/influxdb-udp"
		getRoute  = "GET /config/metrics/influxdb-udp/udp"
	)
	fake := newFakePBS()
	fake.reply(listRoute, http.StatusOK, `{"data":[{"name":"v6","host":"[2001:db8::1]:8089"},`+
		`{"name":"udp","host":"influx.example.com:8089","mtu":1400,"enable":false,"comment":"UDP"}],"digest":"`+metricsDigest+`"}`)
	fake.reply(getRoute, http.StatusOK, `{"data":{"name":"udp","host":"influx.example.com:8089","mtu":1400,`+
		`"enable":false,"comment":"UDP"},"digest":"`+metricsDigest+`"}`)
	c := fake.client(t)
	ctx := context.Background()

	no, mtu := false, int64(1400)
	servers, err := c.ListInfluxDBUDPServers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantServers := []InfluxDBUDPServer{
		{Name: "v6", Host: "[2001:db8::1]:8089"},
		{Name: "udp", Host: "influx.example.com:8089", MTU: &mtu, Enable: &no, Comment: "UDP"},
	}
	if !reflect.DeepEqual(servers, wantServers) {
		t.Errorf("ListInfluxDBUDPServers() = %+v, want %+v", servers, wantServers)
	}

	server, digest, err := c.GetInfluxDBUDPServer(ctx, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(server, wantServers[1]) || digest != metricsDigest {
		t.Errorf("GetInfluxDBUDPServer() = %+v, %q, want %+v, %q", server, digest, wantServers[1], metricsDigest)
	}

	fake.reply(getRoute, http.StatusOK, `{"data":{"name":"udp","host":"192.0.2.10:8089"},"digest":"`+metricsDigest+`"}`)
	server, _, err = c.GetInfluxDBUDPServer(ctx, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if bare := (InfluxDBUDPServer{Name: "udp", Host: "192.0.2.10:8089"}); !reflect.DeepEqual(server, bare) {
		t.Errorf("GetInfluxDBUDPServer() of a bare server = %+v, want %+v", server, bare)
	}

	fake.reply(listRoute, http.StatusOK, `{"data":[],"digest":"`+metricsDigest+`"}`)
	if servers, err := c.ListInfluxDBUDPServers(ctx); err != nil || len(servers) != 0 {
		t.Errorf("ListInfluxDBUDPServers() of none = %+v, %v", servers, err)
	}

	wantRoutes := []string{listRoute, getRoute, getRoute, listRoute}
	if got := fake.routes(); !reflect.DeepEqual(got, wantRoutes) {
		t.Fatalf("routes = %v, want %v", got, wantRoutes)
	}
	for _, route := range []string{listRoute, getRoute} {
		if call := fake.lastCall(t, route); len(call.query) != 0 || len(call.form) != 0 {
			t.Errorf("%s query = %v, form = %v, want neither", route, call.query, call.form)
		}
	}
}

// The writes, shared by both types, go under the path of the type they are
// given: create and update send the caller's params as the form, unchanged;
// MetricServerDigest reads the server for the digest alone; the delete
// sends the digest in the query when it has one, and nothing otherwise.
func TestMetricServerWritesHitTheirRoutes(t *testing.T) {
	tests := map[string]struct {
		create url.Values
		update url.Values
	}{
		MetricServerTypeInfluxDBHTTP: {
			create: url.Values{"name": {"influx"}, "url": {"https://influx.example.com:8086"}, "token": {influxToken},
				"organization": {"ops"}, "bucket": {"pbs"}, "max-body-size": {"1000000"}, "verify-tls": {"true"},
				"enable": {"false"}, "comment": {"Metrics"}},
			update: url.Values{"url": {"https://influx.example.com:8443"}, "token": {influxToken},
				"delete": {"bucket", "comment", "enable"}, DigestParam: {metricsDigest}},
		},
		MetricServerTypeInfluxDBUDP: {
			create: url.Values{"name": {"influx"}, "host": {"[2001:db8::1]:8089"}, "mtu": {"1400"}, "enable": {"false"},
				"comment": {"UDP"}},
			update: url.Values{"host": {"influx.example.com:8089"}, "delete": {"mtu", "comment"}, DigestParam: {metricsDigest}},
		},
	}
	for serverType, tc := range tests {
		t.Run(serverType, func(t *testing.T) {
			createRoute := "POST /config/metrics/" + serverType
			getRoute := "GET /config/metrics/" + serverType + "/influx"
			updateRoute := "PUT /config/metrics/" + serverType + "/influx"
			deleteRoute := "DELETE /config/metrics/" + serverType + "/influx"
			fake := newFakePBS()
			fake.reply(createRoute, http.StatusOK, `{"data":null}`)
			fake.reply(getRoute, http.StatusOK, `{"data":{"name":"influx"},"digest":"`+metricsDigest+`"}`)
			fake.reply(updateRoute, http.StatusOK, `{"data":null}`)
			fake.reply(deleteRoute, http.StatusOK, `{"data":null}`)
			c := fake.client(t)
			ctx := context.Background()

			if err := c.CreateMetricServer(ctx, serverType, tc.create); err != nil {
				t.Fatalf("CreateMetricServer() = %v", err)
			}
			if call := fake.lastCall(t, createRoute); !reflect.DeepEqual(call.form, tc.create) || len(call.query) != 0 {
				t.Errorf("POST form = %v, query = %v, want form %v", call.form, call.query, tc.create)
			}
			if err := c.UpdateMetricServer(ctx, serverType, "influx", tc.update); err != nil {
				t.Fatalf("UpdateMetricServer() = %v", err)
			}
			if call := fake.lastCall(t, updateRoute); !reflect.DeepEqual(call.form, tc.update) || len(call.query) != 0 {
				t.Errorf("PUT form = %v, query = %v, want form %v", call.form, call.query, tc.update)
			}
			if digest, err := c.MetricServerDigest(ctx, serverType, "influx"); err != nil || digest != metricsDigest {
				t.Errorf("MetricServerDigest() = %q, %v, want %q", digest, err, metricsDigest)
			}
			if call := fake.lastCall(t, getRoute); len(call.query) != 0 || len(call.form) != 0 {
				t.Errorf("GET query = %v, form = %v, want neither", call.query, call.form)
			}

			if err := c.DeleteMetricServer(ctx, serverType, "influx", metricsDigest); err != nil {
				t.Fatalf("DeleteMetricServer() = %v", err)
			}
			if call := fake.lastCall(t, deleteRoute); !reflect.DeepEqual(call.query, url.Values{DigestParam: {metricsDigest}}) || len(call.form) != 0 {
				t.Errorf("DELETE query = %v, form = %v, want only the digest", call.query, call.form)
			}
			if err := c.DeleteMetricServer(ctx, serverType, "influx", ""); err != nil {
				t.Fatalf("DeleteMetricServer() without a digest = %v", err)
			}
			if call := fake.lastCall(t, deleteRoute); len(call.query) != 0 || len(call.form) != 0 {
				t.Errorf("DELETE without a digest: query = %v, form = %v, want neither", call.query, call.form)
			}

			want := []string{createRoute, updateRoute, getRoute, deleteRoute, deleteRoute}
			if got := fake.routes(); !reflect.DeepEqual(got, want) {
				t.Fatalf("routes = %v, want %v", got, want)
			}
		})
	}
}

// PBS's errors reach the caller as they are: a missing server is not found
// on every method, a server of the other type is IsOfOtherType on GET and
// PUT, a taken name is IsAlreadyExists, a stale digest IsDigestConflict, and
// none of these is a failed check.
func TestMetricServerErrorsAreRecognised(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /config/metrics/influxdb-http/missing", http.StatusBadRequest, "no such influxdb-http 'missing'")
	fake.reply("GET /config/metrics/influxdb-udp/missing", http.StatusBadRequest, "no such influxdb-udp 'missing'")
	fake.reply("PUT /config/metrics/influxdb-http/missing", http.StatusBadRequest, "no such influxdb-http 'missing'")
	fake.reply("DELETE /config/metrics/influxdb-udp/missing", http.StatusBadRequest, "name 'missing' does not exist.")
	fake.reply("GET /config/metrics/influxdb-http/udp", http.StatusBadRequest,
		"got unexpected type 'influxdb-udp' for influxdb-http 'udp'")
	fake.reply("GET /config/metrics/influxdb-udp/http", http.StatusBadRequest,
		"got unexpected type 'influxdb-http' for influxdb-udp 'http'")
	fake.reply("PUT /config/metrics/influxdb-http/udp", http.StatusBadRequest,
		"got unexpected type 'influxdb-udp' for influxdb-http 'udp'")
	fake.reply("POST /config/metrics/influxdb-udp", http.StatusBadRequest, "metric server 'taken' already exists.")
	fake.reply("DELETE /config/metrics/influxdb-http/stale", http.StatusBadRequest,
		"detected modified configuration - file changed by other user? Try again.")
	fake.reply("GET /config/metrics/influxdb-udp", http.StatusForbidden, "permission check failed")
	c := fake.client(t)
	ctx := context.Background()

	notCheck := func(name string, err error) {
		t.Helper()
		if check, status := MetricServerCheckFailureOf(err); check != MetricServerCheckPassed || status != 0 {
			t.Errorf("%s: MetricServerCheckFailureOf(%v) = %v, %d, want no failed check", name, err, check, status)
		}
	}

	httpServer, digest, err := c.GetInfluxDBHTTPServer(ctx, "missing")
	if !IsNotFound(err) || IsOfOtherType(err) || !reflect.DeepEqual(httpServer, InfluxDBHTTPServer{}) || digest != "" {
		t.Errorf("GetInfluxDBHTTPServer(missing) = %+v, %q, %v, want only a not-found error", httpServer, digest, err)
	}
	notCheck("GET missing", err)
	udpServer, digest, err := c.GetInfluxDBUDPServer(ctx, "missing")
	if !IsNotFound(err) || IsOfOtherType(err) || !reflect.DeepEqual(udpServer, InfluxDBUDPServer{}) || digest != "" {
		t.Errorf("GetInfluxDBUDPServer(missing) = %+v, %q, %v, want only a not-found error", udpServer, digest, err)
	}
	if err := c.UpdateMetricServer(ctx, MetricServerTypeInfluxDBHTTP, "missing", url.Values{"comment": {"x"}}); !IsNotFound(err) {
		t.Errorf("UpdateMetricServer(missing) = %v, want a not-found error", err)
	}
	err = c.DeleteMetricServer(ctx, MetricServerTypeInfluxDBUDP, "missing", "")
	if !IsNotFound(err) || IsEndpointMissing(err) {
		t.Errorf("DeleteMetricServer(missing) = %v, want a not-found error", err)
	}
	notCheck("DELETE missing", err)

	httpServer, digest, err = c.GetInfluxDBHTTPServer(ctx, "udp")
	if !IsOfOtherType(err) || IsNotFound(err) || !reflect.DeepEqual(httpServer, InfluxDBHTTPServer{}) || digest != "" {
		t.Errorf("GetInfluxDBHTTPServer(udp) = %+v, %q, %v, want an other-type error", httpServer, digest, err)
	}
	notCheck("GET of the other type", err)
	if _, _, err := c.GetInfluxDBUDPServer(ctx, "http"); !IsOfOtherType(err) || IsNotFound(err) {
		t.Errorf("GetInfluxDBUDPServer(http) = %v, want an other-type error", err)
	}
	if digest, err := c.MetricServerDigest(ctx, MetricServerTypeInfluxDBHTTP, "udp"); !IsOfOtherType(err) || digest != "" {
		t.Errorf("MetricServerDigest(udp) = %q, %v, want an other-type error", digest, err)
	}
	err = c.UpdateMetricServer(ctx, MetricServerTypeInfluxDBHTTP, "udp", url.Values{"token": {influxToken}})
	if !IsOfOtherType(err) || IsNotFound(err) {
		t.Errorf("UpdateMetricServer(udp) = %v, want an other-type error", err)
	}
	notCheck("PUT of the other type", err)

	err = c.CreateMetricServer(ctx, MetricServerTypeInfluxDBUDP, url.Values{"name": {"taken"}, "host": {"influx.example.com:8089"}})
	if !IsAlreadyExists(err) || IsNotFound(err) {
		t.Errorf("CreateMetricServer(taken) = %v, want an already-exists error", err)
	}
	notCheck("POST of a taken name", err)
	err = c.DeleteMetricServer(ctx, MetricServerTypeInfluxDBHTTP, "stale", "0000")
	if !IsDigestConflict(err) || IsNotFound(err) {
		t.Errorf("DeleteMetricServer(stale) = %v, want a digest conflict", err)
	}
	notCheck("DELETE with a stale digest", err)
	if servers, err := c.ListInfluxDBUDPServers(ctx); !IsForbidden(err) || servers != nil {
		t.Errorf("ListInfluxDBUDPServers() = %+v, %v, want a forbidden error", servers, err)
	}
}

// PBS may quote a rejected value in its error. The token a create or update
// sends is kept out of it — as sent and URL-encoded — while the rest of the
// error is left as it is: a failed check, with the token redacted, is still
// one. A write without a token redacts nothing.
func TestMetricServerWritesRedactTheToken(t *testing.T) {
	echo := "parameter verification failed - 'token': value '" + influxToken + "' (" + url.QueryEscape(influxToken) +
		") is not a valid token"
	tests := map[string]struct {
		route string
		write func(*Client, url.Values) error
	}{
		"create": {"POST /config/metrics/influxdb-http", func(c *Client, p url.Values) error {
			return c.CreateMetricServer(context.Background(), MetricServerTypeInfluxDBHTTP, p)
		}},
		"update": {"PUT /config/metrics/influxdb-http/influx", func(c *Client, p url.Values) error {
			return c.UpdateMetricServer(context.Background(), MetricServerTypeInfluxDBHTTP, "influx", p)
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			params := url.Values{"url": {"https://influx.example.com:8086"}, "token": {influxToken}}
			if name == "create" {
				params.Set("name", "influx")
			}
			fake := newFakePBS()
			fake.reply(tc.route, http.StatusBadRequest, echo)
			c := fake.client(t)

			err := tc.write(c, params)
			apiErr, ok := asError(err)
			if !ok || apiErr.StatusCode != http.StatusBadRequest || !strings.Contains(err.Error(), redactedMarker) {
				t.Fatalf("error = %v, want PBS's 400, redacted", err)
			}
			for _, leak := range []string{influxToken, url.QueryEscape(influxToken)} {
				if strings.Contains(err.Error(), leak) || strings.Contains(apiErr.Message, leak) || strings.Contains(apiErr.Body, leak) {
					t.Fatalf("error = %v, body = %q, leaks %q", err, apiErr.Body, leak)
				}
			}
			if !strings.HasPrefix(apiErr.Message, "parameter verification failed - 'token': value '") {
				t.Errorf("Message = %q, want the rest of PBS's text kept", apiErr.Message)
			}
			// The token itself was sent.
			if call := fake.lastCall(t, tc.route); !reflect.DeepEqual(call.form, params) {
				t.Errorf("form = %v, want %v", call.form, params)
			}

			const unauthorized = "could not connect to https://influx.example.com:8086: got bad status: 401 Unauthorized"
			fake.reply(tc.route, http.StatusBadRequest, unauthorized)
			err = tc.write(c, params)
			if apiErr, ok := asError(err); !ok || apiErr.Message != unauthorized {
				t.Errorf("error = %v, want PBS's text unchanged", err)
			}
			if check, status := MetricServerCheckFailureOf(err); check != MetricServerUnauthorized || status != http.StatusUnauthorized {
				t.Errorf("MetricServerCheckFailureOf(%v) = %v, %d, want MetricServerUnauthorized, 401", err, check, status)
			}
		})
	}

	// Without a token there is nothing to redact, not even an empty string.
	const lookup = "cannot connect to influx.invalid:8089: failed to lookup address information: Name or service not known"
	fake := newFakePBS()
	fake.reply("POST /config/metrics/influxdb-udp", http.StatusBadRequest, lookup)
	err := fake.client(t).CreateMetricServer(context.Background(), MetricServerTypeInfluxDBUDP,
		url.Values{"name": {"udp"}, "host": {"influx.invalid:8089"}})
	if apiErr, ok := asError(err); !ok || apiErr.Message != lookup || strings.Contains(err.Error(), redactedMarker) {
		t.Errorf("CreateMetricServer() without a token = %v, want PBS's text unchanged", err)
	}
}

// MetricServerCheckFailureOf tells PBS's failed checks of a metric server
// apart, by the texts PBS 4.2 answers them with, from errors with other
// causes, and returns the status the server answered with, if it answered.
// PBS 4's HTTP client reports every failed connection — a name that does not
// resolve, a refused connection, a failed TLS handshake — as "client error
// (Connect)"; PBS 3's hyper 0.14 gave the cause, which is still taken for a
// connection that failed, whatever it says.
func TestMetricServerCheckFailureOf(t *testing.T) {
	const (
		influx  = "could not connect to https://influx.example.com:8086: "
		refused = influx + "client error (Connect)"
	)
	type result struct {
		check  MetricServerCheck
		status int
	}
	for message, want := range map[string]result{
		influx + "got bad status: 401 Unauthorized":          {MetricServerUnauthorized, http.StatusUnauthorized},
		influx + "got bad status: 403 Forbidden":             {MetricServerUnauthorized, http.StatusForbidden},
		influx + "got bad status: 404 Not Found":             {MetricServerNoHealth, http.StatusNotFound},
		influx + "got bad status: 500 Internal Server Error": {MetricServerBadStatus, http.StatusInternalServerError},
		influx + "got bad status: 503 Service Unavailable":   {MetricServerBadStatus, http.StatusServiceUnavailable},
		influx + "got bad status: 302 Found":                 {MetricServerBadStatus, http.StatusFound},
		// A plain-HTTP URL to InfluxDB serving TLS.
		"could not connect to http://influx.example.com:8086: got bad status: 400 Bad Request": {MetricServerBadStatus, http.StatusBadRequest},
		// The URL's path is kept before /health.
		"could not connect to https://influx.example.com/influxdb: got bad status: 404 Not Found": {MetricServerNoHealth, http.StatusNotFound},
		refused: {MetricServerUnreachable, 0},
		"could not connect to http://[2001:db8::1]:8086: client error (Connect)":           {MetricServerUnreachable, 0},
		"could not connect to https://influx.example.com:8086: client error (SendRequest)": {MetricServerUnreachable, 0},
		// PBS 3's texts, with the cause.
		"could not connect to https://influx.invalid:8086: error trying to connect: dns error: " +
			"failed to lookup address information: Name or service not known": {MetricServerUnreachable, 0},
		influx + "error trying to connect: error:0A000086:SSL routines:tls_post_process_server_certificate:" +
			"certificate verify failed:../ssl/statem/statem_clnt.c:2091:": {MetricServerUnreachable, 0},
		"cannot connect to influx.invalid:8089: failed to lookup address information: Name or service not known": {MetricServerUnreachable, 0},

		"parameter verification failed - 'url': value 'influx' does not match the regex pattern":  {MetricServerCheckPassed, 0},
		"parameter verification failed - 'host': value 'influx' does not match the regex pattern": {MetricServerCheckPassed, 0},
		"metric server 'influx' already exists.":                                                  {MetricServerCheckPassed, 0},
		"detected modified configuration - file changed by other user? Try again.":                {MetricServerCheckPassed, 0},
		"no such influxdb-http 'influx'":                                                          {MetricServerCheckPassed, 0},
		"no such influxdb-udp 'influx'":                                                           {MetricServerCheckPassed, 0},
		"got unexpected type 'influxdb-udp' for influxdb-http 'influx'":                           {MetricServerCheckPassed, 0},
		"name 'influx' does not exist.":                                                           {MetricServerCheckPassed, 0},
		// Only at the start of PBS's text is it a check.
		"parameter verification failed - 'url': " + refused: {MetricServerCheckPassed, 0},
	} {
		err := apiError(http.StatusBadRequest, message)
		if check, status := MetricServerCheckFailureOf(err); check != want.check || status != want.status {
			t.Errorf("MetricServerCheckFailureOf(%q) = %v, %d, want %v, %d", message, check, status, want.check, want.status)
		}
	}

	// A check that failed is found behind wrapping too.
	wrapped := fmt.Errorf("creating the server: %w", apiError(http.StatusBadRequest, influx+"got bad status: 404 Not Found"))
	if check, status := MetricServerCheckFailureOf(wrapped); check != MetricServerNoHealth || status != http.StatusNotFound {
		t.Errorf("MetricServerCheckFailureOf(%v) = %v, %d, want MetricServerNoHealth, 404", wrapped, check, status)
	}

	for _, err := range []error{
		nil,
		errors.New(refused),
		&Error{StatusCode: http.StatusForbidden, Message: "permission check failed"},
		&Error{StatusCode: http.StatusForbidden, Message: influx + "got bad status: 403 Forbidden"},
		&Error{StatusCode: http.StatusInternalServerError, Message: refused},
		&Error{StatusCode: http.StatusNotFound, Message: "Path '/api2/json/config/metrics/influxdb-http' not found."},
	} {
		if check, status := MetricServerCheckFailureOf(err); check != MetricServerCheckPassed || status != 0 {
			t.Errorf("MetricServerCheckFailureOf(%v) = %v, %d, want MetricServerCheckPassed, 0", err, check, status)
		}
	}
}
