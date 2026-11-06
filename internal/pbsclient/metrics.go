package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// Metric servers are InfluxDB servers PBS sends its metrics to — host,
// disk and datastore usage, every 10 seconds — over HTTP(S) or UDP. They
// live in metricserver.cfg, one section each, keyed by name: servers of
// both types share one namespace and one digest. What PBS 4.2 does, read in
// its source (src/api2/config/metrics/{influxdbhttp,influxdbudp}.rs,
// src/api2/admin/metrics.rs, pbs-config/src/metrics.rs,
// pbs-api-types/src/metrics.rs, src/server/metric_collection/ and the
// proxmox-metrics crate):
//
//   - Every create, and every update after which the server is enabled,
//     whatever it changes, first checks the server as it would be after the
//     change, and saves nothing when that fails. For an HTTP server PBS sends
//     GET <url>/health — the URL's path kept, its query dropped — with
//     "Authorization: Token <token>" when there is a token, and wants a 2xx:
//     "could not connect to <url>: got bad status: 404 Not Found". With
//     verify-tls, the server's certificate must be valid for the URL's host
//     and signed by a CA the system trusts. When no answer comes, PBS 4 does
//     not say why: its HTTP client (proxmox-http on hyper 1 and hyper-util's
//     legacy client) reports a name that does not resolve, a refused or
//     timed-out connection and a failed TLS handshake alike, as "could not
//     connect to <url>: client error (Connect)" — the cause stays in the
//     error's source, which PBS does not print. The check does not go through
//     the node's HTTP proxy, and has no timeout of its own. It only reads
//     /health, which InfluxDB 2 and 1.8 answer without looking at the token,
//     so it tests neither the token's write access nor the organization and
//     bucket. For a UDP server PBS only resolves the host and connects a UDP
//     socket, which needs no listener: "cannot connect to <host>: failed to
//     lookup address information: …" is about all that can fail. A server
//     that is not enabled is not checked.
//   - The token of an HTTP server is never returned: reads and lists drop it,
//     though the schema says otherwise.
//   - enable is stored only when false, and deleting it enables the server.
//     Left out, organization and bucket are "proxmox", max-body-size
//     25000000 bytes, verify-tls true and mtu 1500; PBS stores and returns
//     only what was set.
//   - An update trims the comment and deletes an empty one; a create writes
//     it as sent. Every read parses the file again, which trims every value.
//   - A duplicate name, of either type, is 400 "metric server 'x' already
//     exists.". A missing server is 400 "no such influxdb-http 'x'" on GET
//     and PUT, and 400 "name 'x' does not exist." on DELETE; IsNotFound
//     covers them. A server of the other type answers GET and PUT with 400
//     "got unexpected type 'influxdb-udp' for influxdb-http 'x'",
//     IsOfOtherType, but DELETE removes a server of either type.
//   - Reading needs Sys.Audit on /, changing Sys.Modify on /.

// ConfigMetricServers is the configuration file of metric servers, as a name
// for WithConfigLock.
const ConfigMetricServers = "metricserver.cfg"

// Metric server types, as PBS names them: the path it serves them under,
// /config/metrics/<type>[/<name>].
const (
	MetricServerTypeInfluxDBHTTP = "influxdb-http"
	MetricServerTypeInfluxDBUDP  = "influxdb-udp"
)

// What PBS uses for the properties a metric server leaves out.
const (
	DefaultInfluxDBOrganization = "proxmox"
	DefaultInfluxDBBucket       = "proxmox"
	DefaultInfluxDBMaxBodySize  = 25000000
	DefaultInfluxDBMTU          = 1500
)

// InfluxDBHTTPServer is an InfluxDB HTTP metric server as PBS reports it,
// without the token, which PBS never returns. A property left out is nil or
// empty.
type InfluxDBHTTPServer struct {
	Name string `json:"name"`
	// Enable is nil for enabled: PBS stores it only when false.
	Enable       *bool  `json:"enable,omitempty"`
	URL          string `json:"url"`
	Organization string `json:"organization,omitempty"`
	Bucket       string `json:"bucket,omitempty"`
	// MaxBodySize is how many bytes of metrics PBS sends in one request.
	MaxBodySize *int64 `json:"max-body-size,omitempty"`
	VerifyTLS   *bool  `json:"verify-tls,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// InfluxDBUDPServer is an InfluxDB UDP metric server as PBS reports it.
type InfluxDBUDPServer struct {
	Name string `json:"name"`
	// Enable is nil for enabled: PBS stores it only when false.
	Enable *bool `json:"enable,omitempty"`
	// Host is "<host>:<port>", the host a DNS name, an IPv4 address or an
	// IPv6 address in brackets.
	Host string `json:"host"`
	// MTU bounds the datagrams PBS sends, in bytes.
	MTU     *int64 `json:"mtu,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// GetInfluxDBHTTPServer reads an InfluxDB HTTP metric server, and returns
// the digest of metricserver.cfg with it.
func (c *Client) GetInfluxDBHTTPServer(ctx context.Context, name string) (InfluxDBHTTPServer, string, error) {
	var server InfluxDBHTTPServer
	env, err := c.Get(ctx, Path("config", "metrics", MetricServerTypeInfluxDBHTTP, name), nil, &server)
	if err != nil {
		return InfluxDBHTTPServer{}, "", err
	}
	return server, env.Digest, nil
}

// GetInfluxDBUDPServer reads an InfluxDB UDP metric server, and returns the
// digest of metricserver.cfg with it.
func (c *Client) GetInfluxDBUDPServer(ctx context.Context, name string) (InfluxDBUDPServer, string, error) {
	var server InfluxDBUDPServer
	env, err := c.Get(ctx, Path("config", "metrics", MetricServerTypeInfluxDBUDP, name), nil, &server)
	if err != nil {
		return InfluxDBUDPServer{}, "", err
	}
	return server, env.Digest, nil
}

// ListInfluxDBHTTPServers lists the InfluxDB HTTP metric servers, without
// their tokens.
func (c *Client) ListInfluxDBHTTPServers(ctx context.Context) ([]InfluxDBHTTPServer, error) {
	var servers []InfluxDBHTTPServer
	_, err := c.Get(ctx, Path("config", "metrics", MetricServerTypeInfluxDBHTTP), nil, &servers)
	return servers, err
}

// ListInfluxDBUDPServers lists the InfluxDB UDP metric servers.
func (c *Client) ListInfluxDBUDPServers(ctx context.Context) ([]InfluxDBUDPServer, error) {
	var servers []InfluxDBUDPServer
	_, err := c.Get(ctx, Path("config", "metrics", MetricServerTypeInfluxDBUDP), nil, &servers)
	return servers, err
}

// CreateMetricServer creates a metric server of the given type —
// MetricServerTypeInfluxDBHTTP or MetricServerTypeInfluxDBUDP — from params,
// which must hold "name" and "url" or "host". PBS checks an enabled server
// before it saves it; MetricServerCheckFailureOf tells why the check failed.
// The token is kept out of any error.
func (c *Client) CreateMetricServer(ctx context.Context, serverType string, params url.Values) error {
	_, err := c.Post(ctx, Path("config", "metrics", serverType), params, nil)
	return redactAPIError(err, params.Get("token"))
}

// UpdateMetricServer changes the properties of a metric server of the given
// type that params carries, and deletes those named in its delete
// parameter. PBS checks the server as it is after the change, when it is
// enabled then, before it saves anything. The token is kept out of any
// error.
func (c *Client) UpdateMetricServer(ctx context.Context, serverType, name string, params url.Values) error {
	_, err := c.Put(ctx, Path("config", "metrics", serverType, name), params, nil)
	return redactAPIError(err, params.Get("token"))
}

// MetricServerDigest reads a metric server of the given type only to learn
// the digest of metricserver.cfg: it fails, IsOfOtherType, when the server
// has the other type.
func (c *Client) MetricServerDigest(ctx context.Context, serverType, name string) (string, error) {
	env, err := c.Get(ctx, Path("config", "metrics", serverType, name), nil, nil)
	if err != nil {
		return "", err
	}
	return env.Digest, nil
}

// DeleteMetricServer deletes a metric server, provided metricserver.cfg
// still has the digest given, when one is. PBS does not check the server's
// type — DELETE under influxdb-http removes a UDP server just as well — so
// read it first, and pass the digest of that read.
func (c *Client) DeleteMetricServer(ctx context.Context, serverType, name, digest string) error {
	var params url.Values
	if digest != "" {
		params = url.Values{"digest": {digest}}
	}
	_, err := c.Delete(ctx, Path("config", "metrics", serverType, name), params, nil)
	return err
}

// MetricServerCheck is why PBS refused to save a metric server: what went
// wrong when it checked the server first.
type MetricServerCheck int

const (
	// MetricServerCheckPassed: the error is not a failed check.
	MetricServerCheckPassed MetricServerCheck = iota
	// MetricServerUnreachable: PBS could not connect to the server. For
	// HTTP, the name did not resolve, nothing answered, the connection
	// failed, or the TLS handshake did — PBS 4 reports all of them as
	// "client error (Connect)", without the cause; for UDP, the name did not
	// resolve or there is no route.
	MetricServerUnreachable
	// MetricServerUnauthorized: the server answered GET <url>/health with
	// 401 or 403, refusing the token or the lack of one.
	MetricServerUnauthorized
	// MetricServerNoHealth: the server answered GET <url>/health with 404:
	// no InfluxDB API at the URL's path.
	MetricServerNoHealth
	// MetricServerBadStatus: the server answered GET <url>/health with
	// another status that is not a 2xx, such as a 5xx or a redirect.
	MetricServerBadStatus
)

// metricServerCheckPattern is PBS's error when the check of a metric server
// failed: "could not connect to <url>: <reason>" for HTTP, "cannot connect
// to <host>: <reason>" for UDP.
var metricServerCheckPattern = regexp.MustCompile(`^(?:could not|cannot) connect to \S+: `)

// badStatusPattern is the reason of a check that got an answer other than a
// 2xx, with its status code.
var badStatusPattern = regexp.MustCompile(`got bad status: ([0-9]{3})\b`)

// MetricServerCheckFailureOf tells, from the 400 PBS answered a create or
// update of a metric server with, whether and how its check of the server
// failed, and the HTTP status the server answered with, if it answered.
func MetricServerCheckFailureOf(err error) (check MetricServerCheck, status int) {
	apiErr, ok := asError(err)
	if !ok || apiErr.StatusCode != http.StatusBadRequest {
		return MetricServerCheckPassed, 0
	}
	loc := metricServerCheckPattern.FindStringIndex(apiErr.Message)
	if loc == nil {
		return MetricServerCheckPassed, 0
	}
	reason := apiErr.Message[loc[1]:]
	if m := badStatusPattern.FindStringSubmatch(reason); m != nil {
		status, _ = strconv.Atoi(m[1])
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return MetricServerUnauthorized, status
		case http.StatusNotFound:
			return MetricServerNoHealth, status
		}
		return MetricServerBadStatus, status
	}
	return MetricServerUnreachable, 0
}
