package provider

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of pbs_metric_server_influxdb_http, _udp and
// pbs_metric_servers. PBS checks an enabled server before it saves it, from
// its own host, so the tests run the InfluxDB servers themselves, on the host
// they run on, which the PBS container reaches at PBS_ACC_HOST_ADDRESS: an
// HTTP server that answers InfluxDB 2's /health and write API, over HTTP or
// HTTPS with a certificate nobody trusts, and a UDP socket. PBS then sends
// its metrics to them every 10 seconds, which the tests wait for. A server
// that is not enabled is not checked, so the tests that need no metrics use
// disabled HTTP servers on hosts that do not exist, and UDP servers on the
// PBS host's loopback address, which PBS resolves and connects a socket to
// without a listener.

// testAccInfluxDBPath is the path of the receiver's base URL, as a reverse
// proxy serving InfluxDB below a path has it: PBS must keep it in front of
// /health and /api/v2/write.
const testAccInfluxDBPath = "/influx"

// testAccMetricsTimeout is how long the tests wait for PBS to send metrics,
// which it does every 10 seconds.
const testAccMetricsTimeout = 60 * time.Second

// testAccMetricServerName returns a fresh metric server name.
func testAccMetricServerName() string {
	return "tfacc-" + testAccRandom(8)
}

// testAccCheckMetricServersDestroyed checks that no metric server of either
// type has any of the names. HTTP and UDP servers share one namespace, so
// one GET tells: PBS answers it with the server, with "got unexpected type"
// for a server of the other type, and with "no such influxdb-http" only when
// there is none.
func testAccCheckMetricServersDestroyed(names ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		for _, name := range names {
			_, err := client.MetricServerDigest(context.Background(), pbsclient.MetricServerTypeInfluxDBHTTP, name)
			switch {
			case err == nil || pbsclient.IsOfOtherType(err):
				return fmt.Errorf("metric server %s still exists", name)
			case !pbsclient.IsNotFound(err):
				return err
			}
		}
		return nil
	}
}

// testAccCheckInfluxDBHTTPServer checks an InfluxDB HTTP server as PBS
// reports it.
func testAccCheckInfluxDBHTTPServer(name string, check func(pbsclient.InfluxDBHTTPServer) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		server, _, err := client.GetInfluxDBHTTPServer(context.Background(), name)
		if err != nil {
			return err
		}
		if err := check(server); err != nil {
			return fmt.Errorf("InfluxDB HTTP server %s: %w", name, err)
		}
		return nil
	}
}

// testAccCheckInfluxDBUDPServer checks an InfluxDB UDP server as PBS
// reports it.
func testAccCheckInfluxDBUDPServer(name string, check func(pbsclient.InfluxDBUDPServer) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		server, _, err := client.GetInfluxDBUDPServer(context.Background(), name)
		if err != nil {
			return err
		}
		if err := check(server); err != nil {
			return fmt.Errorf("InfluxDB UDP server %s: %w", name, err)
		}
		return nil
	}
}

// testAccCheckSortedBy checks that the elements of a list attribute are
// sorted by their key attribute.
func testAccCheckSortedBy(resourceName, list, key string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("%s is not in state", resourceName)
		}
		attributes := rs.Primary.Attributes
		n, _ := strconv.Atoi(attributes[list+".#"])
		for i := 1; i < n; i++ {
			prev, next := attributes[fmt.Sprintf("%s.%d.%s", list, i-1, key)], attributes[fmt.Sprintf("%s.%d.%s", list, i, key)]
			if prev > next {
				return fmt.Errorf("%s: %s are not sorted by %s: %q comes before %q", resourceName, list, key, prev, next)
			}
		}
		return nil
	}
}

// testAccLineProtocolPattern matches a line of InfluxDB line protocol as far
// as the tests look: a measurement, its tags if any, a space and a field,
// key=value. A backslash escapes the character after it.
var testAccLineProtocolPattern = regexp.MustCompile(`^(?:[^\s,\\]|\\.)+(?:,(?:[^\s\\]|\\.)+)? (?:[^\s=\\]|\\.)+=\S`)

// testAccIsLineProtocol reports whether s is one or more lines of InfluxDB
// line protocol, each ended by a newline but perhaps the last.
func testAccIsLineProtocol(s string) bool {
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if !testAccLineProtocolPattern.MatchString(line) {
			return false
		}
	}
	return true
}

// testAccAwaitMetrics polls received every second until it reports true or
// testAccMetricsTimeout has passed, and returns what it reported last.
func testAccAwaitMetrics(received func() bool) bool {
	deadline := time.Now().Add(testAccMetricsTimeout)
	for !received() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
	return true
}

// testAccInfluxDBReceiver is the InfluxDB HTTP server of the tests: it
// serves InfluxDB 2's /health and write API below testAccInfluxDBPath, on
// every interface of the host, which the PBS container reaches at
// PBS_ACC_HOST_ADDRESS. Like InfluxDB 3 without --disable-authz health, it
// answers /health with 204 only when the request carries the token it
// expects, and with 401 otherwise; it answers writes the same way, other
// paths with 404, and records every request. The test skips without that
// address.
type testAccInfluxDBReceiver struct {
	// url is the base URL PBS reaches the receiver at, its path included.
	url string
	mu  sync.Mutex
	// token is the token the receiver accepts.
	token    string
	requests []testAccInfluxDBRequest
}

// testAccInfluxDBRequest is a request PBS sent the receiver.
type testAccInfluxDBRequest struct {
	method, path, authorization string
	// org and bucket are the query parameters of a write.
	org, bucket string
	// lineProtocol is whether the body is InfluxDB line protocol.
	lineProtocol bool
}

// newTestAccInfluxDBReceiver starts a receiver that accepts token, over
// HTTPS with a certificate PBS does not trust when secure is set.
func newTestAccInfluxDBReceiver(t *testing.T, token string, secure bool) *testAccInfluxDBReceiver {
	t.Helper()
	host := os.Getenv(envAccHostAddress)
	if host == "" {
		t.Skipf("%s is not set, so PBS cannot reach an InfluxDB server on this host", envAccHostAddress)
	}
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	r := &testAccInfluxDBReceiver{token: token}
	server := httptest.NewUnstartedServer(r)
	// httptest listens on the loopback interface, which the PBS container
	// does not reach.
	_ = server.Listener.Close()
	server.Listener = listener
	// PBS's failed TLS handshakes are expected; they need not be logged.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	scheme := "http"
	if secure {
		// httptest's certificate, for example.com and the loopback
		// addresses, is signed by a CA of its own, which PBS does not trust.
		server.StartTLS()
		scheme = "https"
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	r.url = scheme + "://" + net.JoinHostPort(host, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)) + testAccInfluxDBPath
	return r
}

func (r *testAccInfluxDBReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	query := req.URL.Query()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, testAccInfluxDBRequest{
		method:        req.Method,
		path:          req.URL.Path,
		authorization: req.Header.Get("Authorization"),
		org:           query.Get("org"),
		bucket:        query.Get("bucket"),
		lineProtocol:  testAccIsLineProtocol(string(body)),
	})
	switch {
	case req.URL.Path != testAccInfluxDBPath+"/health" && req.URL.Path != testAccInfluxDBPath+"/api/v2/write":
		w.WriteHeader(http.StatusNotFound)
	case req.Header.Get("Authorization") != "Token "+r.token:
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// setToken has the receiver accept another token from now on.
func (r *testAccInfluxDBReceiver) setToken(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.token = token
}

// checkedHealth checks that PBS checked the server, GET <path>/health, with
// the token.
func (r *testAccInfluxDBReceiver) checkedHealth(token string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, req := range r.requests {
			if req.method == http.MethodGet && req.path == testAccInfluxDBPath+"/health" && req.authorization == "Token "+token {
				return nil
			}
		}
		return fmt.Errorf("PBS did not check the server at %s with the token %q; the receiver got %+v", r.url, token, r.requests)
	}
}

// wroteMetrics waits for PBS to send metrics with InfluxDB 2's write API: a
// POST of line protocol to <path>/api/v2/write, for the organization and
// bucket, with the token.
func (r *testAccInfluxDBReceiver) wroteMetrics(org, bucket, token string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		wrote := func() bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			for _, req := range r.requests {
				if req.method == http.MethodPost && req.path == testAccInfluxDBPath+"/api/v2/write" && req.org == org &&
					req.bucket == bucket && req.authorization == "Token "+token && req.lineProtocol {
					return true
				}
			}
			return false
		}
		if testAccAwaitMetrics(wrote) {
			return nil
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		return fmt.Errorf("PBS wrote no metrics to %s for org %q and bucket %q with the token %q within %s; the receiver got %+v",
			r.url, org, bucket, token, testAccMetricsTimeout, r.requests)
	}
}

// testAccUDPReceiver is the InfluxDB UDP listener of the tests: a socket on
// every interface of the host, which the PBS container reaches at
// PBS_ACC_HOST_ADDRESS, recording the datagrams it receives. The test skips
// without that address.
type testAccUDPReceiver struct {
	// host is the address PBS reaches the socket at, <host>:<port>.
	host      string
	mu        sync.Mutex
	datagrams []string
}

func newTestAccUDPReceiver(t *testing.T) *testAccUDPReceiver {
	t.Helper()
	host := os.Getenv(envAccHostAddress)
	if host == "" {
		t.Skipf("%s is not set, so PBS cannot reach an InfluxDB UDP listener on this host", envAccHostAddress)
	}
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	r := &testAccUDPReceiver{host: net.JoinHostPort(host, strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port))}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				// The socket is closed.
				return
			}
			r.mu.Lock()
			r.datagrams = append(r.datagrams, string(buf[:n]))
			r.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return r
}

// receivedMetrics waits for PBS to send metrics, a datagram of line
// protocol, and checks that every datagram so far is line protocol and at
// most mtu bytes long. UDP from the PBS container should reach the host as
// TCP does; when nothing arrives, the check says so instead of waiting on.
func (r *testAccUDPReceiver) receivedMetrics(mtu int) acc.TestCheckFunc {
	return func(*terraform.State) error {
		received := func() bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			return len(r.datagrams) > 0
		}
		if !testAccAwaitMetrics(received) {
			return fmt.Errorf("no datagram reached %s within %s: PBS sent no metrics, or UDP from the PBS container does "+
				"not reach this host, as TCP does; look for a firewall on the host", r.host, testAccMetricsTimeout)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, d := range r.datagrams {
			if !testAccIsLineProtocol(d) || len(d) > mtu {
				return fmt.Errorf("PBS sent a datagram of %d bytes that is not line protocol or exceeds the MTU of %d: %q", len(d), mtu, d)
			}
		}
		return nil
	}
}

// An HTTP server through its life, against the receiver: created with a
// token and every setting, which PBS checks with the token and then writes
// metrics with, to the organization and bucket; imported; the settings back
// to PBS's defaults, which PBS no longer stores, and a new token, which the
// check of the update and the writes after it carry; and disabled, with a
// URL nothing answers at, which PBS saves without a check.
func TestAccMetricServerInfluxDBHTTP(t *testing.T) {
	receiver := newTestAccInfluxDBReceiver(t, "tfacc-token-1", false)
	name := testAccMetricServerName()
	const resourceName = "pbs_metric_server_influxdb_http.test"
	config := func(serverURL string, version int, body string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_metric_server_influxdb_http" "test" {
  name             = %q
  url              = %q
  token_wo         = "tfacc-token-%d"
  token_wo_version = %d
%s
}
`, name, serverURL, version, version, body)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckMetricServersDestroyed(name),
		Steps: []acc.TestStep{
			{
				Config: config(receiver.url, 1, `
  organization  = "tfacc-org"
  bucket        = "tfacc-bucket"
  max_body_size = 65536
  comment       = "terraform-provider-pbs acceptance tests"`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckResourceAttr(resourceName, "url", receiver.url),
					acc.TestCheckResourceAttr(resourceName, "organization", "tfacc-org"),
					acc.TestCheckResourceAttr(resourceName, "bucket", "tfacc-bucket"),
					acc.TestCheckResourceAttr(resourceName, "max_body_size", "65536"),
					acc.TestCheckResourceAttr(resourceName, "verify_tls", "true"),
					acc.TestCheckResourceAttr(resourceName, "enable", "true"),
					acc.TestCheckResourceAttr(resourceName, "comment", "terraform-provider-pbs acceptance tests"),
					acc.TestCheckNoResourceAttr(resourceName, "token_wo"),
					acc.TestCheckResourceAttr(resourceName, "token_wo_version", "1"),
					testAccCheckInfluxDBHTTPServer(name, func(s pbsclient.InfluxDBHTTPServer) error {
						// enable and verify-tls keep PBS's defaults, which the
						// provider does not send.
						if s.URL != receiver.url || s.Organization != "tfacc-org" || s.Bucket != "tfacc-bucket" ||
							s.MaxBodySize == nil || *s.MaxBodySize != 65536 || s.VerifyTLS != nil || s.Enable != nil ||
							s.Comment != "terraform-provider-pbs acceptance tests" {
							return fmt.Errorf("server = %+v", s)
						}
						return nil
					}),
					receiver.checkedHealth("tfacc-token-1"),
					receiver.wroteMetrics("tfacc-org", "tfacc-bucket", "tfacc-token-1"),
				),
			},
			{
				// PBS never returns the token.
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"token_wo", "token_wo_version"},
			},
			{
				// The settings removed go back to PBS's defaults, which an
				// update deletes; the check of the update carries the new
				// token, which the receiver now wants.
				PreConfig: func() { receiver.setToken("tfacc-token-2") },
				Config:    config(receiver.url, 2, ""),
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
				}},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "organization", pbsclient.DefaultInfluxDBOrganization),
					acc.TestCheckResourceAttr(resourceName, "bucket", pbsclient.DefaultInfluxDBBucket),
					acc.TestCheckResourceAttr(resourceName, "max_body_size", strconv.Itoa(pbsclient.DefaultInfluxDBMaxBodySize)),
					acc.TestCheckNoResourceAttr(resourceName, "comment"),
					acc.TestCheckResourceAttr(resourceName, "token_wo_version", "2"),
					testAccCheckInfluxDBHTTPServer(name, func(s pbsclient.InfluxDBHTTPServer) error {
						if s.Organization != "" || s.Bucket != "" || s.MaxBodySize != nil || s.Comment != "" {
							return fmt.Errorf("PBS kept settings removed from the server: %+v", s)
						}
						return nil
					}),
					receiver.checkedHealth("tfacc-token-2"),
					receiver.wroteMetrics(pbsclient.DefaultInfluxDBOrganization, pbsclient.DefaultInfluxDBBucket, "tfacc-token-2"),
				),
			},
			{
				// Nothing listens on port 1 of the PBS host: a disabled server
				// is saved without a check, or the update would fail.
				Config: config("http://127.0.0.1:1", 2, `  enable = false`),
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
				}},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "url", "http://127.0.0.1:1"),
					acc.TestCheckResourceAttr(resourceName, "enable", "false"),
					testAccCheckInfluxDBHTTPServer(name, func(s pbsclient.InfluxDBHTTPServer) error {
						if s.URL != "http://127.0.0.1:1" || s.Enable == nil || *s.Enable {
							return fmt.Errorf("server = %+v", s)
						}
						return nil
					}),
				),
			},
		},
	})
}

// PBS saves no HTTP server whose check fails, and the provider says what to
// look at: a token the server refuses, a path without InfluxDB's API, a port
// nothing listens on, and a certificate PBS does not trust. Each failure
// leaves nothing behind; with verify_tls = false, PBS takes the certificate.
func TestAccMetricServerInfluxDBHTTPCheckFails(t *testing.T) {
	receiver := newTestAccInfluxDBReceiver(t, "tfacc-token", false)
	tlsReceiver := newTestAccInfluxDBReceiver(t, "tfacc-token", true)
	name := testAccMetricServerName()
	const resourceName = "pbs_metric_server_influxdb_http.test"
	config := func(serverURL, token, extra string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_metric_server_influxdb_http" "test" {
  name             = %q
  url              = %q
  token_wo         = %q
  token_wo_version = 1
  %s
}
`, name, serverURL, token, extra)
	}
	nothingSaved := func() {
		if err := testAccCheckMetricServersDestroyed(name)(nil); err != nil {
			t.Fatalf("after PBS refused the server: %v", err)
		}
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckMetricServersDestroyed(name),
		Steps: []acc.TestStep{
			{
				Config:      config(receiver.url, "wrong-token", ""),
				ExpectError: regexp.MustCompile(`refusing\s+the\s+token\s+or\s+the\s+lack\s+of\s+one`),
			},
			{
				PreConfig:   nothingSaved,
				Config:      config(receiver.url+"/wrong", "tfacc-token", ""),
				ExpectError: regexp.MustCompile(`there\s+is\s+no\s+InfluxDB\s+API\s+at\s+that\s+path`),
			},
			{
				// Nothing listens on port 1 of the PBS host.
				PreConfig:   nothingSaved,
				Config:      config("http://127.0.0.1:1", "tfacc-token", ""),
				ExpectError: regexp.MustCompile(`PBS\s+could\s+not\s+connect\s+to`),
			},
			{
				// PBS 4 says no more than "client error (Connect)" when the
				// handshake fails, so the advice for an https:// URL covers
				// the certificate as well.
				PreConfig:   nothingSaved,
				Config:      config(tlsReceiver.url, "tfacc-token", ""),
				ExpectError: regexp.MustCompile(`signed\s+by\s+a\s+CA\s+the\s+PBS\s+host\s+trusts`),
			},
			{
				PreConfig: nothingSaved,
				Config:    config(tlsReceiver.url, "tfacc-token", "verify_tls = false"),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "verify_tls", "false"),
					testAccCheckInfluxDBHTTPServer(name, func(s pbsclient.InfluxDBHTTPServer) error {
						if s.URL != tlsReceiver.url || s.VerifyTLS == nil || *s.VerifyTLS {
							return fmt.Errorf("server = %+v", s)
						}
						return nil
					}),
					tlsReceiver.checkedHealth("tfacc-token"),
				),
			},
		},
	})
}

// A UDP server through its life, against the test's socket: created with an
// MTU and a comment, after which PBS sends its metrics in datagrams no
// larger than the MTU; imported; both back to the defaults; a host that does
// not resolve, which PBS refuses, keeping the server as it was; and the same
// host with the server disabled, which PBS saves without resolving it.
func TestAccMetricServerInfluxDBUDP(t *testing.T) {
	receiver := newTestAccUDPReceiver(t)
	name := testAccMetricServerName()
	const resourceName = "pbs_metric_server_influxdb_udp.test"
	const unresolvable = "influxdb.invalid:8089"
	config := func(host, body string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_metric_server_influxdb_udp" "test" {
  name = %q
  host = %q
%s
}
`, name, host, body)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckMetricServersDestroyed(name),
		Steps: []acc.TestStep{
			{
				Config: config(receiver.host, `
  mtu     = 1000
  comment = "terraform-provider-pbs acceptance tests"`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckResourceAttr(resourceName, "host", receiver.host),
					acc.TestCheckResourceAttr(resourceName, "mtu", "1000"),
					acc.TestCheckResourceAttr(resourceName, "enable", "true"),
					acc.TestCheckResourceAttr(resourceName, "comment", "terraform-provider-pbs acceptance tests"),
					testAccCheckInfluxDBUDPServer(name, func(s pbsclient.InfluxDBUDPServer) error {
						if s.Host != receiver.host || s.MTU == nil || *s.MTU != 1000 || s.Enable != nil ||
							s.Comment != "terraform-provider-pbs acceptance tests" {
							return fmt.Errorf("server = %+v", s)
						}
						return nil
					}),
					receiver.receivedMetrics(1000),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: config(receiver.host, ""),
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
				}},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "mtu", strconv.Itoa(pbsclient.DefaultInfluxDBMTU)),
					acc.TestCheckNoResourceAttr(resourceName, "comment"),
					testAccCheckInfluxDBUDPServer(name, func(s pbsclient.InfluxDBUDPServer) error {
						if s.MTU != nil || s.Comment != "" {
							return fmt.Errorf("PBS kept settings removed from the server: %+v", s)
						}
						return nil
					}),
				),
			},
			{
				// The name does not resolve on the PBS host.
				Config:      config(unresolvable, ""),
				ExpectError: regexp.MustCompile(`PBS\s+could\s+not\s+resolve\s+influxdb\.invalid:8089`),
			},
			{
				// PBS saved nothing of the refused update; disabled, the
				// server is saved without a check.
				PreConfig: func() {
					err := testAccCheckInfluxDBUDPServer(name, func(s pbsclient.InfluxDBUDPServer) error {
						if s.Host != receiver.host {
							return fmt.Errorf("PBS saved the host it refused: %+v", s)
						}
						return nil
					})(nil)
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: config(unresolvable, `  enable = false`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "host", unresolvable),
					acc.TestCheckResourceAttr(resourceName, "enable", "false"),
					testAccCheckInfluxDBUDPServer(name, func(s pbsclient.InfluxDBUDPServer) error {
						if s.Host != unresolvable || s.Enable == nil || *s.Enable {
							return fmt.Errorf("server = %+v", s)
						}
						return nil
					}),
				),
			},
		},
	})
}

// HTTP and UDP servers share one namespace: a UDP server cannot take the
// name of an HTTP one. When a UDP server replaces the HTTP server outside
// Terraform, a refresh drops the HTTP resource from state, with a warning,
// and plans to create it again; destroying the resource — which the test's
// destroy does without a refresh, so that Delete meets the UDP server —
// leaves the UDP server alone, though PBS's DELETE would remove it.
func TestAccMetricServerSharedNamespace(t *testing.T) {
	name := testAccMetricServerName()
	const resourceName = "pbs_metric_server_influxdb_http.test"
	// Disabled, the HTTP server is saved without a check.
	httpConfig := providerConfig + fmt.Sprintf(`
resource "pbs_metric_server_influxdb_http" "test" {
  name   = %q
  url    = "http://influxdb.invalid:8086"
  enable = false
}
`, name)
	const udpHost = "127.0.0.1:8089"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckInfluxDBUDPServer(name, func(s pbsclient.InfluxDBUDPServer) error {
				if s.Host != udpHost {
					return fmt.Errorf("server = %+v", s)
				}
				return nil
			}),
			func(*terraform.State) error {
				client, err := testAccClient()
				if err != nil {
					return err
				}
				if _, _, err := client.GetInfluxDBHTTPServer(context.Background(), name); !pbsclient.IsOfOtherType(err) {
					return fmt.Errorf("reading %s as an InfluxDB HTTP server: %v, want an error of another type", name, err)
				}
				return nil
			},
		),
		Steps: []acc.TestStep{
			{
				// The UDP server waits for the HTTP one, so that it is the
				// UDP server PBS refuses.
				Config: httpConfig + fmt.Sprintf(`
resource "pbs_metric_server_influxdb_udp" "test" {
  name       = %q
  host       = %q
  depends_on = [pbs_metric_server_influxdb_http.test]
}
`, name, udpHost),
				ExpectError: regexp.MustCompile(`PBS\s+metric\s+server\s+already\s+exists`),
			},
			{
				Config: httpConfig,
				Check: testAccCheckInfluxDBHTTPServer(name, func(s pbsclient.InfluxDBHTTPServer) error {
					if s.URL != "http://influxdb.invalid:8086" || s.Enable == nil || *s.Enable {
						return fmt.Errorf("server = %+v", s)
					}
					return nil
				}),
			},
			{
				// The HTTP server replaced by a UDP one outside Terraform,
				// which the test deletes when it ends.
				PreConfig: func() {
					client, err := testAccClient()
					if err != nil {
						t.Fatal(err)
					}
					ctx := context.Background()
					if err := client.DeleteMetricServer(ctx, pbsclient.MetricServerTypeInfluxDBHTTP, name, ""); err != nil {
						t.Fatalf("deleting the HTTP server: %v", err)
					}
					if err := client.CreateMetricServer(ctx, pbsclient.MetricServerTypeInfluxDBUDP, url.Values{
						"name": {name}, "host": {udpHost}, "enable": {pbsclient.FormatBool(false)},
					}); err != nil {
						t.Fatalf("creating the UDP server: %v", err)
					}
					t.Cleanup(func() {
						err := client.DeleteMetricServer(context.Background(), pbsclient.MetricServerTypeInfluxDBUDP, name, "")
						if err != nil && !pbsclient.IsNotFound(err) {
							t.Errorf("deleting the UDP server %s: %v", name, err)
						}
					})
				},
				Config:             httpConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				ConfigPlanChecks: acc.ConfigPlanChecks{PostApplyPostRefresh: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionCreate),
				}},
			},
		},
	})
}

// From Terraform 1.12, both resources import by identity too. The HTTP
// server has no token, which an import cannot read, so that its import
// plans no change; disabled, it needs no InfluxDB server.
func TestAccMetricServerImportByIdentity(t *testing.T) {
	httpName, udpName := testAccMetricServerName(), testAccMetricServerName()
	config := providerConfig + fmt.Sprintf(`
resource "pbs_metric_server_influxdb_http" "test" {
  name         = %q
  url          = "https://influxdb.invalid:8086/influx"
  organization = "tfacc-org"
  verify_tls   = false
  enable       = false
}

resource "pbs_metric_server_influxdb_udp" "test" {
  name = %q
  host = "127.0.0.1:8089"
  mtu  = 1400
}
`, httpName, udpName)

	steps := []acc.TestStep{{Config: config}}
	for _, resourceName := range []string{"pbs_metric_server_influxdb_http.test", "pbs_metric_server_influxdb_udp.test"} {
		steps = append(steps,
			acc.TestStep{Config: config, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			acc.TestStep{Config: config, ResourceName: resourceName, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckMetricServersDestroyed(httpName, udpName),
		Steps:                    steps,
	})
}

// pbs_metric_servers lists the servers of both types together, sorted by
// name though PBS lists each type in no order, with PBS's defaults for the
// settings a server leaves out, and the settings of the other type null.
func TestAccMetricServersDataSource(t *testing.T) {
	base := testAccMetricServerName()
	// The UDP server sorts first, though the provider reads the HTTP
	// servers first.
	httpName, udpName := base+"-b", base+"-a"
	const dataName = "data.pbs_metric_servers.all"

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckMetricServersDestroyed(httpName, udpName),
		Steps: []acc.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "pbs_metric_server_influxdb_http" "test" {
  name    = %q
  url     = "http://influxdb.invalid:8086"
  enable  = false
  comment = "terraform-provider-pbs acceptance tests"
}

resource "pbs_metric_server_influxdb_udp" "test" {
  name = %q
  host = "127.0.0.1:8089"
}

data "pbs_metric_servers" "all" {
  depends_on = [pbs_metric_server_influxdb_http.test, pbs_metric_server_influxdb_udp.test]
}
`, httpName, udpName),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckListElement(dataName, "servers", "name", httpName, map[string]string{
						"type":          pbsclient.MetricServerTypeInfluxDBHTTP,
						"enable":        "false",
						"comment":       "terraform-provider-pbs acceptance tests",
						"url":           "http://influxdb.invalid:8086",
						"organization":  pbsclient.DefaultInfluxDBOrganization,
						"bucket":        pbsclient.DefaultInfluxDBBucket,
						"max_body_size": strconv.Itoa(pbsclient.DefaultInfluxDBMaxBodySize),
						"verify_tls":    "true",
						"host":          "",
						"mtu":           "",
					}),
					testAccCheckListElement(dataName, "servers", "name", udpName, map[string]string{
						"type":          pbsclient.MetricServerTypeInfluxDBUDP,
						"enable":        "true",
						"comment":       "",
						"url":           "",
						"organization":  "",
						"bucket":        "",
						"max_body_size": "",
						"verify_tls":    "",
						"host":          "127.0.0.1:8089",
						"mtu":           strconv.Itoa(pbsclient.DefaultInfluxDBMTU),
					}),
					testAccCheckSortedBy(dataName, "servers", "name"),
				),
			},
		},
	})
}
