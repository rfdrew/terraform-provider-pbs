package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// newServiceHarness serves the services of node localhost, and its
// certificate and node.cfg through the ACME fake, which the checks of the
// proxy read.
func newServiceHarness(t *testing.T, opts ...harnessOption) (*protocolHarness, *fakePBS, *fakeServices, *fakeACME) {
	t.Helper()
	fastServiceSettle(t)
	fake := newFakePBS()
	services := newFakeServices(fake)
	acme := newFakeACME(t, fake)
	return newProtocolHarness(t, fake, opts...), fake, services, acme
}

// fastServiceSettle shortens the waits after a command for the test.
func fastServiceSettle(t *testing.T) {
	t.Helper()
	settle, poll, handover := serviceSettleTime, serviceSettlePoll, serviceHandoverGrace
	serviceSettleTime, serviceSettlePoll, serviceHandoverGrace = time.Second, 50*time.Millisecond, 2*time.Second
	t.Cleanup(func() { serviceSettleTime, serviceSettlePoll, serviceHandoverGrace = settle, poll, handover })
}

// requireCommands fails the test unless PBS ran exactly the commands want.
func requireCommands(t *testing.T, services *fakeServices, want ...string) {
	t.Helper()
	if got := services.ran(); !slices.Equal(got, want) {
		t.Fatalf("PBS ran %q, want %q", got, want)
	}
}

func TestServiceActionSchemas(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, tc := range []struct {
		action    string
		skipFlags bool
	}{
		{"pbs_service_reload", true},
		{"pbs_service_restart", true},
		{"pbs_service_start", false},
	} {
		names := map[string]bool{}
		for _, attribute := range h.actionSchema(t, tc.action).Block.Attributes {
			names[attribute.Name] = true
		}
		if names["wait"] || names["force"] || !names["service"] || !names["node"] || !names["timeout"] {
			t.Errorf("%s has attributes %v", tc.action, names)
		}
		if names["skip_certificate_match"] != tc.skipFlags || names["skip_checks"] != tc.skipFlags {
			t.Errorf("%s: skip_certificate_match and skip_checks are %v, want %v", tc.action, names, tc.skipFlags)
		}
	}
}

func TestServiceActionValidation(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())
	for _, tc := range []struct {
		action string
		attrs  map[string]any
		want   string
	}{
		{"pbs_service_reload", map[string]any{"service": "ssh"}, "value must be one of"},
		{"pbs_service_start", map[string]any{"service": "-bad"}, "value must be one of"},
		{"pbs_service_restart", map[string]any{"service": "proxmox-backup.service"}, "value must be one of"},
		{"pbs_service_reload", map[string]any{"service": "postfix", "node": "-bad"}, "node name"},
		{"pbs_service_start", map[string]any{"service": "postfix", "timeout": "0s"}, "positive duration"},
		{"pbs_service_restart", map[string]any{"service": "proxmox-backup"}, "pbs_service_reload"},
	} {
		requireProtocolErrorContaining(t, h.validateAction(t, tc.action, h.actionValue(t, tc.action, tc.attrs)), tc.want)
	}
	for _, tc := range []struct {
		action string
		attrs  map[string]any
	}{
		{"pbs_service_reload", map[string]any{"service": "proxmox-backup"}},
		{"pbs_service_restart", map[string]any{"service": "proxmox-backup-proxy", "skip_checks": true}},
		{"pbs_service_reload", map[string]any{"service": tfUnknown, "node": tfUnknown, "timeout": tfUnknown,
			"skip_certificate_match": tfUnknown, "skip_checks": tfUnknown}},
		{"pbs_service_restart", map[string]any{"service": tfUnknown}},
		{"pbs_service_start", map[string]any{"service": tfUnknown, "node": tfUnknown, "timeout": tfUnknown}},
	} {
		config := h.actionValue(t, tc.action, tc.attrs)
		requireNoProtocolErrors(t, h.validateAction(t, tc.action, config))
		requireNoProtocolErrors(t, h.planAction(t, tc.action, config))
	}
}

// A value known only at apply time passes validation; Invoke checks it
// again, since PBS hands any name to systemctl as root.
func TestServiceActionChecksTheServiceAgainWhenInvoked(t *testing.T) {
	h, _, services, _ := newServiceHarness(t)
	got := h.invokeActionWith(context.Background(), t, "pbs_service_reload",
		h.actionValue(t, "pbs_service_reload", map[string]any{"service": "--force"}))
	requireProtocolErrorContaining(t, got.diagnostics, `Unknown PBS service "--force"`)
	got = h.invokeActionWith(context.Background(), t, "pbs_service_restart",
		h.actionValue(t, "pbs_service_restart", map[string]any{"service": "proxmox-backup"}))
	requireProtocolErrorContaining(t, got.diagnostics, "PBS's API daemon cannot be restarted through its API")
	requireCommands(t, services)
}

func TestServiceActionsRunTheirCommand(t *testing.T) {
	for _, tc := range []struct {
		action, service, before, command, done string
	}{
		{"pbs_service_restart", "postfix", "running", "restart postfix", "PBS restarted service postfix on node localhost; systemd reports it running"},
		{"pbs_service_restart", "chrony", "failed", "restart chrony", "PBS restarted service chrony"},
		{"pbs_service_reload", "sshd", "running", "reload sshd", "PBS reloaded service sshd on node localhost; systemd reports it running"},
		{"pbs_service_start", "cron", "dead", "start cron", "PBS started service cron on node localhost; systemd reports it running"},
		{"pbs_service_reload", "proxmox-backup", "running", "reload proxmox-backup",
			"the old process finishes the connections and tasks it had"},
	} {
		t.Run(tc.action+" "+tc.service, func(t *testing.T) {
			h, fake, services, _ := newServiceHarness(t)
			services.set(tc.service, tc.before, "enabled")
			services.configure(func(s *fakeServices) { s.running = 1 })

			got := h.invokeAction(t, tc.action, map[string]any{"service": tc.service})
			requireNoProtocolErrors(t, got.diagnostics)
			if len(got.diagnostics) != 0 {
				t.Fatalf("diagnostics: %v", got.diagnostics)
			}
			requireCommands(t, services, tc.command)
			requireProgressContaining(t, got, "PBS started task UPID:pbs-tasks:")
			requireProgressContaining(t, got, ":srv"+strings.Fields(tc.command)[0]+":"+tc.service+":")
			requireProgressContaining(t, got, tc.done)
			// The state before, the command, the state after; nothing about
			// the proxy, which is not reloaded.
			route := "/nodes/localhost/services/" + tc.service
			if fake.count("GET "+route+"/state") < 2 || fake.count("POST "+route+"/"+strings.Fields(tc.command)[0]) != 1 ||
				fake.count("GET /nodes/localhost/certificates/info") != 0 {
				t.Fatalf("routes: %v", fake.routes())
			}
		})
	}
}

// What the state before the command rules out is refused, or skipped,
// before PBS is asked.
func TestServiceActionsCheckTheStateFirst(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		action, service        string
		state, unitState, want string
		warning, progress      bool
	}{
		{"not installed", "pbs_service_restart", "chrony", "dead", "not-found", "Service chrony is not installed on PBS node localhost", false, false},
		{"not installed reload", "pbs_service_reload", "cron", "dead", "not-found", "cron and chrony", false, false},
		{"masked", "pbs_service_start", "postfix", "dead", "masked", "systemctl unmask", false, false},
		{"masked restart", "pbs_service_restart", "postfix", "running", "masked", "Service postfix is masked", false, false},
		{"masked reload", "pbs_service_reload", "postfix", "running", "masked", "refuses to start, restart or reload a masked unit", false, false},
		{"masked and stopped reload", "pbs_service_reload", "cron", "dead", "masked", "Service cron is masked", false, false},
		{"reload of a stopped service", "pbs_service_reload", "postfix", "dead", "enabled", "pbs_service_restart or pbs_service_start starts it", true, false},
		{"reload of a failed service", "pbs_service_reload", "sshd", "failed", "enabled", "systemd reports it as failed", true, false},
		{"start of a running service", "pbs_service_start", "sshd", "running", "enabled", "systemd reports service sshd on node localhost as running already; nothing to start", false, true},
		{"start of PBS's proxy", "pbs_service_start", "proxmox-backup-proxy", "running", "enabled", "nothing to start", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, services, _ := newServiceHarness(t)
			services.set(tc.service, tc.state, tc.unitState)
			got := h.invokeAction(t, tc.action, map[string]any{"service": tc.service})
			switch {
			case tc.progress:
				requireNoProtocolErrors(t, got.diagnostics)
				requireProgressContaining(t, got, tc.want)
			case tc.warning:
				requireNoProtocolErrors(t, got.diagnostics)
				requireProtocolWarningContaining(t, got.diagnostics, tc.want)
			default:
				requireProtocolErrorContaining(t, got.diagnostics, tc.want)
			}
			requireCommands(t, services)
		})
	}
}

// Without systemd — PBS in a Docker container — the state cannot be read,
// and the action says why before PBS runs a command that would fail.
func TestServiceActionsWithoutSystemd(t *testing.T) {
	h, _, services, _ := newServiceHarness(t)
	services.configure(func(s *fakeServices) { s.noSystemd = true })
	got := h.invokeAction(t, "pbs_service_restart", map[string]any{"service": "postfix"})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to read the state of service postfix on PBS node localhost")
	requireProtocolErrorContaining(t, got.diagnostics, "systemctl show failed with exit status: 1")
	requireProtocolErrorContaining(t, got.diagnostics, "such as PBS in a Docker container")

	services.configure(func(s *fakeServices) { s.noSystemd, s.nullState = false, true })
	got = h.invokeAction(t, "pbs_service_start", map[string]any{"service": "chrony"})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS answered no state")
	requireCommands(t, services)
}

// Without Sys.Audit on the service, the command runs unchecked.
func TestServiceActionsWithoutTheStatePrivilege(t *testing.T) {
	h, fake, services, _ := newServiceHarness(t)
	services.configure(func(s *fakeServices) { s.stateForbidden = true })
	got := h.invokeAction(t, "pbs_service_start", map[string]any{"service": "postfix"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "cannot read the state of service postfix (needs Sys.Audit on /system/services/postfix)")
	requireProgressContaining(t, got, "PBS started service postfix on node localhost")
	requireCommands(t, services, "start postfix")
	if n := fake.count("GET /nodes/localhost/services/postfix/state"); n != 1 {
		t.Fatalf("the state was read %d times: %v", n, fake.routes())
	}
}

func TestServiceActionsExplainAMissingPrivilege(t *testing.T) {
	h, _, services, _ := newServiceHarness(t)
	services.configure(func(s *fakeServices) { s.commandForbidden = true })
	got := h.invokeAction(t, "pbs_service_restart", map[string]any{"service": "postfix"})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to restart service postfix on PBS node localhost")
	requireProtocolErrorContaining(t, got.diagnostics, "Sys.Modify on /system/services/postfix")
	requireProtocolErrorContaining(t, got.diagnostics, "An API token has no privileges of its own")
}

// The proxy hands the command to the API daemon; when that is down, the
// proxy answers 400.
func TestServiceActionsWithoutTheAPIDaemon(t *testing.T) {
	h, fake, _, _ := newServiceHarness(t)
	fake.reply("POST /nodes/localhost/services/postfix/restart", http.StatusBadRequest, "client error (Connect)")
	got := h.invokeAction(t, "pbs_service_restart", map[string]any{"service": "postfix"})
	requireProtocolErrorContaining(t, got.diagnostics, "client error (Connect)")
	requireProtocolErrorContaining(t, got.diagnostics, "systemctl start proxmox-backup")
}

// A task that fails says where systemd's message is, and what an exit
// status says when it says something.
func TestServiceActionsReportAFailedTask(t *testing.T) {
	for _, tc := range []struct {
		exit string
		want []string
	}{
		{"systemctl restart failed with exit status: 1", []string{
			"PBS task UPID:pbs-tasks:", "journalctl -u proxmox-backup", "systemctl status", "The end of the task's log",
		}},
		{"systemctl restart failed with exit status: 5", []string{"systemd knows no unit for postfix", "cron and chrony"}},
		{"No such file or directory (os error 2)", []string{"PBS found no systemctl to run", "Docker container"}},
	} {
		t.Run(tc.exit, func(t *testing.T) {
			h, _, services, _ := newServiceHarness(t)
			services.configure(func(s *fakeServices) { s.exit = tc.exit })
			got := h.invokeAction(t, "pbs_service_restart", map[string]any{"service": "postfix"})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to restart service postfix on PBS node localhost")
			for _, want := range tc.want {
				requireProtocolErrorContaining(t, got.diagnostics, want)
			}
		})
	}
}

// A service that fails right after it started is reported once systemd
// says so.
func TestServiceActionsReportAServiceThatStops(t *testing.T) {
	h, _, services, _ := newServiceHarness(t)
	services.configure(func(s *fakeServices) { s.crashes = true })
	got := h.invokeAction(t, "pbs_service_restart", map[string]any{"service": "chrony"})
	requireProtocolErrorContaining(t, got.diagnostics, "Service chrony is not running on PBS node localhost after the restart")
	requireProtocolErrorContaining(t, got.diagnostics, "systemd reports the service as failed (unit state enabled)")
}

func TestServiceActionTimeout(t *testing.T) {
	h, _, services, _ := newServiceHarness(t)
	services.configure(func(s *fakeServices) { s.running = -1 })
	got := h.invokeAction(t, "pbs_service_restart", map[string]any{"service": "postfix", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "Restart of service postfix on PBS node localhost did not finish")
	requireProtocolErrorContaining(t, got.diagnostics, "Raise the action's `timeout`")
}

// --- proxmox-backup-proxy -------------------------------------------------------

// serviceTransport wraps the fake: once PBS was asked for a service
// command, the polls of tasks can fail as while the proxy starts its new
// process, for good as when it did not start, with a certificate the
// client does not trust, or with an error from PBS, as while the old API
// daemon hands over to the new one.
type serviceTransport struct {
	fake *fakePBS

	mu        sync.Mutex
	commanded bool
	failPolls int
	cutOff    bool
	apiErrors int
	untrusted error
	polls     int
}

func (s *serviceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/services/") {
		s.commanded = true
	}
	if s.commanded && req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/tasks/") &&
		strings.HasSuffix(req.URL.Path, "/status") {
		s.polls++
		refused := errors.New("dial tcp 192.0.2.10:8007: connect: connection refused")
		switch {
		case s.untrusted != nil:
			s.mu.Unlock()
			return nil, s.untrusted
		case s.cutOff:
			s.mu.Unlock()
			return nil, refused
		case s.failPolls > 0:
			s.failPolls--
			s.mu.Unlock()
			return nil, refused
		case s.apiErrors > 0:
			s.apiErrors--
			s.mu.Unlock()
			rec := httptest.NewRecorder()
			writeError(rec, "Connection refused (os error 111)")
			return rec.Result(), nil
		}
	}
	s.mu.Unlock()
	return s.fake.RoundTrip(req)
}

// newServiceTransportHarness is newServiceHarness through a
// serviceTransport.
func newServiceTransportHarness(t *testing.T, transport *serviceTransport) (*protocolHarness, *fakeServices, *fakeACME) {
	t.Helper()
	fastServiceSettle(t)
	transport.fake = newFakePBS()
	services := newFakeServices(transport.fake)
	acme := newFakeACME(t, transport.fake)
	return newProtocolHarness(t, transport.fake, withTransport(transport)), services, acme
}

// Without a TLS transport, the client cannot look at the certificate the
// proxy presents, and the action checks the chain only: PBS's own
// self-signed P-256 certificate meets level 2 and 3.
func TestServiceReloadActionChecksTheProxy(t *testing.T) {
	for _, tc := range []struct {
		action  string
		ciphers string
	}{
		{"pbs_service_reload", ""},
		{"pbs_service_restart", "ECDHE-ECDSA-AES256-GCM-SHA384:@SECLEVEL=3"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			h, fake, services, acme := newServiceHarness(t)
			if tc.ciphers != "" {
				acme.mu.Lock()
				acme.node["ciphers-tls-1.2"] = tc.ciphers
				acme.mu.Unlock()
			}
			got := h.invokeAction(t, tc.action, map[string]any{"service": "proxmox-backup-proxy"})
			requireNoProtocolErrors(t, got.diagnostics)
			requireCommands(t, services, "reload proxmox-backup-proxy")
			if fake.count("GET /nodes/localhost/certificates/info") != 1 || fake.count("GET /nodes/localhost/config") != 1 {
				t.Fatalf("routes: %v", fake.routes())
			}
			requireProgressContaining(t, got, "meets OpenSSL's security level")
			requireProgressContaining(t, got, ":srvreload:proxmox-backup-proxy:")
			requireProgressContaining(t, got, "waiting for it to answer again")
			requireProgressContaining(t, got, "PBS reloaded service proxmox-backup-proxy on node localhost; systemd reports it running; the old process finishes")
			if tc.action == "pbs_service_restart" {
				requireProgressContaining(t, got, "PBS reloads proxmox-backup-proxy rather than restarting it")
				requireProgressContaining(t, got, "security level 3 (@SECLEVEL=3 in ciphers_tls_1_2)")
				if fake.count("POST /nodes/localhost/services/proxmox-backup-proxy/restart") != 1 {
					t.Fatalf("routes: %v", fake.routes())
				}
			} else {
				requireProgressContaining(t, got, "security level 2 (Debian's default")
			}
		})
	}
}

// rsaCertificate makes a certificate for cn with an RSA key of bits, signed
// by parent: a public key is all a check of the chain needs, and making a
// large RSA key would take long.
func rsaCertificate(t *testing.T, cn string, bits int, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(1790000000, 0),
		NotAfter:     time.Unix(1790000000+90*24*3600, 0),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &rsa.PublicKey{N: n, E: 65537}, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A chain that falls short of the security level of the cipher lists keeps
// the reloaded proxy from starting: the action refuses, and skip_checks
// reloads anyway.
func TestServiceReloadActionRefusesAWeakChain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ciphers map[string]string
		chain   func(t *testing.T, acme *fakeACME) pbsclient.CertificateInfo
		want    []string
	}{{
		name:    "RSA-2048 at level 3",
		ciphers: map[string]string{"ciphers-tls-1.2": "HIGH:@SECLEVEL=3"},
		chain: func(t *testing.T, acme *fakeACME) pbsclient.CertificateInfo {
			return certificateInfo(rsaCertificate(t, "pbs.example.org", 2048, acme.ca, acme.caKey), acme.ca)
		},
		want: []string{"security level 3 (@SECLEVEL=3 in ciphers_tls_1_2)", "128 bits of security",
			"certificate 1 of the chain (CN=pbs.example.org) has a 2048-bit RSA key",
			"Lower or remove the security level (@SECLEVEL=3 in ciphers_tls_1_2 of pbs_node_config)"},
	}, {
		name:    "an RSA-2048 intermediate at level 3",
		ciphers: map[string]string{"ciphers-tls-1.2": "@SECLEVEL=1:HIGH:@SECLEVEL=3"},
		chain: func(t *testing.T, acme *fakeACME) pbsclient.CertificateInfo {
			_, leaf := fakeCertificate(t, "pbs.example.org", []string{"pbs.example.org"}, acme.ca, acme.caKey)
			return certificateInfo(leaf, rsaCertificate(t, "Weak Intermediate", 2048, acme.ca, acme.caKey))
		},
		want: []string{"certificate 2 of the chain (CN=Weak Intermediate) has a 2048-bit RSA key"},
	}, {
		// Lowering the level in ciphers_tls_1_3 does nothing, so the error
		// does not advise it.
		name:    "RSA-1024 at Debian's default",
		ciphers: map[string]string{"ciphers-tls-1.3": "TLS_AES_256_GCM_SHA384:@SECLEVEL=1"},
		chain: func(t *testing.T, acme *fakeACME) pbsclient.CertificateInfo {
			return certificateInfo(rsaCertificate(t, "pbs.example.org", 1024, acme.ca, acme.caKey), acme.ca)
		},
		want: []string{"security level 2 (Debian's default; ciphers_tls_1_2 of node.cfg sets none)",
			"has a 1024-bit RSA key", ". Install a certificate with stronger keys and signatures before reloading"},
	}, {
		// Nor does it advise lowering a level below Debian's further.
		name:    "RSA-512 at level 1",
		ciphers: map[string]string{"ciphers-tls-1.2": "HIGH:@SECLEVEL=1"},
		chain: func(t *testing.T, acme *fakeACME) pbsclient.CertificateInfo {
			return certificateInfo(rsaCertificate(t, "pbs.example.org", 512, acme.ca, acme.caKey), acme.ca)
		},
		want: []string{"security level 1 (@SECLEVEL=1 in ciphers_tls_1_2)", "has a 512-bit RSA key",
			". Install a certificate with stronger keys and signatures before reloading"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, services, acme := newServiceHarness(t)
			acme.mu.Lock()
			for key, value := range tc.ciphers {
				acme.node[key] = value
			}
			acme.cert = tc.chain(t, acme)
			acme.mu.Unlock()

			got := h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"})
			requireProtocolErrorContaining(t, got.diagnostics, "PBS's certificate is too weak for the proxy's security level")
			for _, want := range tc.want {
				requireProtocolErrorContaining(t, got.diagnostics, want)
			}
			requireProtocolErrorContaining(t, got.diagnostics, "`skip_checks = true` reloads anyway")
			requireCommands(t, services)

			got = h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy", "skip_checks": true})
			requireNoProtocolErrors(t, got.diagnostics)
			requireProgressContaining(t, got, "skip_checks = true")
			requireCommands(t, services, "reload proxmox-backup-proxy")
		})
	}
}

// The proxy loads its chain at the level ciphers_tls_1_2 sets, a level
// below Debian's included, and OpenSSL ignores one in ciphers_tls_1_3: the
// action checks the chain at that level, and reloads a chain that meets it.
func TestServiceReloadActionChecksAtTheLevelOfTheTLS12List(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ciphers map[string]string
		chain   func(t *testing.T, acme *fakeACME) pbsclient.CertificateInfo
		want    string
	}{{
		// The plan of pbs_node_config warns that this does nothing; PBS
		// stores it, as OpenSSL skips the name.
		name:    "P-256 with @SECLEVEL=4 in the TLS 1.3 list",
		ciphers: map[string]string{"ciphers-tls-1.3": "TLS_AES_256_GCM_SHA384:@SECLEVEL=4"},
		want:    "security level 2 (Debian's default; ciphers_tls_1_2 of node.cfg sets none)",
	}, {
		name: "P-256 at level 3, with @SECLEVEL=4 in the TLS 1.3 list",
		ciphers: map[string]string{
			"ciphers-tls-1.2": "HIGH:@SECLEVEL=3",
			"ciphers-tls-1.3": "TLS_AES_256_GCM_SHA384:@SECLEVEL=4",
		},
		want: "security level 3 (@SECLEVEL=3 in ciphers_tls_1_2)",
	}, {
		name:    "RSA-1024 at level 1",
		ciphers: map[string]string{"ciphers-tls-1.2": "@SECLEVEL=3:HIGH:@SECLEVEL=1"},
		chain: func(t *testing.T, acme *fakeACME) pbsclient.CertificateInfo {
			return certificateInfo(rsaCertificate(t, "pbs.example.org", 1024, acme.ca, acme.caKey), acme.ca)
		},
		want: "security level 1 (@SECLEVEL=1 in ciphers_tls_1_2)",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, services, acme := newServiceHarness(t)
			acme.mu.Lock()
			for key, value := range tc.ciphers {
				acme.node[key] = value
			}
			if tc.chain != nil {
				acme.cert = tc.chain(t, acme)
			}
			acme.mu.Unlock()

			got := h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"})
			requireNoProtocolErrors(t, got.diagnostics)
			requireProgressContaining(t, got, "the certificate chain of proxy.pem meets OpenSSL's "+tc.want)
			requireCommands(t, services, "reload proxmox-backup-proxy")
		})
	}
}

// A TLS 1.2 list OpenSSL refuses keeps the reloaded proxy from starting
// whatever the certificate: the action refuses without checking the chain,
// rather than checking PBS's P-256 certificate at level 5 or 2, and
// skip_checks reloads anyway. PBS refuses such a list through its API; it
// comes from an edit of node.cfg on the host.
func TestServiceReloadActionRefusesACipherListOpenSSLRefuses(t *testing.T) {
	for _, tc := range []struct {
		list, want string
	}{
		{"HIGH:@SECLEVEL=9", `OpenSSL refuses the command "@SECLEVEL=9"`},
		{"HIGH:@SECLEVEL=10", `"@SECLEVEL=10"`},
		{"HIGH:@seclevel=3", `"@seclevel=3"`},
		{"HIGH:!@SECLEVEL=3", `"!@SECLEVEL=3"`},
		{"HIGH:@SECLEVEL=3:!", `"!": the operator '!' must be followed by a cipher name`},
	} {
		t.Run(tc.list, func(t *testing.T) {
			h, _, services, acme := newServiceHarness(t)
			acme.mu.Lock()
			acme.node["ciphers-tls-1.2"] = tc.list
			acme.mu.Unlock()

			got := h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"})
			requireProtocolErrorContaining(t, got.diagnostics, "OpenSSL refuses PBS's cipher list for TLS 1.2")
			requireProtocolErrorContaining(t, got.diagnostics, tc.want)
			requireProtocolErrorContaining(t, got.diagnostics, "would not start whatever the certificate")
			requireProtocolErrorContaining(t, got.diagnostics, "`skip_checks = true` reloads anyway")
			for _, d := range got.diagnostics {
				if strings.Contains(d.Summary, "too weak") {
					t.Errorf("the action checked the chain: %s: %s", d.Summary, d.Detail)
				}
			}
			requireCommands(t, services)

			got = h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy", "skip_checks": true})
			requireNoProtocolErrors(t, got.diagnostics)
			requireCommands(t, services, "reload proxmox-backup-proxy")
		})
	}
}

// The level is the last @SECLEVEL of ciphers_tls_1_2, below Debian's too,
// or Debian's when that list sets none; ciphers_tls_1_3 never counts.
func TestProxySecurityLevel(t *testing.T) {
	for _, tc := range []struct {
		tls12, tls13 string
		level        int
		source       string
		err          string
	}{
		{tls12: "", tls13: "", level: 2, source: "Debian's default; ciphers_tls_1_2 of node.cfg sets none"},
		{tls12: "HIGH:!aNULL", tls13: "TLS_AES_256_GCM_SHA384", level: 2, source: "Debian's default"},
		{tls12: "", tls13: "TLS_AES_256_GCM_SHA384:@SECLEVEL=4", level: 2, source: "Debian's default"},
		{tls12: "HIGH:@SECLEVEL=1", level: 1, source: "@SECLEVEL=1 in ciphers_tls_1_2"},
		{tls12: "HIGH:@SECLEVEL=0", level: 0, source: "@SECLEVEL=0 in ciphers_tls_1_2"},
		{tls12: "@SECLEVEL=4:HIGH:@SECLEVEL=3", level: 3, source: "@SECLEVEL=3 in ciphers_tls_1_2"},
		{tls12: "HIGH:@SECLEVEL=3", tls13: "TLS_AES_256_GCM_SHA384:@SECLEVEL=4", level: 3, source: "@SECLEVEL=3 in ciphers_tls_1_2"},
		{tls12: "HIGH:@SECLEVEL=99999999999999999999", err: `"@SECLEVEL=99999999999999999999"`},
		{tls12: "HIGH:@SECLEVEL=03", tls13: "TLS_AES_256_GCM_SHA384:@SECLEVEL=4", err: `"@SECLEVEL=03"`},
	} {
		level, command, err := proxySecurityLevel(pbsclient.NodeSettings{CiphersTLS12: tc.tls12, CiphersTLS13: tc.tls13})
		switch {
		case tc.err != "":
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q, %q: level %d (%s), %v; want an error with %s", tc.tls12, tc.tls13, level, command, err, tc.err)
			}
		case err != nil || level != tc.level || !strings.Contains(securityLevelSource(command), tc.source):
			t.Errorf("%q, %q: level %d (%s), %v; want %d (%s)", tc.tls12, tc.tls13, level, securityLevelSource(command), err,
				tc.level, tc.source)
		}
	}
}

// The checks need privileges of their own; without them the action
// refuses, and says what to grant or set.
func TestServiceReloadActionCannotCheckTheProxy(t *testing.T) {
	for _, tc := range []struct {
		route, want string
	}{
		{"GET /nodes/localhost/certificates/info", certificatesPrivilege},
		{"GET /nodes/localhost/config", nodeConfigReadPrivilege},
	} {
		t.Run(tc.route, func(t *testing.T) {
			h, fake, services, _ := newServiceHarness(t)
			fake.reply(tc.route, http.StatusForbidden, "permission check failed")
			got := h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"})
			requireProtocolErrorContaining(t, got.diagnostics, "Unable to check PBS's proxy before reloading it")
			requireProtocolErrorContaining(t, got.diagnostics, tc.want)
			requireProtocolErrorContaining(t, got.diagnostics, "Grant the privilege, or set `skip_checks = true`")
			requireCommands(t, services)

			// skip_checks reads nothing.
			before := fake.count(tc.route)
			got = h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy", "skip_checks": true})
			requireNoProtocolErrors(t, got.diagnostics)
			requireCommands(t, services, "reload proxmox-backup-proxy")
			if fake.count(tc.route) != before {
				t.Fatalf("skip_checks read %s: %v", tc.route, fake.routes())
			}
		})
	}
}

// Over TLS, the action looks at the certificate the proxy presents: when it
// is not that of proxy.pem, the proxy failed to load the file, and would not
// start after a reload.
func TestServiceReloadActionComparesThePresentedCertificate(t *testing.T) {
	fastServiceSettle(t)
	fake := newFakePBS()
	services := newFakeServices(fake)
	acme := newFakeACME(t, fake)
	readyForACME(acme)
	servedKey, served := fakeCertificate(t, "pbs.example.org", []string{"pbs.example.org"}, acme.ca, acme.caKey)
	_, written := fakeCertificate(t, "pbs.example.org", []string{"pbs.example.org"}, acme.ca, acme.caKey)
	acme.mu.Lock()
	acme.cert = certificateInfo(served, acme.ca)
	acme.mu.Unlock()
	proxy := serveRenewProxy(t, fake)
	proxy.present(servedKey, served, acme.ca)
	h := newProtocolHarness(t, fake, withTransport(proxy.transport()))

	// The proxy presents the certificate of proxy.pem.
	handshakes := proxy.handshakes.Load()
	got := h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireCommands(t, services, "reload proxmox-backup-proxy")
	if proxy.handshakes.Load() == handshakes {
		t.Fatal("nothing looked at the certificate the proxy presents")
	}

	// proxy.pem holds another certificate, which the proxy did not load.
	acme.mu.Lock()
	acme.cert = certificateInfo(written, acme.ca)
	acme.mu.Unlock()
	got = h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS's proxy presents another certificate than its certificate file")
	requireProtocolErrorContaining(t, got.diagnostics, pbsclient.FormatFingerprint(pbsclient.CertificateFingerprint(served)))
	requireProtocolErrorContaining(t, got.diagnostics, acme.cert.Fingerprint)
	requireProtocolErrorContaining(t, got.diagnostics, "error reloading certificate")
	requireProtocolErrorContaining(t, got.diagnostics, "skip_certificate_match = true")
	got = h.invokeAction(t, "pbs_service_restart", map[string]any{"service": "proxmox-backup-proxy"})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS's proxy presents another certificate than its certificate file")
	requireCommands(t, services, "reload proxmox-backup-proxy")

	// Behind a TLS front end, the provider never sees PBS's certificate:
	// skip_certificate_match reloads, and still checks the chain.
	got = h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy", "skip_certificate_match": true})
	requireNoProtocolErrors(t, got.diagnostics)
	requireProgressContaining(t, got, "skip_certificate_match = true")
	requireProgressContaining(t, got, "meets OpenSSL's security level 2")
	requireCommands(t, services, "reload proxmox-backup-proxy", "reload proxmox-backup-proxy")
}

// A proxy that stops answering for a moment is waited for.
func TestServiceReloadActionWaitsForTheProxy(t *testing.T) {
	transport := &serviceTransport{failPolls: 2}
	h, services, _ := newServiceTransportHarness(t, transport)
	got := h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireCommands(t, services, "reload proxmox-backup-proxy")
}

// A proxy that does not answer again failed to start.
func TestServiceReloadActionProxyDoesNotComeBack(t *testing.T) {
	transport := &serviceTransport{cutOff: true}
	h, _, _ := newServiceTransportHarness(t, transport)
	got := h.invokeAction(t, "pbs_service_restart", map[string]any{"service": "proxmox-backup-proxy", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS's proxy did not come back")
	requireProtocolErrorContaining(t, got.diagnostics, "systemctl status proxmox-backup-proxy")
	requireProtocolErrorContaining(t, got.diagnostics, "journalctl -u proxmox-backup-proxy")
	requireProtocolErrorContaining(t, got.diagnostics, "connection refused")
}

// A proxy that presents a certificate the client does not trust after the
// reload has loaded the one in proxy.pem.
func TestServiceReloadActionProxyPresentsAnUntrustedCertificate(t *testing.T) {
	presented := strings.Repeat("ab", 32)
	transport := &serviceTransport{untrusted: &pbsclient.UntrustedCertificateError{
		Fingerprints: []string{presented}, Pinned: strings.Repeat("cd", 32),
	}}
	h, _, _ := newServiceTransportHarness(t, transport)
	got := h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy", "timeout": "1s"})
	requireProtocolErrorContaining(t, got.diagnostics, "PBS's proxy presents a certificate the provider does not trust")
	requireProtocolErrorContaining(t, got.diagnostics, pbsclient.FormatFingerprint(presented))
	requireProtocolErrorContaining(t, got.diagnostics, "tls_cert_fingerprint")
}

// While the old API daemon hands over to the new one, the proxy cannot
// tell how the reload's task stands for a moment: the action polls again.
// Other services get no such grace.
func TestServiceReloadActionWaitsForTheAPIDaemon(t *testing.T) {
	transport := &serviceTransport{apiErrors: 3}
	h, services, _ := newServiceTransportHarness(t, transport)
	got := h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup"})
	requireNoProtocolErrors(t, got.diagnostics)
	requireCommands(t, services, "reload proxmox-backup")

	transport.mu.Lock()
	transport.commanded, transport.apiErrors, transport.polls = false, 1000, 0
	transport.mu.Unlock()
	got = h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup"})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to follow PBS task")
	requireProtocolErrorContaining(t, got.diagnostics, "Connection refused (os error 111)")

	transport.mu.Lock()
	transport.commanded, transport.apiErrors, transport.polls = false, 1000, 0
	transport.mu.Unlock()
	got = h.invokeAction(t, "pbs_service_reload", map[string]any{"service": "postfix"})
	requireProtocolErrorContaining(t, got.diagnostics, "Unable to follow PBS task")
	transport.mu.Lock()
	polls := transport.polls
	transport.mu.Unlock()
	if polls != 1 {
		t.Fatalf("the status of postfix's reload was polled %d times", polls)
	}
}

// When Terraform stops the action, it stops waiting at once, and lets go of
// the lock of node.cfg and of the certificate.
func TestServiceReloadActionCancelled(t *testing.T) {
	h, _, services, _ := newServiceHarness(t)
	services.configure(func(s *fakeServices) { s.running = -1 })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	h.invokeActionWith(ctx, t, "pbs_service_reload", h.actionValue(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"}))
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the action went on for %s after it was cancelled", elapsed)
	}
	// A second invocation would wait for good if the first held on to a
	// lock.
	services.configure(func(s *fakeServices) { s.running = 0 })
	done := make(chan actionInvocation)
	go func() {
		done <- h.invokeActionWith(context.Background(), t, "pbs_service_reload",
			h.actionValue(t, "pbs_service_reload", map[string]any{"service": "proxmox-backup-proxy"}))
	}()
	select {
	case got := <-done:
		requireNoProtocolErrors(t, got.diagnostics)
	case <-time.After(10 * time.Second):
		t.Fatal("a lock of the proxy's reload is still held")
	}
}
