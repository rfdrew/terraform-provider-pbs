package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of the node's settings. They change the stand itself —
// node.cfg, /etc/resolv.conf, the time zone, the certificate — which the
// other tests share, so each records what it changes before it starts and
// puts it back when it ends, failed or not.

// envAccDNSWritable is set when PBS can write /etc/resolv.conf on the stand:
// scripts/bootstrap-test-pbs.sh unmounts the file Docker mounts there.
const envAccDNSWritable = "PBS_ACC_DNS_WRITABLE"

// testAccNodeClient skips a test that talks to the stand before acc.Test
// does, without TF_ACC, and returns a client of the stand.
func testAccNodeClient(t *testing.T) *pbsclient.Client {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	testAccPreCheck(t)
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// testAccRestoreNodeSettings puts the node's settings — not its ACME
// settings — back as they are now when the test ends.
func testAccRestoreNodeSettings(t *testing.T, client *pbsclient.Client) {
	t.Helper()
	ctx := context.Background()
	node := client.Node()
	before, _, err := client.GetNodeSettings(ctx, node)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		after, digest, err := client.GetNodeSettings(ctx, node)
		if err == nil {
			params := url.Values{}
			var deletes []string
			for _, s := range nodeSettings {
				was, is := s.pbs(before), s.pbs(after)
				switch was {
				case is:
				case "":
					deletes = append(deletes, s.property)
				default:
					params.Set(s.property, was)
				}
			}
			pbsclient.AddDelete(params, deletes...)
			if len(params) > 0 {
				params.Set(pbsclient.DigestParam, digest)
				err = client.UpdateNodeConfig(ctx, node, params)
			}
		}
		if err != nil {
			t.Errorf("putting the node's settings back: %v", err)
		}
	})
}

func TestAccNodeConfig(t *testing.T) {
	client := testAccNodeClient(t)
	testAccRestoreNodeSettings(t, client)
	const resourceName = "pbs_node_config.this"
	location := ""
	if testAccVersionAtLeast(4, 2, 1) {
		location = `location = { name = "Vienna", latitude = 48.2, longitude = 16.37 }`
	}
	consent := "Authorised use **only**.\nEverything is logged."
	config := func(managed string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_node_config" "this" {
  description     = "Acceptance tests\n\nof terraform-provider-pbs"
  consent_text    = %q
  default_lang    = "de"
  ciphers_tls_1_2 = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
  %s
  %s
}
`, consent, location, managed)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNodeSettings(func(s pbsclient.NodeSettings) bool { return s.Description == "" && s.DefaultLang == "" }),
		Steps: []acc.TestStep{
			{
				Config: config(`email_from = "tfacc@pbs.test"
  task_log_max_days = 30`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", pbsclient.DefaultNode),
					acc.TestCheckResourceAttr(resourceName, "email_from", "tfacc@pbs.test"),
					acc.TestCheckResourceAttr(resourceName, "consent_text", consent),
					testAccCheckNodeSettings(func(s pbsclient.NodeSettings) bool {
						decoded, _ := base64.StdEncoding.DecodeString(s.ConsentText)
						return s.EmailFrom == "tfacc@pbs.test" && s.TaskLogMaxDays != nil && *s.TaskLogMaxDays == 30 &&
							s.Description == "Acceptance tests\n\nof terraform-provider-pbs\n" && string(decoded) == consent &&
							(location == "" || s.Location == "name=Vienna,latitude=48.2,longitude=16.37")
					}),
				),
			},
			{
				// Removing settings deletes them.
				Config: config(`task_log_max_days = 7`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "email_from"),
					testAccCheckNodeSettings(func(s pbsclient.NodeSettings) bool {
						return s.EmailFrom == "" && s.TaskLogMaxDays != nil && *s.TaskLogMaxDays == 7
					}),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     pbsclient.DefaultNode,
				ImportStateVerify: true,
				// PBS reads the notes back with a line break at the end.
				ImportStateVerifyIgnore: []string{"description"},
			},
		},
	})
}

// testAccCheckNodeSettings checks the node's settings in PBS.
func testAccCheckNodeSettings(check func(pbsclient.NodeSettings) bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		settings, _, err := client.GetNodeSettings(context.Background(), client.Node())
		if err != nil {
			return err
		}
		if !check(settings) {
			return fmt.Errorf("the node's settings are %+v", settings)
		}
		return nil
	}
}

func TestAccDNS(t *testing.T) {
	client := testAccNodeClient(t)
	if os.Getenv(envAccDNSWritable) != "1" {
		t.Skip(envAccDNSWritable + " is not set: PBS cannot write /etc/resolv.conf on this stand")
	}
	ctx := context.Background()
	before, err := client.GetDNS(ctx, client.Node())
	if err != nil {
		t.Fatal(err)
	}
	if before.DNS1 == "" {
		t.Skip("the stand has no nameserver to keep")
	}
	t.Cleanup(func() {
		after, err := client.GetDNS(ctx, client.Node())
		if err == nil {
			params := url.Values{pbsclient.DigestParam: {after.Digest}}
			if before.Search != "" {
				params.Set("search", before.Search)
			}
			var deletes []string
			for i, server := range before.Nameservers() {
				if server != "" {
					params.Set(fmt.Sprintf("dns%d", i+1), server)
				} else if after.Nameservers()[i] != "" {
					deletes = append(deletes, fmt.Sprintf("dns%d", i+1))
				}
			}
			pbsclient.AddDelete(params, deletes...)
			err = client.UpdateDNS(ctx, client.Node(), params)
		}
		if err != nil {
			t.Errorf("putting the DNS settings back: %v", err)
		}
	})
	const resourceName = "pbs_dns.this"
	// The stand's own nameserver stays first, so that it still resolves
	// names; the second is from a documentation range. PBS cannot remove a
	// search domain, so one is set only where the stand has one to put
	// back; elsewhere the configuration leaves it out, which leaves it
	// alone.
	search, searchLine := before.Search, ""
	if before.Search != "" {
		search, searchLine = "tfacc.example", `search = "tfacc.example"`
	}
	config := func(extra string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_dns" "this" {
  %s
  dns1 = %q
  %s
}
`, searchLine, before.DNS1, extra)
	}
	nameservers := func(want ...string) acc.TestCheckFunc {
		return func(*terraform.State) error {
			dns, err := client.GetDNS(ctx, client.Node())
			if err != nil {
				return err
			}
			servers := dns.Nameservers()
			got := strings.Join(strings.Fields(strings.Join(servers[:], " ")), ",")
			if dns.Search != search || got != strings.Join(want, ",") {
				return fmt.Errorf("search %q, nameservers %s, want %v", dns.Search, got, want)
			}
			return nil
		}
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// Destroying leaves the settings.
		CheckDestroy: nameservers(before.DNS1),
		Steps: []acc.TestStep{
			{
				Config: config(`dns2 = "192.0.2.53"`),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "dns2", "192.0.2.53"),
					nameservers(before.DNS1, "192.0.2.53"),
				),
			},
			{
				Config: config(""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(resourceName, "dns2"),
					nameservers(before.DNS1),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     pbsclient.DefaultNode,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccTimezone(t *testing.T) {
	client := testAccNodeClient(t)
	ctx := context.Background()
	before, err := client.GetTime(ctx, client.Node())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.SetTimezone(ctx, client.Node(), before.Timezone); err != nil {
			t.Errorf("putting the time zone back: %v", err)
		}
	})
	const resourceName = "pbs_timezone.this"
	config := func(timezone string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_timezone" "this" {
  timezone = %q
}

data "pbs_time" "this" {
  depends_on = [pbs_timezone.this]
}
`, timezone)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// Destroying leaves the zone.
		CheckDestroy: func(*terraform.State) error {
			now, err := client.GetTime(ctx, client.Node())
			if err == nil && now.Timezone != "America/New_York" {
				err = fmt.Errorf("the zone is %s after destroying", now.Timezone)
			}
			return err
		},
		Steps: []acc.TestStep{
			{
				Config: config("Europe/Vienna"),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", pbsclient.DefaultNode),
					acc.TestCheckResourceAttr("data.pbs_time.this", "timezone", "Europe/Vienna"),
					acc.TestMatchResourceAttr("data.pbs_time.this", "utc_offset", regexp.MustCompile(`^(3600|7200)$`)),
					acc.TestMatchResourceAttr("data.pbs_time.this", "local_time", regexp.MustCompile(`\+0[12]:00$`)),
					acc.TestMatchResourceAttr("data.pbs_time.this", "time", regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)),
				),
			},
			{
				Config: config("America/New_York"),
				Check:  acc.TestMatchResourceAttr("data.pbs_time.this", "utc_offset", regexp.MustCompile(`^-(14400|18000)$`)),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     pbsclient.DefaultNode,
				ImportStateVerify: true,
			},
			{
				Config:      config("Mars/Olympus_Mons"),
				ExpectError: regexp.MustCompile(`no time zone "Mars/Olympus_Mons"`),
			},
		},
	})
}

// Setting a key needs Proxmox's shop. The stand reaches the internet, but
// the test has no key and must not depend on the shop, so PBS is pointed at
// an HTTP proxy that refuses connections: the failure path, with nothing
// written. The data source reads the node without a subscription.
func TestAccSubscription(t *testing.T) {
	client := testAccNodeClient(t)
	ctx := context.Background()
	current, err := client.GetSubscription(ctx, client.Node())
	if err != nil {
		// PBS before 4.2.1 makes the server ID from the SSH host key, which
		// a container may not have.
		t.Skipf("the stand cannot report its subscription: %v", err)
	}
	if current.Status != pbsclient.SubscriptionNotFound {
		t.Skipf("the stand has a subscription (%s)", current.Status)
	}
	testAccRestoreNodeSettings(t, client)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckNodeSettings(func(s pbsclient.NodeSettings) bool { return s.HTTPProxy == "" }),
			func(*terraform.State) error {
				s, err := client.GetSubscription(ctx, client.Node())
				if err == nil && s.Status != pbsclient.SubscriptionNotFound {
					err = fmt.Errorf("the node has a subscription: %+v", s)
				}
				return err
			},
		),
		Steps: []acc.TestStep{
			{
				Config: providerConfig + `
data "pbs_subscription" "this" {}
`,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("data.pbs_subscription.this", "status", "notfound"),
					acc.TestCheckNoResourceAttr("data.pbs_subscription.this", "key"),
					acc.TestMatchResourceAttr("data.pbs_subscription.this", "server_id", regexp.MustCompile(`^[0-9A-F]{32}$`)),
					acc.TestCheckResourceAttrSet("data.pbs_subscription.this", "url"),
				),
			},
			{
				Config: providerConfig + `
resource "pbs_subscription" "this" {
  key = "pbsc-0123"
}
`,
				ExpectError: regexp.MustCompile(`must be a PBS subscription key`),
			},
			{
				Config: providerConfig + `
resource "pbs_node_config" "proxy" {
  http_proxy = "http://127.0.0.1:1"
}

resource "pbs_subscription" "this" {
  key        = "pbsc-0123456789"
  depends_on = [pbs_node_config.proxy]
}
`,
				ExpectError: regexp.MustCompile(`could not reach it`),
			},
		},
	})
}

// testAccCustomCertificate makes a certificate for the stand, valid for
// localhost and 127.0.0.1, signed by a CA of its own: the chain, the key and
// the certificate's fingerprint as PBS shows it.
func testAccCustomCertificate(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate) (chain, key, fingerprint string) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"tfacc"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf(leaf) + pemOf(ca), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		pbsclient.FormatFingerprint(pbsclient.CertificateFingerprint(leaf))
}

// Uploading a certificate changes the one PBS_TLS_FINGERPRINT pins, which
// every terraform command of a step reads anew. The steps that upload run
// with certificate verification off; between them, a step pinned to the
// uploaded certificate's fingerprint shows that PBS serves it. The stand's
// own certificate goes back when the test ends.
func TestAccNodeCertificateCustom(t *testing.T) {
	testAccNodeClient(t)
	certFile, keyFile := os.Getenv(envAccProxyCertFile), os.Getenv(envAccProxyKeyFile)
	if certFile == "" || keyFile == "" {
		t.Skip(envAccProxyCertFile + " and " + envAccProxyKeyFile + " are not set: the stand's certificate could not be put back")
	}
	t.Cleanup(func() {
		if err := testAccRestoreCertificate(certFile, keyFile); err != nil {
			t.Errorf("putting PBS's certificate back: %v", err)
		}
	})
	insecure := func() {
		t.Setenv(envCertFingerprint, "")
		t.Setenv(envCAFile, "")
		t.Setenv(envInsecureSkipVerify, "true")
	}
	insecure()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tfacc CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tfacc CA"}}, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	firstChain, firstKey, first := testAccCustomCertificate(t, caKey, ca)
	secondChain, secondKey, second := testAccCustomCertificate(t, caKey, ca)
	const resourceName = "pbs_node_certificate.this"
	config := func(chain, key string, version int) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_node_certificate" "this" {
  source         = "custom"
  certificates   = %q
  key_wo         = %q
  key_wo_version = %d
}
`, chain, key, version)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		CheckDestroy:             testAccCheckSelfSigned,
		Steps: []acc.TestStep{
			{
				Config: config(firstChain, firstKey, 1),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "fingerprint", first),
					acc.TestCheckResourceAttr(resourceName, "source", "custom"),
					acc.TestMatchResourceAttr(resourceName, "issuer", regexp.MustCompile("tfacc CA")),
					acc.TestCheckResourceAttr(resourceName, "san.0", "localhost"),
				),
			},
			{
				// A run pinned to the uploaded certificate connects: PBS
				// serves it.
				PreConfig: func() {
					t.Setenv(envCertFingerprint, first)
					t.Setenv(envInsecureSkipVerify, "")
				},
				Config:   config(firstChain, firstKey, 1),
				PlanOnly: true,
			},
			{
				PreConfig: insecure,
				Config:    config(secondChain, secondKey, 2),
				Check:     acc.TestCheckResourceAttr(resourceName, "fingerprint", second),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateId:           pbsclient.DefaultNode,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"source", "certificates", "key_wo_version"},
			},
		},
	})
}

// From Terraform 1.12, the node's settings import by identity too.
func TestAccNodeSettingsImportByIdentity(t *testing.T) {
	client := testAccNodeClient(t)
	testAccRestoreNodeSettings(t, client)
	ctx := context.Background()
	before, err := client.GetTime(ctx, client.Node())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.SetTimezone(ctx, client.Node(), before.Timezone); err != nil {
			t.Errorf("putting the time zone back: %v", err)
		}
	})
	config := providerConfig + `
resource "pbs_node_config" "this" {
  email_from = "tfacc@pbs.test"
}

resource "pbs_timezone" "this" {
  timezone = "Europe/Vienna"
}
`
	steps := []acc.TestStep{{Config: config}}
	for _, name := range []string{"pbs_node_config.this", "pbs_timezone.this"} {
		steps = append(steps,
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		)
	}
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		Steps:                    steps,
	})
}
