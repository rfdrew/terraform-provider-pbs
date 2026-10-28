package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// Acceptance tests of the ACME resources, against Pebble, Let's Encrypt's
// test CA, which scripts/bootstrap-test-pbs.sh starts next to PBS and which
// validates every challenge without looking. The Cloudflare plugin is only
// created, changed and deleted: its token is not real.
//
// Ordering a certificate changes the one PBS_TLS_FINGERPRINT pins, so the
// tests that order put PBS's own certificate back when they end, from the
// files the bootstrap script saved, and the test of the Terraform resources
// runs with certificate verification off: every terraform command of a
// step configures the provider anew, from the environment, and the
// fingerprint there names the old certificate. The test of the client trusts
// the new certificate the way the provider does within one run.

// The facts scripts/bootstrap-test-pbs.sh exports for these tests.
const (
	// envAccACMEDirectory is Pebble's ACME directory, as PBS reaches it.
	envAccACMEDirectory = "PBS_ACC_ACME_DIRECTORY"
	// envAccProxyCertFile and envAccProxyKeyFile are PBS's own certificate
	// and key, as the stand started.
	envAccProxyCertFile = "PBS_ACC_PROXY_CERT_FILE"
	envAccProxyKeyFile  = "PBS_ACC_PROXY_KEY_FILE"
)

// pebbleToS is the terms of service Pebble's directory advertises.
const pebbleToS = "data:text/plain,Do%20what%20thou%20wilt"

// testAccACMEDirectory returns Pebble's directory, or skips the test.
func testAccACMEDirectory(t *testing.T) string {
	t.Helper()
	directory := os.Getenv(envAccACMEDirectory)
	if directory == "" && os.Getenv("TF_ACC") != "" {
		t.Skip(envAccACMEDirectory + " is not set: the stand runs no ACME CA")
	}
	return directory
}

// testAccACMEName returns a fresh name for an account or plugin.
func testAccACMEName() string {
	return "tfacc-" + testAccRandom(8)
}

// testAccACMEDomain returns a fresh domain under a name Pebble accepts.
func testAccACMEDomain(label string) string {
	return label + "-" + testAccRandom(6) + ".pebble.test"
}

// testAccCheckACMEDestroyed checks that the accounts and plugins are gone
// and that the node has no ACME settings left.
func testAccCheckACMEDestroyed(accounts, plugins []string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccInsecureClient()
		if err != nil {
			return err
		}
		ctx := context.Background()
		for _, name := range accounts {
			if _, err := client.GetACMEAccount(ctx, name); err == nil {
				return fmt.Errorf("ACME account %s still exists", name)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		for _, id := range plugins {
			if _, _, err := client.GetACMEPlugin(ctx, id); err == nil {
				return fmt.Errorf("ACME plugin %s still exists", id)
			} else if !pbsclient.IsNotFound(err) {
				return err
			}
		}
		config, _, err := client.GetNodeConfig(ctx, pbsclient.DefaultNode)
		if err != nil {
			return err
		}
		if config.ACME != "" || config.ACMEDomains != [pbsclient.MaxACMEDomains]string{} {
			return fmt.Errorf("the node keeps ACME settings: %+v", config)
		}
		return nil
	}
}

// testAccInsecureClient connects to the stand without verifying its
// certificate, which a certificate test may have changed.
func testAccInsecureClient() (*pbsclient.Client, error) {
	return pbsclient.New(pbsclient.Options{
		Endpoint:           os.Getenv(envEndpoint),
		APIToken:           os.Getenv(envAPIToken),
		InsecureSkipVerify: true,
	})
}

// testAccOrdersCertificates skips a test that orders certificates when the
// stand runs no ACME CA or cannot put its certificate back, and puts the
// certificate back when the test ends, failed or not, so that
// PBS_TLS_FINGERPRINT holds for the tests after it.
func testAccOrdersCertificates(t *testing.T) string {
	t.Helper()
	directory := testAccACMEDirectory(t)
	if os.Getenv("TF_ACC") == "" {
		return directory
	}
	certFile, keyFile := os.Getenv(envAccProxyCertFile), os.Getenv(envAccProxyKeyFile)
	if certFile == "" || keyFile == "" {
		t.Skip(envAccProxyCertFile + " and " + envAccProxyKeyFile + " are not set: the stand's certificate could not be put back")
	}
	t.Cleanup(func() {
		if err := testAccRestoreCertificate(certFile, keyFile); err != nil {
			t.Errorf("putting PBS's certificate back: %v", err)
		}
	})
	return directory
}

// testAccRestoreCertificate uploads PBS's own certificate and key, and checks
// that the provider's settings trust the server again.
func testAccRestoreCertificate(certFile, keyFile string) error {
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	client, err := testAccInsecureClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if _, err := client.Post(ctx, client.NodePath("certificates", "custom"),
		url.Values{"certificates": {string(cert)}, "key": {string(key)}, "force": {"true"}}, nil); err != nil {
		return err
	}
	pinned, err := testAccClient()
	if err != nil {
		return err
	}
	_, err = pinned.ServerVersion(ctx)
	return err
}

func TestAccACMEAccount(t *testing.T) {
	directory := testAccACMEDirectory(t)
	name := testAccACMEName()
	const resourceName = "pbs_acme_account.test"
	config := func(contact string) string {
		return providerConfig + fmt.Sprintf(`
data "pbs_acme_tos" "pebble" {
  directory = %q
}

resource "pbs_acme_account" "test" {
  name      = %q
  contact   = %q
  directory = data.pbs_acme_tos.pebble.directory
  tos_url   = data.pbs_acme_tos.pebble.url
}
`, directory, name, contact)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckACMEDestroyed([]string{name}, nil),
		Steps: []acc.TestStep{
			{
				Config: config("tfacc@pbs.test"),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("data.pbs_acme_tos.pebble", "url", pebbleToS),
					acc.TestCheckResourceAttr(resourceName, "id", name),
					acc.TestCheckResourceAttr(resourceName, "status", "valid"),
					acc.TestCheckResourceAttr(resourceName, "tos_url", pebbleToS),
					acc.TestCheckResourceAttrSet(resourceName, "location"),
				),
			},
			{
				// Pebble returns contacts and takes changes, unlike Let's
				// Encrypt.
				Config: config("tfacc@pbs.test,tfacc-2@pbs.test"),
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckACMEAccountContacts(name, "tfacc@pbs.test", "tfacc-2@pbs.test"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// testAccCheckACMEAccountContacts checks the contacts PBS recorded from the
// CA.
func testAccCheckACMEAccountContacts(name string, want ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		account, err := client.GetACMEAccount(context.Background(), name)
		if err != nil {
			return err
		}
		if !sameContacts(account.Emails(), want) {
			return fmt.Errorf("the CA has the contacts %v, want %v", account.Emails(), want)
		}
		return nil
	}
}

func TestAccACMEPlugins(t *testing.T) {
	testAccACMEDirectory(t)
	id := testAccACMEName()
	const resourceName = "pbs_acme_plugin.cloudflare"
	config := func(token string, delay int) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_acme_plugin" "cloudflare" {
  id               = %q
  api              = "cf"
  validation_delay = %d
  data = {
    CF_Token   = %q
    CF_Zone_ID = "0123456789abcdef0123456789abcdef"
  }
}

import {
  to = pbs_acme_plugin.standalone
  id = "standalone"
}

resource "pbs_acme_plugin" "standalone" {
  id = "standalone"
}
`, id, delay, token)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckACMEDestroyed(nil, []string{id}),
		Steps: []acc.TestStep{
			{
				Config: config("not-a-real-token", 30),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "type", "dns"),
					acc.TestCheckResourceAttr(resourceName, "data.CF_Token", "not-a-real-token"),
					acc.TestCheckResourceAttr(resourceName, "validation_delay", "30"),
					acc.TestCheckResourceAttr(resourceName, "disable", "false"),
					acc.TestCheckResourceAttr("pbs_acme_plugin.standalone", "type", "standalone"),
					acc.TestCheckNoResourceAttr("pbs_acme_plugin.standalone", "api"),
				),
			},
			{
				Config: config("another-token", 120),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "data.CF_Token", "another-token"),
					acc.TestCheckResourceAttr(resourceName, "validation_delay", "120"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccNodeACME(t *testing.T) {
	directory := testAccACMEDirectory(t)
	account, plugin := testAccACMEName(), testAccACMEName()
	first, second := testAccACMEDomain("pbs"), testAccACMEDomain("backup")
	const resourceName = "pbs_node_acme.this"
	base := providerConfig + fmt.Sprintf(`
resource "pbs_acme_account" "test" {
  name      = %q
  contact   = "tfacc@pbs.test"
  directory = %q
  tos_url   = %q
}

resource "pbs_acme_plugin" "cloudflare" {
  id   = %q
  api  = "cf"
  data = { CF_Token = "not-a-real-token" }
}
`, account, directory, pebbleToS, plugin)
	config := func(domains string) string {
		return base + fmt.Sprintf(`
resource "pbs_node_acme" "this" {
  account = pbs_acme_account.test.name
  domains = [%s]
}
`, domains)
	}
	firstDomain := fmt.Sprintf(`{ domain = %q }`, first)
	secondDomain := fmt.Sprintf(`{ domain = %q, plugin = pbs_acme_plugin.cloudflare.id, alias = "validation.pebble.test" }`, second)
	slots := map[string]int{}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckACMEDestroyed([]string{account}, []string{plugin}),
		Steps: []acc.TestStep{
			{
				Config: config(firstDomain + ", " + secondDomain),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", pbsclient.DefaultNode),
					acc.TestCheckResourceAttr(resourceName, "node", pbsclient.DefaultNode),
					acc.TestCheckResourceAttr(resourceName, "account", account),
					acc.TestCheckResourceAttr(resourceName, "domains.#", "2"),
					acc.TestCheckTypeSetElemNestedAttrs(resourceName, "domains.*", map[string]string{"domain": second, "plugin": plugin}),
					testAccCheckACMESlots(slots, true),
				),
			},
			{
				// The same domains in another order plan nothing.
				Config:   config(secondDomain + ", " + firstDomain),
				PlanOnly: true,
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     pbsclient.DefaultNode,
				ImportStateVerify: true,
			},
			{
				// One domain stays, in its slot; the other's slot is emptied.
				Config: config(firstDomain),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "domains.#", "1"),
					testAccCheckACMESlots(slots, false),
				),
			},
		},
	})
}

// testAccCheckACMESlots records which slot holds each of the node's ACME
// domains, or, with record false, checks that every domain still there is in
// the slot recorded, and that no other slot holds one.
func testAccCheckACMESlots(slots map[string]int, record bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		config, _, err := client.GetNodeConfig(context.Background(), pbsclient.DefaultNode)
		if err != nil {
			return err
		}
		for i, raw := range config.ACMEDomains {
			if raw == "" {
				continue
			}
			domain, err := pbsclient.ParseACMEDomain(raw)
			if err != nil {
				return err
			}
			if record {
				slots[domain.Domain] = i
				continue
			}
			if want, ok := slots[domain.Domain]; !ok || want != i {
				return fmt.Errorf("%s is in slot %d, recorded in slot %d (known: %v)", domain.Domain, i, want, ok)
			}
		}
		return nil
	}
}

func TestAccNodeCertificate(t *testing.T) {
	directory := testAccOrdersCertificates(t)
	// Every terraform command configures the provider anew from the
	// environment, whose fingerprint names the certificate before the order.
	t.Setenv(envCertFingerprint, "")
	t.Setenv(envCAFile, "")
	t.Setenv(envInsecureSkipVerify, "true")

	account := testAccACMEName()
	first, second := testAccACMEDomain("pbs"), testAccACMEDomain("www")
	const resourceName = "pbs_node_certificate.this"
	config := func(domains ...string) string {
		var entries []string
		for _, d := range domains {
			entries = append(entries, fmt.Sprintf("{ domain = %q }", d))
		}
		return providerConfig + fmt.Sprintf(`
resource "pbs_acme_account" "test" {
  name      = %q
  contact   = "tfacc@pbs.test"
  directory = %q
  tos_url   = %q
}

resource "pbs_node_acme" "this" {
  account = pbs_acme_account.test.name
  domains = [%s]
}

resource "pbs_node_certificate" "this" {
  source = "acme"
  triggers = {
    domains = join(",", sort(pbs_node_acme.this.domains[*].domain))
  }
}
`, account, directory, pebbleToS, strings.Join(entries, ", "))
	}
	var fingerprint string

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckACMEDestroyed([]string{account}, nil),
			testAccCheckSelfSigned,
		),
		Steps: []acc.TestStep{
			{
				Config: config(first),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "id", pbsclient.DefaultNode),
					acc.TestCheckResourceAttr(resourceName, "san.#", "1"),
					acc.TestCheckResourceAttr(resourceName, "san.0", first),
					acc.TestMatchResourceAttr(resourceName, "issuer", regexp.MustCompile("Pebble")),
					acc.TestCheckResourceAttrSet(resourceName, "not_after"),
					captureAttr(resourceName, "fingerprint", &fingerprint),
				),
			},
			{
				// A new domain changes the triggers: a new certificate,
				// ordered in place.
				Config: config(first, second),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(resourceName, "san.#", "2"),
					func(s *terraform.State) error {
						if got := s.RootModule().Resources[resourceName].Primary.Attributes["fingerprint"]; got == fingerprint {
							return fmt.Errorf("the fingerprint is still %s", got)
						}
						return nil
					},
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateId:           pbsclient.DefaultNode,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"source", "triggers"},
			},
		},
	})
}

// testAccCheckSelfSigned checks that the node serves a self-signed
// certificate again.
func testAccCheckSelfSigned(*terraform.State) error {
	client, err := testAccInsecureClient()
	if err != nil {
		return err
	}
	cert, err := client.ProxyCertificate(context.Background())
	if err != nil {
		return err
	}
	if !cert.SelfSigned() {
		return fmt.Errorf("the node serves %s, issued by %s, not a self-signed certificate", cert.Subject, cert.Issuer)
	}
	return nil
}

// The provider's client keeps working when the certificate it pins changes
// under it — against a real proxy, which keeps the connection of the change
// open on the old certificate. A client of the provider's settings, pinned to
// PBS_TLS_FINGERPRINT, orders a certificate, goes back to a self-signed one,
// and goes on after each.
func TestAccCertificateChangeKeepsTheClientWorking(t *testing.T) {
	directory := testAccOrdersCertificates(t)
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	testAccPreCheck(t)
	if os.Getenv(envCertFingerprint) == "" {
		t.Skip(envCertFingerprint + " is not set: the client pins no certificate")
	}
	ctx := context.Background()
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	node := client.Node()

	account := testAccACMEName()
	if err := client.RegisterACMEAccount(ctx, url.Values{
		"name": {account}, "contact": {"tfacc@pbs.test"}, "directory": {directory}, "tos_url": {pebbleToS},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, err := testAccInsecureClient()
		if err == nil {
			err = cleanup.DeactivateACMEAccount(ctx, account, true)
		}
		if err != nil {
			t.Errorf("deactivating the account: %v", err)
		}
	})
	domain := testAccACMEDomain("repin")
	if err := client.UpdateNodeConfig(ctx, node, url.Values{"acme": {"account=" + account}, "acmedomain0": {domain}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		params := url.Values{}
		pbsclient.AddDelete(params, "acme", "acmedomain0")
		cleanup, err := testAccInsecureClient()
		if err == nil {
			err = cleanup.UpdateNodeConfig(ctx, node, params)
		}
		if err != nil {
			t.Errorf("removing the node's ACME settings: %v", err)
		}
	})

	ordered, err := client.ChangeCertificate(ctx, node, func(ctx context.Context) error {
		return client.OrderACMECertificate(ctx, node)
	})
	if err != nil {
		t.Fatalf("ordering: %v", err)
	}
	if !ordered.Changed() || ordered.Unconfirmed != nil || ordered.After.SelfSigned() || !strings.Contains(ordered.After.Issuer, "Pebble") {
		t.Fatalf("ordering changed %+v to %+v (unconfirmed: %v)", ordered.Before, ordered.After, ordered.Unconfirmed)
	}
	client.CloseIdleConnections()
	if _, err := client.ServerVersion(ctx); err != nil {
		t.Fatalf("the client does not trust the ordered certificate: %v", err)
	}
	// A client with the same settings, new, does not.
	fresh, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	var untrusted *pbsclient.UntrustedCertificateError
	if _, err := fresh.ServerVersion(ctx); !errors.As(err, &untrusted) {
		t.Fatalf("a new pinned client's error = %v, want an untrusted certificate", err)
	}

	reverted, err := client.ChangeCertificate(ctx, node, func(ctx context.Context) error {
		return client.DeleteCustomCertificate(ctx, node)
	})
	if err != nil {
		t.Fatalf("going back to a self-signed certificate: %v", err)
	}
	if !reverted.Changed() || reverted.Unconfirmed != nil || !reverted.After.SelfSigned() {
		t.Fatalf("deleting changed %+v to %+v (unconfirmed: %v)", reverted.Before, reverted.After, reverted.Unconfirmed)
	}
	client.CloseIdleConnections()
	if _, err := client.ServerVersion(ctx); err != nil {
		t.Fatalf("the client does not trust the new self-signed certificate: %v", err)
	}
}

// From Terraform 1.12, the ACME resources import by identity too. The
// certificate is left out: an import leaves its source unset, which the
// next apply records, so its import plans an update.
func TestAccACMEResourcesImportByIdentity(t *testing.T) {
	directory := testAccACMEDirectory(t)
	account, plugin := testAccACMEName(), testAccACMEName()
	config := providerConfig + fmt.Sprintf(`
resource "pbs_acme_account" "test" {
  name      = %q
  contact   = "tfacc@pbs.test"
  directory = %q
  tos_url   = %q
}

resource "pbs_acme_plugin" "test" {
  id   = %q
  api  = "cf"
  data = { CF_Token = "not-a-real-token" }
}

resource "pbs_node_acme" "this" {
  account = pbs_acme_account.test.name
  domains = [{ domain = %q, plugin = pbs_acme_plugin.test.id }]
}
`, account, directory, pebbleToS, plugin, testAccACMEDomain("identity"))

	steps := []acc.TestStep{{Config: config}}
	for _, name := range []string{"pbs_acme_account.test", "pbs_acme_plugin.test", "pbs_node_acme.this"} {
		steps = append(steps,
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			acc.TestStep{Config: config, ResourceName: name, ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		CheckDestroy:             testAccCheckACMEDestroyed([]string{account}, []string{plugin}),
		Steps:                    steps,
	})
}
