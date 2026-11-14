package provider

import (
	"context"
	"fmt"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The renewal action against Pebble, whose 90-day certificates are not due
// for 60 days once ordered: a renewal without force renews nothing, one with
// force orders a new certificate, which the next refresh of
// pbs_node_certificate reads without planning anything. Like the other tests
// that order certificates, it puts the stand's certificate back when it
// ends, and runs with certificate verification off, since every terraform
// command configures the provider anew from the environment, whose
// fingerprint names the certificate before the order.
func TestAccNodeCertificateRenewAction(t *testing.T) {
	directory := testAccOrdersCertificates(t)
	t.Setenv(envCertFingerprint, "")
	t.Setenv(envCAFile, "")
	t.Setenv(envInsecureSkipVerify, "true")

	account := testAccACMEName()
	const resourceName = "pbs_node_certificate.this"
	base := providerConfig + fmt.Sprintf(`
resource "pbs_acme_account" "test" {
  name      = %q
  contact   = "tfacc@pbs.test"
  directory = %q
  tos_url   = %q
}

resource "pbs_node_acme" "this" {
  account = pbs_acme_account.test.name
  domains = [{ domain = %q }]
}

resource "pbs_node_certificate" "this" {
  source = "acme"
  triggers = {
    domains = join(",", sort(pbs_node_acme.this.domains[*].domain))
  }
}
`, account, directory, pebbleToS, testAccACMEDomain("renew"))
	renew := func(force bool) string {
		return base + fmt.Sprintf(`
action "pbs_node_certificate_renew" "test" {
  config {
    force = %t
  }
}
`, force) + testAccActionTrigger("action.pbs_node_certificate_renew.test", fmt.Sprint(force))
	}
	var ordered string

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckACMEDestroyed([]string{account}, nil),
			testAccCheckSelfSigned,
		),
		Steps: []acc.TestStep{
			{Config: base, Check: captureAttr(resourceName, "fingerprint", &ordered)},
			// Not due: the action succeeds, and the certificate stays.
			{Config: renew(false), Check: testAccCheckServedFingerprint(func(served string) error {
				if served != ordered {
					return fmt.Errorf("a renewal without force replaced %s with %s", ordered, served)
				}
				return nil
			})},
			// With force, PBS orders a new certificate; the state of
			// pbs_node_certificate has the old one until its next refresh,
			// which plans nothing.
			{Config: renew(true), Check: testAccCheckServedFingerprint(func(served string) error {
				if served == ordered {
					return fmt.Errorf("a forced renewal kept %s", served)
				}
				return nil
			})},
			{Config: renew(true), Check: func(s *terraform.State) error {
				recorded := s.RootModule().Resources[resourceName].Primary.Attributes["fingerprint"]
				return testAccCheckServedFingerprint(func(served string) error {
					if recorded != served || served == ordered {
						return fmt.Errorf("pbs_node_certificate records %s, PBS serves %s, ordered was %s", recorded, served, ordered)
					}
					return nil
				})(s)
			}},
		},
	})
}

// testAccCheckServedFingerprint checks the fingerprint of the certificate
// PBS serves now, written as pbs_node_certificate records it.
func testAccCheckServedFingerprint(check func(served string) error) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccInsecureClient()
		if err != nil {
			return err
		}
		cert, err := client.ProxyCertificate(context.Background())
		if err != nil {
			return err
		}
		normalised, err := pbsclient.NormaliseFingerprint(cert.Fingerprint)
		if err != nil {
			return err
		}
		return check(pbsclient.FormatFingerprint(normalised))
	}
}
