package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Acceptance tests of pbs_acme_account's External Account Binding and
// force_destroy, against Pebble. scripts/bootstrap-test-pbs.sh gives Pebble
// two binding keys; Pebble checks a binding whenever a registration carries
// one, and requires none, so the other ACME tests register without.

// The External Account Binding keys scripts/bootstrap-test-pbs.sh gives
// Pebble: key identifiers and HMAC keys, base64url without padding. The
// second key holds "-" or "_", so that its standard base64 form holds "+"
// or "/", which PBS reads as standard base64.
const (
	envAccACMEEABKid  = "PBS_ACC_ACME_EAB_KID"
	envAccACMEEABKey  = "PBS_ACC_ACME_EAB_HMAC_KEY"
	envAccACMEEABKid2 = "PBS_ACC_ACME_EAB_KID_2"
	envAccACMEEABKey2 = "PBS_ACC_ACME_EAB_HMAC_KEY_2"
)

const (
	// acmeAccountsDir is where PBS keeps its accounts' files, named after
	// the accounts (proxmox-acme-api's account_config.rs).
	acmeAccountsDir     = "/etc/proxmox-backup/acme/accounts/"
	acmeEABResourceName = "pbs_acme_account.test"
	// acmeUnknownEABKeyID is a key identifier Pebble does not know, and
	// acmeUnknownAccountID the ID of an account it does not know.
	acmeUnknownEABKeyID  = "tfacc-eab-unknown"
	acmeUnknownAccountID = "tfacc-gone"
)

// acmeEABKey is one of Pebble's External Account Binding keys.
type acmeEABKey struct {
	kid, key string
}

// testAccACMEEAB returns Pebble's directory and its two External Account
// Binding keys, or skips the test.
func testAccACMEEAB(t *testing.T) (directory string, first, second acmeEABKey) {
	t.Helper()
	directory = testAccACMEDirectory(t)
	first = acmeEABKey{os.Getenv(envAccACMEEABKid), os.Getenv(envAccACMEEABKey)}
	second = acmeEABKey{os.Getenv(envAccACMEEABKid2), os.Getenv(envAccACMEEABKey2)}
	if os.Getenv("TF_ACC") != "" && (first.kid == "" || first.key == "" || second.kid == "" || second.key == "") {
		t.Skip(envAccACMEEABKid + " and the other External Account Binding variables are not set: Pebble knows no binding keys")
	}
	return directory, first, second
}

// testAccACMEEABConfig is an account at Pebble with a binding: kid, key and
// version, or none when kid is empty. extra goes into the resource block.
func testAccACMEEABConfig(directory, name, kid, key string, version int, extra string) string {
	binding := ""
	if kid != "" {
		binding = fmt.Sprintf(`
  eab_kid                 = %q
  eab_hmac_key_wo         = %q
  eab_hmac_key_wo_version = %d`, kid, key, version)
	}
	return providerConfig + fmt.Sprintf(`
resource "pbs_acme_account" "test" {
  name      = %q
  contact   = "tfacc@pbs.test"
  directory = %q
  tos_url   = %q%s%s
}
`, name, directory, pebbleToS, binding, extra)
}

// testAccCheckACMEAccountEAB checks, through the API, the key identifier of
// the binding PBS holds as Pebble echoed it: proof that PBS sent the binding
// and Pebble accepted it.
func testAccCheckACMEAccountEAB(name, kid string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		account, err := client.GetACMEAccount(context.Background(), name)
		if err != nil {
			return err
		}
		if got := account.EABKeyID(); got != kid {
			return fmt.Errorf("PBS holds the binding of key identifier %q, want %q", got, kid)
		}
		return nil
	}
}

func TestAccACMEAccountEAB(t *testing.T) {
	directory, first, second := testAccACMEEAB(t)
	name := testAccACMEName()
	// The second key in standard base64, as some CAs hand keys out.
	secondStd := strings.NewReplacer("-", "+", "_", "/").Replace(second.key)
	var location string

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckACMEDestroyed([]string{name}, nil),
		Steps: []acc.TestStep{
			{
				Config: testAccACMEEABConfig(directory, name, first.kid, first.key, 1, ""),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(acmeEABResourceName, "status", "valid"),
					acc.TestCheckResourceAttr(acmeEABResourceName, "eab_kid", first.kid),
					acc.TestCheckResourceAttr(acmeEABResourceName, "eab_hmac_key_wo_version", "1"),
					acc.TestCheckNoResourceAttr(acmeEABResourceName, "eab_hmac_key_wo"),
					acc.TestCheckResourceAttr(acmeEABResourceName, "force_destroy", "false"),
					captureAttr(acmeEABResourceName, "location", &location),
					testAccCheckACMEAccountEAB(name, first.kid),
				),
			},
			{
				// Before any update of the account, which makes Pebble drop
				// the binding PBS holds: the import reads eab_kid from it.
				ResourceName:            acmeEABResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"eab_hmac_key_wo", "eab_hmac_key_wo_version"},
			},
			{
				// A new binding registers a new account.
				Config: testAccACMEEABConfig(directory, name, second.kid, secondStd, 2, ""),
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(acmeEABResourceName, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(acmeEABResourceName, "eab_kid", second.kid),
					acc.TestCheckResourceAttr(acmeEABResourceName, "eab_hmac_key_wo_version", "2"),
					func(s *terraform.State) error {
						if got := s.RootModule().Resources[acmeEABResourceName].Primary.Attributes["location"]; got == location {
							return fmt.Errorf("the location is still %s", got)
						}
						return nil
					},
					testAccCheckACMEAccountEAB(name, second.kid),
					captureAttr(acmeEABResourceName, "location", &location),
				),
			},
			{
				// Leaving the binding out is only recorded.
				Config: testAccACMEEABConfig(directory, name, "", "", 0, ""),
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(acmeEABResourceName, plancheck.ResourceActionUpdate),
				}},
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckNoResourceAttr(acmeEABResourceName, "eab_kid"),
					acc.TestCheckNoResourceAttr(acmeEABResourceName, "eab_hmac_key_wo_version"),
					acc.TestCheckResourceAttrPtr(acmeEABResourceName, "location", &location),
				),
			},
		},
	})
}

// A binding Pebble refuses fails the registration with the provider's hint,
// and leaves no account.
func TestAccACMEAccountEABRefused(t *testing.T) {
	directory, first, _ := testAccACMEEAB(t)
	name := testAccACMEName()
	wrongKey := make([]byte, 48)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   writeOnlyVersions,
		CheckDestroy:             testAccCheckACMEDestroyed([]string{name}, nil),
		Steps: []acc.TestStep{
			{
				Config:      testAccACMEEABConfig(directory, name, first.kid, base64.RawURLEncoding.EncodeToString(wrongKey), 1, ""),
				ExpectError: regexp.MustCompile(`refused\s+the\s+External\s+Account\s+Binding(?s:.*)verification\s+error`),
			},
			{
				Config:      testAccACMEEABConfig(directory, name, acmeUnknownEABKeyID, first.key, 1, ""),
				ExpectError: regexp.MustCompile(`refused\s+the\s+External\s+Account\s+Binding(?s:.*)not\s+known\s+to\s+the\s+ACME\s+server`),
			},
		},
	})
}

// testAccSkipWithoutContainer skips a test that changes files in the
// stand's container when it cannot: without the container's name or Docker.
func testAccSkipWithoutContainer(t *testing.T) string {
	t.Helper()
	container := os.Getenv(envAccContainer)
	if os.Getenv("TF_ACC") == "" {
		return container
	}
	if container == "" {
		t.Skip(envAccContainer + " is not set: the test changes a file in the stand's container")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("the test changes a file in the stand's container, with docker:", err)
	}
	return container
}

// testAccForgetACMEAccountAtCA points PBS's file of an account at an account
// Pebble does not know, as a CA that lost or deleted the account would have
// it: Pebble then refuses to deactivate it with accountDoesNotExist. PBS
// writes the file as pretty-printed JSON, "location": "<URL>", and only the
// computed location changes in what PBS reports.
func testAccForgetACMEAccountAtCA(container, name string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		file := acmeAccountsDir + name
		script := `sed -i 's#\("location": "[^"]*/my-account/\)[^"]*"#\1` + acmeUnknownAccountID + `"#' "$1" && grep -q '/my-account/` +
			acmeUnknownAccountID + `"' "$1"`
		if out, err := exec.Command("docker", "exec", container, "sh", "-c", script, "sh", file).CombinedOutput(); err != nil {
			return fmt.Errorf("pointing %s at an account Pebble does not know: %v\n%s", file, err, out)
		}
		return nil
	}
}

// testAccCheckACMEAccountFileKept checks that PBS kept the key of an account
// it removed with force, renamed as a deactivated account.
func testAccCheckACMEAccountFileKept(container, name string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		file := acmeAccountsDir + "_deactivated_" + name + "_0"
		if out, err := exec.Command("docker", "exec", container, "test", "-e", file).CombinedOutput(); err != nil {
			return fmt.Errorf("PBS kept no %s: %v\n%s", file, err, out)
		}
		return nil
	}
}

// When Pebble no longer knows an account, destroying it fails, with advice,
// until force_destroy is set; then PBS removes it, keeping its key.
func TestAccACMEAccountForceDestroy(t *testing.T) {
	directory := testAccACMEDirectory(t)
	container := testAccSkipWithoutContainer(t)
	name := testAccACMEName()
	config := func(forceDestroy bool) string {
		return testAccACMEEABConfig(directory, name, "", "", 0, fmt.Sprintf("\n  force_destroy = %t", forceDestroy))
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckACMEDestroyed([]string{name}, nil),
			testAccCheckACMEAccountFileKept(container, name),
		),
		Steps: []acc.TestStep{
			{
				Config: config(false),
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr(acmeEABResourceName, "force_destroy", "false"),
					testAccForgetACMEAccountAtCA(container, name),
				),
			},
			{
				// Removing the resource destroys it: Pebble refuses.
				Config: providerConfig,
				ExpectError: regexp.MustCompile(`could\s+not\s+deactivate(?s:.*)does\s+not\s+know\s+the\s+account` +
					`(?s:.*)set\s+force_destroy\s+=\s+true(?s:.*)accountDoesNotExist`),
			},
			{
				Config: config(true),
				ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(acmeEABResourceName, plancheck.ResourceActionUpdate),
				}},
				Check: acc.TestCheckResourceAttr(acmeEABResourceName, "force_destroy", "true"),
			},
		},
	})
}
