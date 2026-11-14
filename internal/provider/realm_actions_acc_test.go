package provider

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// A sync of an LDAP realm against the stand's directory, whose one user the
// sync makes a PBS user of: a dry run first, which changes nothing, then the
// sync, which creates the user, disabled as enable_new says, with the first
// name the realm's sync_attributes take from the directory, and deletes a
// user of the realm the directory does not have, as remove_vanished says.
// The users of a deleted realm stay in PBS, so the test deletes them; PBS
// answers that with "unknown realm", having deleted the user all the same.
func TestAccRealmSyncAction(t *testing.T) {
	d := testAccLDAP(t)
	name := testAccRealmName()
	synced, vanished := d.user+"@"+name, "tfacc-vanished@"+name
	// deleteUsers deletes the realm's users, which outlive it, once the
	// test has run.
	deleteUsers := func() {
		client, err := testAccClient()
		if err != nil {
			t.Error(err)
			return
		}
		ctx := context.Background()
		for _, userID := range []string{synced, vanished} {
			err := client.DeleteUser(ctx, userID)
			if pbsclient.IsUserRealmGone(err, userID) {
				if _, err = client.GetUser(ctx, userID); err == nil {
					err = fmt.Errorf("PBS answered unknown realm and kept the user")
				}
			}
			if err != nil && !pbsclient.IsNotFound(err) {
				t.Errorf("deleting %s: %v", userID, err)
			}
		}
	}
	realm := providerConfig + fmt.Sprintf(`
resource "pbs_realm_ldap" "test" {
  realm           = %q
  server1         = %q
  base_dn         = %q
  user_attr       = "uid"
  bind_dn         = %q
  %s
  sync_attributes = { firstname = "givenName", lastname = "sn" }
  comment         = "terraform-provider-pbs acceptance tests"
}
`, name, d.server, d.baseDN, d.bindDN, testAccPasswordWO(d.bindPassword, 1))
	sync := func(dryRun bool) string {
		return fmt.Sprintf(`
action "pbs_realm_sync" "test" {
  config {
    realm           = pbs_realm_ldap.test.realm
    dry_run         = %t
    enable_new      = false
    remove_vanished = ["entry"]
  }
}
`, dryRun) + testAccActionTrigger("action.pbs_realm_sync.test", fmt.Sprintf("dry run: %t", dryRun))
	}
	user := func(userID string, check func(pbsclient.User, error) error) acc.TestCheckFunc {
		return func(*terraform.State) error {
			client, err := testAccClient()
			if err != nil {
				return err
			}
			u, err := client.GetUser(context.Background(), userID)
			if err := check(u, err); err != nil {
				return fmt.Errorf("user %s: %w", userID, err)
			}
			return nil
		}
	}
	absent := func(_ pbsclient.User, err error) error {
		if err == nil {
			return fmt.Errorf("exists")
		} else if !pbsclient.IsNotFound(err) {
			return err
		}
		return nil
	}
	present := func(_ pbsclient.User, err error) error { return err }

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); t.Cleanup(deleteUsers) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   actionVersionChecks,
		CheckDestroy:             testAccCheckDirectoryRealmsDestroyed(pbsclient.RealmTypeLDAP, name),
		Steps: []acc.TestStep{
			{
				Config: realm,
				Check:  user(synced, absent),
			},
			{
				// A user of the realm the directory does not have, made
				// outside Terraform, which the sync deletes.
				PreConfig: func() {
					client, err := testAccClient()
					if err != nil {
						t.Fatal(err)
					}
					if err := client.CreateUser(context.Background(), url.Values{"userid": {vanished}}); err != nil {
						t.Fatalf("creating %s: %v", vanished, err)
					}
				},
				Config: realm + sync(true),
				Check: acc.ComposeAggregateTestCheckFunc(
					user(synced, absent),
					user(vanished, present),
				),
			},
			{
				Config: realm + sync(false),
				Check: acc.ComposeAggregateTestCheckFunc(
					user(synced, func(u pbsclient.User, err error) error {
						switch {
						case err != nil:
							return err
						case u.Firstname != "Alice" || u.Lastname != "Example" || u.Enabled():
							return fmt.Errorf("synced as %+v, want Alice Example, disabled", u)
						}
						return nil
					}),
					user(vanished, absent),
				),
			},
		},
	})
}
