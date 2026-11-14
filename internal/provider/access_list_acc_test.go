package provider

import (
	"fmt"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// The list resources of the access layer, pbs_api_token and pbs_acl,
// against a user, a token and ACL entries of the test's own. The stand has
// tokens and entries of its own, and other tests add theirs meanwhile, so
// the checks look for the test's objects rather than count them all.
func TestAccAccessListResources(t *testing.T) {
	userID := testAccUserID()
	tokenID := userID + "!ci"
	aclPath := "/datastore/" + testAccDatastore(t)
	token := map[string]knownvalue.Check{"tokenid": knownvalue.StringExact(tokenID)}
	userEntry := map[string]knownvalue.Check{
		"path": knownvalue.StringExact(aclPath), "auth_id": knownvalue.StringExact(userID), "role": knownvalue.StringExact("DatastoreAudit"),
	}
	tokenEntry := map[string]knownvalue.Check{
		"path": knownvalue.StringExact(aclPath), "auth_id": knownvalue.StringExact(tokenID), "role": knownvalue.StringExact("DatastoreBackup"),
	}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_user" "test" {
  userid = %[1]q
}

resource "pbs_api_token" "test" {
  userid     = pbs_user.test.userid
  token_name = "ci"
  comment    = "listed by terraform query"
  expire     = 4102444800
}

resource "pbs_acl" "user" {
  path    = %[2]q
  auth_id = pbs_user.test.userid
  role    = "DatastoreAudit"
}

resource "pbs_acl" "token" {
  path      = %[2]q
  auth_id   = pbs_api_token.test.tokenid
  role      = "DatastoreBackup"
  propagate = false
}
`, userID, aclPath)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy:             testAccCheckAccessDestroyed(userID),
		Steps: []acc.TestStep{
			{Config: config},
			{
				// The step keeps the configuration of the step before, with
				// its provider block, next to this query file.
				Query: true,
				Config: fmt.Sprintf(`
list "pbs_api_token" "user" {
  provider         = pbs
  include_resource = true

  config {
    userid = %[1]q
  }
}

list "pbs_api_token" "all" {
  provider = pbs
}

list "pbs_acl" "token" {
  provider         = pbs
  include_resource = true

  config {
    auth_id = %[2]q
  }
}

list "pbs_acl" "path" {
  provider = pbs

  config {
    path = %[3]q
  }
}
`, userID, tokenID, aclPath),
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectLength("pbs_api_token.user", 1),
					querycheck.ExpectIdentity("pbs_api_token.user", token),
					querycheck.ExpectIdentity("pbs_api_token.all", token),
					querycheck.ExpectResourceDisplayName("pbs_api_token.user", queryfilter.ByResourceIdentity(token),
						knownvalue.StringExact(tokenID+" — listed by terraform query")),
					// The secret is never known, and sensitive anyway.
					querycheck.ExpectResourceKnownValues("pbs_api_token.user", queryfilter.ByResourceIdentity(token), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("userid"), KnownValue: knownvalue.StringExact(userID)},
						{Path: tfjsonpath.New("expire"), KnownValue: knownvalue.Int64Exact(4102444800)},
						{Path: tfjsonpath.New("value"), KnownValue: knownvalue.Null()},
					}),
					// auth_id selects the token's entries, not its user's.
					querycheck.ExpectLength("pbs_acl.token", 1),
					querycheck.ExpectIdentity("pbs_acl.token", tokenEntry),
					querycheck.ExpectResourceKnownValues("pbs_acl.token", queryfilter.ByResourceIdentity(tokenEntry), []querycheck.KnownValueCheck{
						{Path: tfjsonpath.New("propagate"), KnownValue: knownvalue.Bool(false)},
					}),
					querycheck.ExpectIdentity("pbs_acl.path", userEntry),
					querycheck.ExpectIdentity("pbs_acl.path", tokenEntry),
					querycheck.ExpectResourceDisplayName("pbs_acl.path", queryfilter.ByResourceIdentity(userEntry),
						knownvalue.StringExact("DatastoreAudit on "+aclPath+" for "+userID)),
				},
			},
			// What -generate-config-out writes for an object is the
			// configuration Terraform generates from its imported state:
			// it must plan no change.
			{
				Config:          config,
				ResourceName:    "pbs_api_token.test",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
			{
				Config:          config,
				ResourceName:    "pbs_acl.token",
				ImportState:     true,
				ImportStateKind: acc.ImportBlockWithResourceIdentity,
				GenerateConfig:  true,
			},
		},
	})
}
