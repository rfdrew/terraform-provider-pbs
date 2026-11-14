package provider

import (
	"fmt"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The list resources of the metric servers, the S3 endpoints, the traffic
// control rules and the realms. Nothing here contacts a server: PBS checks
// no disabled metric server, and saves S3 endpoints and OpenID realms
// without contacting them, so they point at hosts that do not exist; the
// traffic control rule matches a documentation network no client of the
// stand comes from. LDAP and Active Directory realms need the stand's LDAP
// server, and have a test of their own.
func TestAccConfigListResources(t *testing.T) {
	httpServer, udpServer := testAccMetricServerName(), testAccMetricServerName()
	s3Endpoint, rule, realm := "tfacc-"+testAccRandom(8), "tfacc-"+testAccRandom(8), testAccRealmName()
	byName := func(attribute, name string) map[string]knownvalue.Check {
		return map[string]knownvalue.Check{attribute: knownvalue.StringExact(name)}
	}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_metric_server_influxdb_http" "test" {
  name    = %q
  url     = "http://influxdb.invalid:8086"
  enable  = false
  comment = "listed by terraform query"
}

resource "pbs_metric_server_influxdb_udp" "test" {
  name   = %q
  host   = "influxdb.invalid:8089"
  mtu    = 1400
  enable = false
}

resource "pbs_s3_endpoint" "test" {
  id                    = %q
  endpoint              = "s3.example.invalid"
  port                  = 9443
  path_style            = true
  access_key            = "tfacc-access"
  secret_key_wo         = "tfacc-secret"
  secret_key_wo_version = 1
}

resource "pbs_traffic_control_rule" "test" {
  name    = %q
  network = ["203.0.113.0/24"]
  rate_in = "10 MiB"
  comment = "listed by terraform query"
}

resource "pbs_realm_openid" "test" {
  realm      = %q
  issuer_url = %q
  client_id  = "pbs"
  client_key = "tfacc-client-key"
  comment    = "listed by terraform query"
}
`, httpServer, udpServer, s3Endpoint, rule, realm, testAccIssuerURL)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckMetricServersDestroyed(httpServer, udpServer),
			testAccCheckS3EndpointsDestroyed(s3Endpoint),
			testAccCheckTrafficControlRulesDestroyed(rule),
			testAccCheckOpenIDRealmsDestroyed(realm),
		),
		Steps: []acc.TestStep{
			{Config: config},
			{
				// The step keeps the configuration of the step before, with
				// its provider block, next to this query file.
				Query: true,
				Config: `
list "pbs_metric_server_influxdb_http" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_metric_server_influxdb_udp" "all" {
  provider = pbs
}

list "pbs_s3_endpoint" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_traffic_control_rule" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_realm_openid" "all" {
  provider         = pbs
  include_resource = true
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					// Metric servers of both types share a namespace, but each
					// list has its own type only.
					querycheck.ExpectIdentity("pbs_metric_server_influxdb_http.all", byName("name", httpServer)),
					querycheck.ExpectNoIdentity("pbs_metric_server_influxdb_http.all", byName("name", udpServer)),
					querycheck.ExpectIdentity("pbs_metric_server_influxdb_udp.all", byName("name", udpServer)),
					querycheck.ExpectNoIdentity("pbs_metric_server_influxdb_udp.all", byName("name", httpServer)),
					querycheck.ExpectResourceDisplayName("pbs_metric_server_influxdb_http.all", queryfilter.ByResourceIdentity(byName("name", httpServer)),
						knownvalue.StringExact(httpServer+" — listed by terraform query")),
					querycheck.ExpectResourceKnownValues("pbs_metric_server_influxdb_http.all", queryfilter.ByResourceIdentity(byName("name", httpServer)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("enable"), KnownValue: knownvalue.Bool(false)},
							{Path: tfjsonpath.New("organization"), KnownValue: knownvalue.StringExact(pbsclient.DefaultInfluxDBOrganization)},
							{Path: tfjsonpath.New("token_wo_version"), KnownValue: knownvalue.Null()},
						}),
					// The access key is sensitive: the result leaves it out.
					querycheck.ExpectIdentity("pbs_s3_endpoint.all", byName("id", s3Endpoint)),
					querycheck.ExpectResourceDisplayName("pbs_s3_endpoint.all", queryfilter.ByResourceIdentity(byName("id", s3Endpoint)),
						knownvalue.StringExact(s3Endpoint+" — s3.example.invalid:9443")),
					querycheck.ExpectResourceKnownValues("pbs_s3_endpoint.all", queryfilter.ByResourceIdentity(byName("id", s3Endpoint)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("endpoint"), KnownValue: knownvalue.StringExact("s3.example.invalid")},
							{Path: tfjsonpath.New("path_style"), KnownValue: knownvalue.Bool(true)},
							{Path: tfjsonpath.New("access_key"), KnownValue: knownvalue.Null()},
						}),
					querycheck.ExpectIdentity("pbs_traffic_control_rule.all", byName("name", rule)),
					querycheck.ExpectResourceKnownValues("pbs_traffic_control_rule.all", queryfilter.ByResourceIdentity(byName("name", rule)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("rate_in"), KnownValue: knownvalue.StringExact("10 MiB")},
							{Path: tfjsonpath.New("comment"), KnownValue: knownvalue.StringExact("listed by terraform query")},
						}),
					// The client key is not imported, though PBS returns it.
					querycheck.ExpectIdentity("pbs_realm_openid.all", byName("realm", realm)),
					querycheck.ExpectNoIdentity("pbs_realm_openid.all", byName("realm", "pam")),
					querycheck.ExpectResourceKnownValues("pbs_realm_openid.all", queryfilter.ByResourceIdentity(byName("realm", realm)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("issuer_url"), KnownValue: knownvalue.StringExact(testAccIssuerURL)},
							{Path: tfjsonpath.New("client_key"), KnownValue: knownvalue.Null()},
						}),
				},
			},
			// What -generate-config-out writes for an object is the
			// configuration Terraform generates from its imported state: it
			// plans no change, but for an S3 endpoint, which needs its access
			// key filled in.
			testAccGeneratedConfigStep(config, "pbs_metric_server_influxdb_http.test"),
			testAccGeneratedConfigStep(config, "pbs_metric_server_influxdb_udp.test"),
			testAccGeneratedConfigStep(config, "pbs_traffic_control_rule.test"),
			testAccGeneratedConfigStep(config, "pbs_realm_openid.test"),
		},
	})
}

// LDAP and Active Directory realms, on the stand's LDAP server, which PBS
// connects to when it saves them. The bind password is not imported: the
// generated configuration plans no change without it.
func TestAccDirectoryRealmListResources(t *testing.T) {
	d := testAccLDAP(t)
	ldap, ad := testAccRealmName(), testAccRealmName()
	byRealm := func(name string) map[string]knownvalue.Check {
		return map[string]knownvalue.Check{"realm": knownvalue.StringExact(name)}
	}
	config := providerConfig + fmt.Sprintf(`
resource "pbs_realm_ldap" "test" {
  realm     = %q
  server1   = %q
  base_dn   = %q
  user_attr = "uid"
  bind_dn   = %q
  %s
  comment   = "listed by terraform query"
}

resource "pbs_realm_ad" "test" {
  realm   = %q
  server1 = %q
  bind_dn = %q
  %s
}
`, ldap, d.server, d.baseDN, d.bindDN, testAccPasswordWO(d.bindPassword, 1),
		ad, d.server, d.bindDN, testAccPasswordWO(d.bindPassword, 1))

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   queryVersionChecks,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckDirectoryRealmsDestroyed(pbsclient.RealmTypeLDAP, ldap),
			testAccCheckDirectoryRealmsDestroyed(pbsclient.RealmTypeAD, ad),
		),
		Steps: []acc.TestStep{
			{Config: config},
			{
				Query: true,
				Config: `
list "pbs_realm_ldap" "all" {
  provider         = pbs
  include_resource = true
}

list "pbs_realm_ad" "all" {
  provider         = pbs
  include_resource = true
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectIdentity("pbs_realm_ldap.all", byRealm(ldap)),
					querycheck.ExpectNoIdentity("pbs_realm_ldap.all", byRealm(ad)),
					querycheck.ExpectIdentity("pbs_realm_ad.all", byRealm(ad)),
					querycheck.ExpectNoIdentity("pbs_realm_ad.all", byRealm(ldap)),
					querycheck.ExpectResourceDisplayName("pbs_realm_ldap.all", queryfilter.ByResourceIdentity(byRealm(ldap)),
						knownvalue.StringExact(ldap+" — listed by terraform query")),
					querycheck.ExpectResourceKnownValues("pbs_realm_ldap.all", queryfilter.ByResourceIdentity(byRealm(ldap)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("bind_dn"), KnownValue: knownvalue.StringExact(d.bindDN)},
							{Path: tfjsonpath.New("password_wo_version"), KnownValue: knownvalue.Null()},
						}),
					// PBS found the Active Directory realm's base DN itself.
					querycheck.ExpectResourceKnownValues("pbs_realm_ad.all", queryfilter.ByResourceIdentity(byRealm(ad)),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("base_dn"), KnownValue: knownvalue.StringExact(d.baseDN)},
						}),
				},
			},
			testAccGeneratedConfigStep(config, "pbs_realm_ldap.test"),
			testAccGeneratedConfigStep(config, "pbs_realm_ad.test"),
		},
	})
}

// testAccGeneratedConfigStep imports the resource at address by its
// identity, with the configuration Terraform generates from what the import
// reads, as `terraform plan` does with what `terraform query
// -generate-config-out` writes: the step fails unless that configuration
// plans no change.
func testAccGeneratedConfigStep(config, address string) acc.TestStep {
	return acc.TestStep{
		Config:          config,
		ResourceName:    address,
		ImportState:     true,
		ImportStateKind: acc.ImportBlockWithResourceIdentity,
		GenerateConfig:  true,
	}
}
