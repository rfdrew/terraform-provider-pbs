package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestFingerprintDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &fingerprintDataSource{})
}

const fakeFingerprint = "2f:f2:f7:e9:8b:a5:62:fe:bb:6d:63:40:33:8b:4a:97:e6:d4:80:5d:f9:96:b9:63:ee:4c:08:31:c2:d0:00:5c"

func TestFingerprintDataSourceReadsTheProxyCertificate(t *testing.T) {
	fake := newFakePBS()
	d := &fingerprintDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, `{"data":[
		{"filename":"proxy.key","fingerprint":"aa"},
		{"filename":"proxy.pem","fingerprint":"2F:F2:F7:E9:8B:A5:62:FE:BB:6D:63:40:33:8B:4A:97:E6:D4:80:5D:F9:96:B9:63:EE:4C:08:31:C2:D0:00:5C",
		 "subject":"OU=PBS Ephemeral, O=Proxmox Backup Server, CN=pbs-acc","issuer":"OU=PBS Ephemeral, O=Proxmox Backup Server, CN=pbs-acc",
		 "notbefore":1761562800,"notafter":2076922800,"san":["pbs-acc","localhost"]}]}`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"fingerprint": fakeFingerprint,
		"subject":     "OU=PBS Ephemeral, O=Proxmox Backup Server, CN=pbs-acc",
		"issuer":      "OU=PBS Ephemeral, O=Proxmox Backup Server, CN=pbs-acc",
		"not_before":  "2025-10-27T11:00:00Z",
		"not_after":   "2035-10-25T11:00:00Z",
		"san":         []string{"pbs-acc", "localhost"},
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

func TestFingerprintDataSourceWithoutSAN(t *testing.T) {
	fake := newFakePBS()
	d := &fingerprintDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, `{"data":[{"filename":"proxy.pem","fingerprint":"`+fakeFingerprint+`","subject":"CN=x","issuer":"CN=x"}]}`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{"fingerprint": fakeFingerprint, "subject": "CN=x", "issuer": "CN=x", "san": []string{}})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// A token without Sys.Modify gets 403, and the error says what is missing.
func TestFingerprintDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &fingerprintDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, certificatesPrivilege)
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// --- acceptance --------------------------------------------------------------

// The fingerprint must be the one the port actually serves, which the
// provider pins when PBS_TLS_FINGERPRINT is set.
func TestAccFingerprintDataSource(t *testing.T) {
	var checks []acc.TestCheckFunc
	checks = append(checks,
		acc.TestMatchResourceAttr("data.pbs_fingerprint.this", "fingerprint", regexp.MustCompile(`^([0-9a-f]{2}:){31}[0-9a-f]{2}$`)),
		acc.TestCheckResourceAttrSet("data.pbs_fingerprint.this", "not_after"),
	)
	if pinned := os.Getenv(envCertFingerprint); pinned != "" {
		normalised, err := pbsclient.NormaliseFingerprint(pinned)
		if err != nil {
			t.Fatal(err)
		}
		checks = append(checks, acc.TestCheckResourceAttr("data.pbs_fingerprint.this", "fingerprint", pbsclient.FormatFingerprint(normalised)))
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config: providerConfig + `
data "pbs_fingerprint" "this" {}
`,
				Check: acc.ComposeAggregateTestCheckFunc(append(checks, testAccCheckFingerprintMatchesTheServer("data.pbs_fingerprint.this"))...),
			},
		},
	})
}

// testAccCheckFingerprintMatchesTheServer connects to the server pinned to
// the fingerprint the data source reported, which fails unless it is the
// certificate the port serves.
func testAccCheckFingerprintMatchesTheServer(name string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s not found in state", name)
		}
		client, err := testAccClient()
		if err != nil {
			return err
		}
		opts := pbsclient.Options{
			Endpoint:        client.BaseURL(),
			APIToken:        os.Getenv(envAPIToken),
			CertFingerprint: rs.Primary.Attributes["fingerprint"],
		}
		pinned, err := pbsclient.New(opts)
		if err != nil {
			return err
		}
		if _, err := pinned.ServerVersion(context.Background()); err != nil {
			return fmt.Errorf("connecting pinned to the reported fingerprint: %w", err)
		}
		return nil
	}
}
