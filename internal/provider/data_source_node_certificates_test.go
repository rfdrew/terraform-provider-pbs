package provider

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestNodeCertificatesDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &nodeCertificatesDataSource{})
}

// The certificate PBS generates, as GET certificates/info reports it.
func TestNodeCertificatesDataSourceReadsTheProxyCertificate(t *testing.T) {
	fake := newFakePBS()
	d := &nodeCertificatesDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, `{"data":[{
		"filename":"proxy.pem",
		"subject":"O = Proxmox Backup Server, OU = 5D2C8E4F-3A1B-4C6D-9E0F-7A8B9C0D1E2F, CN = pbs1.example.com",
		"san":["localhost","pbs1","pbs1.example.com"],
		"issuer":"O = Proxmox Backup Server, OU = 5D2C8E4F-3A1B-4C6D-9E0F-7A8B9C0D1E2F, CN = pbs1.example.com",
		"notbefore":1761562800,
		"notafter":33297562800,
		"pem":"-----BEGIN CERTIFICATE-----\nMIIF4TCCA8mgAwIBAgIUQm9ndXMgdGVzdCBjZXJ0aWZpY2F0ZTAN\n-----END CERTIFICATE-----\n",
		"public-key-type":"rsaEncryption",
		"public-key-bits":4096,
		"fingerprint":"2F:F2:F7:E9:8B:A5:62:FE:BB:6D:63:40:33:8B:4A:97:E6:D4:80:5D:F9:96:B9:63:EE:4C:08:31:C2:D0:00:5C"
	}]}`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node": "localhost",
		"certificates": []map[string]any{{
			"filename":        "proxy.pem",
			"fingerprint":     fakeFingerprint,
			"subject":         "O = Proxmox Backup Server, OU = 5D2C8E4F-3A1B-4C6D-9E0F-7A8B9C0D1E2F, CN = pbs1.example.com",
			"issuer":          "O = Proxmox Backup Server, OU = 5D2C8E4F-3A1B-4C6D-9E0F-7A8B9C0D1E2F, CN = pbs1.example.com",
			"not_before":      "2025-10-27T11:00:00Z",
			"not_after":       "3025-02-27T11:00:00Z",
			"san":             []string{"localhost", "pbs1", "pbs1.example.com"},
			"pem":             "-----BEGIN CERTIFICATE-----\nMIIF4TCCA8mgAwIBAgIUQm9ndXMgdGVzdCBjZXJ0aWZpY2F0ZTAN\n-----END CERTIFICATE-----\n",
			"public_key_type": "rsaEncryption",
			"public_key_bits": 4096,
		}},
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// A node the configuration names is the one read, here with an ACME
// certificate: an elliptic-curve key, and the chain after the certificate.
func TestNodeCertificatesDataSourceReadsTheNamedNode(t *testing.T) {
	fake := newFakePBS()
	d := &nodeCertificatesDataSource{data: fake.configured(t)}
	const pem = "-----BEGIN CERTIFICATE-----\nMIIDnzCCAyWgAwIBAgISBg==\n-----END CERTIFICATE-----\n" +
		"-----BEGIN CERTIFICATE-----\nMIIEVzCCAj+gAwIBAgIRAIOPbGPOsTmMYgZigxXJ/d4w\n-----END CERTIFICATE-----\n"
	fake.reply("GET /nodes/pbs1/certificates/info", http.StatusOK, `{"data":[{
		"filename":"proxy.pem","subject":"CN = pbs.example.com","san":["pbs.example.com"],
		"issuer":"C = US, O = Let's Encrypt, CN = E6","notbefore":1777363200,"notafter":1785139200,
		"pem":`+strconv.Quote(pem)+`,"public-key-type":"id-ecPublicKey","public-key-bits":256,"fingerprint":"`+fakeFingerprint+`"}]}`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{"node": "pbs1"}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node": "pbs1",
		"certificates": []map[string]any{{
			"filename":        "proxy.pem",
			"fingerprint":     fakeFingerprint,
			"subject":         "CN = pbs.example.com",
			"issuer":          "C = US, O = Let's Encrypt, CN = E6",
			"not_before":      "2026-04-28T08:00:00Z",
			"not_after":       "2026-07-27T08:00:00Z",
			"san":             []string{"pbs.example.com"},
			"pem":             pem,
			"public_key_type": "id-ecPublicKey",
			"public_key_bits": 256,
		}},
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// What PBS may leave out or send as null is null, a missing list of names
// is empty, and certificates come ordered by file name whatever PBS's order.
func TestNodeCertificatesDataSourceEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want []map[string]any
	}{
		{name: "no certificates", body: `{"data":[]}`, want: []map[string]any{}},
		{name: "null list", body: `{"data":null}`, want: []map[string]any{}},
		{
			name: "optional properties missing",
			body: `{"data":[{"filename":"proxy.pem","subject":"CN = x","issuer":"CN = x","public-key-type":"<unsupported key type>"}]}`,
			want: []map[string]any{{
				"filename": "proxy.pem", "subject": "CN = x", "issuer": "CN = x", "san": []string{},
				"public_key_type": "<unsupported key type>",
			}},
		},
		{
			name: "optional properties null",
			body: `{"data":[{"filename":"proxy.pem","subject":"CN = x","issuer":"CN = x","san":null,"notbefore":null,
				"notafter":null,"pem":null,"public-key-type":"rsaEncryption","public-key-bits":null,"fingerprint":null}]}`,
			want: []map[string]any{{
				"filename": "proxy.pem", "subject": "CN = x", "issuer": "CN = x", "san": []string{},
				"public_key_type": "rsaEncryption",
			}},
		},
		{
			name: "unsorted",
			body: `{"data":[
				{"filename":"proxy.pem","subject":"CN = b","issuer":"CN = b","san":[],"public-key-type":"rsaEncryption","public-key-bits":4096},
				{"filename":"custom.pem","subject":"CN = a","issuer":"CN = a","san":[],"public-key-type":"rsaEncryption","public-key-bits":2048}]}`,
			want: []map[string]any{
				{
					"filename": "custom.pem", "subject": "CN = a", "issuer": "CN = a", "san": []string{},
					"public_key_type": "rsaEncryption", "public_key_bits": 2048,
				},
				{
					"filename": "proxy.pem", "subject": "CN = b", "issuer": "CN = b", "san": []string{},
					"public_key_type": "rsaEncryption", "public_key_bits": 4096,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			d := &nodeCertificatesDataSource{data: fake.configured(t)}
			fake.reply("GET /nodes/localhost/certificates/info", http.StatusOK, tc.body)

			resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
			requireNoErrors(t, resp.Diagnostics)
			want := dataSourceValue(t, d, map[string]any{"node": "localhost", "certificates": tc.want})
			if !resp.State.Raw.Equal(want) {
				t.Errorf("state = %s, want %s", resp.State.Raw, want)
			}
		})
	}
}

// A token without Sys.Modify — an Audit one, say — gets 403, and the error
// says what is missing.
func TestNodeCertificatesDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &nodeCertificatesDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/certificates/info", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, certificatesPrivilege)
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// --- acceptance --------------------------------------------------------------

// The stand's certificate — the one PBS generated, or one the stand put in
// its place — checked for what holds for any certificate, and against
// pbs_fingerprint, which reads the same file.
func TestAccNodeCertificatesDataSource(t *testing.T) {
	if os.Getenv("TF_ACC") != "" {
		testAccPreCheck(t)
		client, err := testAccClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Certificates(context.Background()); pbsclient.IsForbidden(err) {
			t.Skip("the acceptance token lacks " + certificatesPrivilege + ", which reading the certificates needs")
		}
	}
	const name = "data.pbs_node_certificates.this"
	rfc3339 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{{
			Config: providerConfig + `
data "pbs_node_certificates" "this" {}

data "pbs_fingerprint" "this" {}
`,
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttrSet(name, "node"),
				acc.TestCheckResourceAttr(name, "certificates.#", "1"),
				acc.TestCheckResourceAttr(name, "certificates.0.filename", pbsclient.ProxyCertificateFile),
				acc.TestMatchResourceAttr(name, "certificates.0.fingerprint", regexp.MustCompile(`^([0-9a-f]{2}:){31}[0-9a-f]{2}$`)),
				acc.TestCheckResourceAttrPair(name, "certificates.0.fingerprint", "data.pbs_fingerprint.this", "fingerprint"),
				acc.TestCheckResourceAttrPair(name, "certificates.0.subject", "data.pbs_fingerprint.this", "subject"),
				acc.TestCheckResourceAttrSet(name, "certificates.0.issuer"),
				acc.TestMatchResourceAttr(name, "certificates.0.not_before", rfc3339),
				acc.TestMatchResourceAttr(name, "certificates.0.not_after", rfc3339),
				acc.TestCheckResourceAttrSet(name, "certificates.0.san.#"),
				acc.TestMatchResourceAttr(name, "certificates.0.pem", regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)),
				acc.TestCheckResourceAttrSet(name, "certificates.0.public_key_type"),
				acc.TestMatchResourceAttr(name, "certificates.0.public_key_bits", regexp.MustCompile(`^[1-9][0-9]*$`)),
			),
		}},
	})
}
