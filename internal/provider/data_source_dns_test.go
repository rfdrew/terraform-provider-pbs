package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestDNSDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &dnsDataSource{})
}

// The data source reads /etc/resolv.conf as PBS does: the first domain of
// the last search or domain line, the first three nameservers; nothing is
// null for a file without them.
func TestDNSDataSourceReadsResolvConf(t *testing.T) {
	for _, tc := range []struct {
		name string
		// resolvConf is the file, nil for the fake's, as the installer
		// writes it.
		resolvConf *string
		want       map[string]any
	}{
		{
			name: "the installer's",
			want: map[string]any{"search": "example.org", "dns1": "192.0.2.53", "dns2": "192.0.2.54"},
		},
		{
			name: "domain then search, four nameservers",
			resolvConf: ptr("domain old.example\nsearch example.org example.net\nnameserver 192.0.2.53\n" +
				"nameserver 2001:db8::53\nnameserver 192.0.2.54\nnameserver 192.0.2.55\noptions rotate\n"),
			want: map[string]any{"search": "example.org", "dns1": "192.0.2.53", "dns2": "2001:db8::53", "dns3": "192.0.2.54"},
		},
		{
			name:       "comments only",
			resolvConf: ptr("# Nothing here\n"),
			want:       map[string]any{},
		},
		{
			name:       "empty",
			resolvConf: ptr(""),
			want:       map[string]any{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePBS()
			n := newFakeNode(fake)
			if tc.resolvConf != nil {
				n.mu.Lock()
				n.resolvConf = *tc.resolvConf
				n.mu.Unlock()
			}
			d := &dnsDataSource{data: fake.configured(t)}

			resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
			requireNoErrors(t, resp.Diagnostics)
			tc.want["node"] = "localhost"
			if want := dataSourceValue(t, d, tc.want); !resp.State.Raw.Equal(want) {
				t.Errorf("state = %s, want %s", resp.State.Raw, want)
			}
		})
	}
}

// Where Docker mounts /etc/resolv.conf, PBS cannot replace the file, but
// reads it all the same.
func TestDNSDataSourceReadsAMountedFile(t *testing.T) {
	fake := newFakePBS()
	n := newFakeNode(fake)
	n.mu.Lock()
	n.mounted = true
	n.mu.Unlock()
	d := &dnsDataSource{data: fake.configured(t)}

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node": "localhost", "search": "example.org", "dns1": "192.0.2.53", "dns2": "192.0.2.54",
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// A token without Sys.Audit on /system/network/dns gets 403, and the error
// says what is missing; a node without the file fails with PBS's own text.
func TestDNSDataSourceErrors(t *testing.T) {
	fake := newFakePBS()
	d := &dnsDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/dns", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "Unable to read the DNS settings of the PBS node")
	requireErrorContaining(t, resp.Diagnostics, "Sys.Audit on /system/network/dns")
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")

	const missing = `unable to read "/etc/resolv.conf" - No such file or directory (os error 2)`
	fake.reply("GET /nodes/localhost/dns", http.StatusBadRequest, missing)
	resp = readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, missing)
	for _, e := range resp.Diagnostics.Errors() {
		if strings.Contains(e.Detail(), "lacks the privilege") {
			t.Errorf("error %q blames a privilege", e.Detail())
		}
	}
}

// Read the way Terraform reads it, through the protocol, on the node the
// configuration names; node takes only a node name.
func TestDNSDataSourceThroughTheProtocol(t *testing.T) {
	fake := newFakePBS()
	newFakeNode(fake)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_dns", h.dataSourceValue(t, "pbs_dns", map[string]any{"node": "localhost"}))
	if stringAt(t, state, "node") != "localhost" || stringAt(t, state, "search") != "example.org" ||
		stringAt(t, state, "dns1") != "192.0.2.53" || !isNullAt(t, state, "dns3") {
		t.Fatalf("state = %s", state)
	}

	diags := dataSourceConfigDiagnostics(t, h, "pbs_dns", h.dataSourceValue(t, "pbs_dns", map[string]any{"node": "pbs_1"}))
	requireProtocolErrorContaining(t, diags, "must be a node name")
}

// --- acceptance --------------------------------------------------------------

// Reading changes nothing, so the test runs on every stand, where Docker
// mounts /etc/resolv.conf too, and compares the data source with what PBS
// answers when the check runs.
func TestAccDNSDataSource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	const name = "data.pbs_dns.this"
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config: providerConfig + `
data "pbs_dns" "this" {}
`,
				Check: func(s *terraform.State) error {
					client, err := testAccClient()
					if err != nil {
						return err
					}
					dns, err := client.GetDNS(context.Background(), client.Node())
					if err != nil {
						return err
					}
					checks := []acc.TestCheckFunc{acc.TestCheckResourceAttr(name, "node", client.Node())}
					for attribute, value := range map[string]string{
						"search": dns.Search, "dns1": dns.DNS1, "dns2": dns.DNS2, "dns3": dns.DNS3,
					} {
						if value == "" {
							checks = append(checks, acc.TestCheckNoResourceAttr(name, attribute))
						} else {
							checks = append(checks, acc.TestCheckResourceAttr(name, attribute, value))
						}
					}
					if err := acc.ComposeAggregateTestCheckFunc(checks...)(s); err != nil {
						return fmt.Errorf("PBS reads %+v: %w", dns, err)
					}
					return nil
				},
			},
		},
	})
}
