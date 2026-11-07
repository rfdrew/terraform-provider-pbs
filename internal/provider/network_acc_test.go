package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// The network tests change the network of the stand's container, which
// Pebble, the S3 server and slapd share, so they touch nothing but
// interfaces named tfacc* and the veth pairs scripts/bootstrap-test-pbs.sh
// makes for them (PBS_ACC_NETWORK_NICS, which PBS lists as physical), give
// them addresses from the documentation ranges, and put everything back
// when they end: what PBS applied is applied again without them, what is
// pending is dropped. Applying needs a stand where PBS can
// (PBS_ACC_NETWORK_RELOAD); creating interfaces needs root@pam, which only
// the packages stand has.
const (
	envAccNetworkNICs   = "PBS_ACC_NETWORK_NICS"
	envAccNetworkReload = "PBS_ACC_NETWORK_RELOAD"
)

// testAccNetworkNICs returns the stand's NICs for the network tests, or
// skips the test.
func testAccNetworkNICs(t *testing.T) []string {
	t.Helper()
	nics := strings.Split(os.Getenv(envAccNetworkNICs), ",")
	if len(nics) < 2 || nics[0] == "" {
		t.Skipf("%s does not name two NICs", envAccNetworkNICs)
	}
	return nics
}

// testAccNetworkReload reports whether PBS can apply network changes on the
// stand.
func testAccNetworkReload() bool { return os.Getenv(envAccNetworkReload) == "1" }

// testAccRootProvider returns a provider block that signs in as root@pam,
// or skips the test where the stand has none.
func testAccRootProvider(t *testing.T) string {
	t.Helper()
	username, password := os.Getenv(envAccAdminUsername), os.Getenv(envAccAdminPassword)
	if username != "root@pam" || password == "" {
		t.Skipf("creating network interfaces needs root@pam, and %s is %q", envAccAdminUsername, username)
	}
	return fmt.Sprintf("provider \"pbs\" {\n  username = %q\n  password = %q\n}\n", username, password)
}

// testAccNetworkAdmin returns a client that signs in as the stand's admin,
// for the cleanup.
func testAccNetworkAdmin(t *testing.T) *pbsclient.Client {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	testAccPreCheck(t)
	client, err := testAccClientAs(func(o *pbsclient.Options) {
		o.Username, o.Password = os.Getenv(envAccAdminUsername), os.Getenv(envAccAdminPassword)
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// testAccRestoreNetwork puts the stand's network back when the test ends:
// it deletes the interfaces of the given names — VLAN interfaces and
// bridges before the bonds they may use —, resets the NICs, and applies
// that where PBS can, or drops what is pending where it cannot.
func testAccRestoreNetwork(t *testing.T, client *pbsclient.Client, interfaces []string, nics []string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		node := client.Node()
		order := func(name string) int {
			switch iface, err := client.NetworkInterface(ctx, node, name); {
			case err != nil:
				return 3
			case iface.Type == networkTypeVLAN:
				return 0
			case iface.Type == networkTypeBridge:
				return 1
			default:
				return 2
			}
		}
		sorted := slices.Clone(interfaces)
		slices.SortStableFunc(sorted, func(a, b string) int { return order(a) - order(b) })
		for _, name := range sorted {
			if err := client.DeleteNetworkInterface(ctx, node, name, ""); err != nil && !pbsclient.IsNotFound(err) {
				t.Errorf("deleting %s: %v", name, err)
			}
		}
		for _, nic := range nics {
			params := map[string][]string{pbsclient.DeleteParam: {"autostart", "cidr", "cidr6", "comments", "comments6", "gateway", "gateway6", "method6", "mtu"}}
			if err := client.UpdateNetworkInterface(ctx, node, nic, params); err != nil && !pbsclient.IsNotFound(err) {
				t.Errorf("resetting %s: %v", nic, err)
			}
		}
		if !testAccNetworkReload() {
			if err := client.RevertNetwork(ctx, node); err != nil {
				t.Errorf("dropping the pending network changes: %v", err)
			}
			return
		}
		upid, err := client.ReloadNetwork(ctx, node)
		if err == nil {
			_, err = client.WaitTask(ctx, upid)
		}
		if err != nil {
			t.Errorf("applying the restored network: %v", err)
		}
		for _, nic := range nics {
			_ = exec.Command("docker", "exec", os.Getenv(envAccContainer), "ip", "link", "set", nic, "mtu", "1500").Run()
		}
	})
}

// testAccCheckNetworkPending checks whether changes are pending.
func testAccCheckNetworkPending(want bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		changes, err := client.NetworkChanges(context.Background(), client.Node())
		if err != nil {
			return err
		}
		if (changes != "") != want {
			return fmt.Errorf("pending changes = %q, want some: %v", changes, want)
		}
		return nil
	}
}

// testAccCheckNetworkConfigured checks whether the node's configuration —
// pending or running — has an interface.
func testAccCheckNetworkConfigured(name string, want bool) acc.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccClient()
		if err != nil {
			return err
		}
		_, err = client.NetworkInterface(context.Background(), client.Node(), name)
		switch {
		case pbsclient.IsNotFound(err):
			if want {
				return fmt.Errorf("%s is not configured", name)
			}
			return nil
		case err != nil:
			return err
		case !want:
			return fmt.Errorf("%s is still configured", name)
		}
		return nil
	}
}

// testAccCheckLink checks, in the stand's container, that a link exists with
// the given MTU and addresses, or that it does not exist when mtu is 0. It
// checks nothing where PBS cannot apply changes or Docker is out of reach.
func testAccCheckLink(name string, mtu int, addresses ...string) acc.TestCheckFunc {
	return func(*terraform.State) error {
		container := os.Getenv(envAccContainer)
		if !testAccNetworkReload() || container == "" {
			return nil
		}
		if _, err := exec.LookPath("docker"); err != nil {
			return nil
		}
		out, err := exec.Command("docker", "exec", container, "ip", "-j", "addr", "show", "dev", name).Output()
		if mtu == 0 {
			// ip says `Device "<name>" does not exist.`; any other failure
			// proves nothing.
			var exit *exec.ExitError
			if errors.As(err, &exit) && strings.Contains(string(exit.Stderr), "does not exist") {
				return nil
			}
			if err != nil {
				return fmt.Errorf("ip addr show dev %s: %v", name, err)
			}
			if strings.TrimSpace(string(out)) != "[]" {
				return fmt.Errorf("%s still exists: %s", name, out)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("ip addr show dev %s: %v", name, err)
		}
		var links []struct {
			MTU      int `json:"mtu"`
			AddrInfo []struct {
				Local     string `json:"local"`
				PrefixLen int    `json:"prefixlen"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal(out, &links); err != nil || len(links) != 1 {
			return fmt.Errorf("ip addr show dev %s: %s (%v)", name, out, err)
		}
		if links[0].MTU != mtu {
			return fmt.Errorf("%s has MTU %d, want %d", name, links[0].MTU, mtu)
		}
		var have []string
		for _, a := range links[0].AddrInfo {
			have = append(have, fmt.Sprintf("%s/%d", a.Local, a.PrefixLen))
		}
		for _, want := range addresses {
			if !slices.Contains(have, want) {
				return fmt.Errorf("%s has the addresses %v, not %s", name, have, want)
			}
		}
		return nil
	}
}

// A token cannot create an interface: PBS would refuse, and the plan says
// why.
func TestAccNetworkInterfaceCreateNeedsRootPam(t *testing.T) {
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNetworkConfigured("tfaccbr9", false),
		Steps: []acc.TestStep{{
			Config: providerConfig + `
resource "pbs_network_interface" "test" {
  name = "tfaccbr9"
  type = "bridge"
}
`,
			ExpectError: regexp.MustCompile(`Creating a network interface needs root@pam`),
		}},
	})
}

// A bond of the stand's NICs, a bridge on it and a VLAN interface on the
// bridge, applied together, changed, imported, and the VLAN interface
// removed again.
func TestAccNetworkInterfaceTopology(t *testing.T) {
	root := testAccRootProvider(t)
	nics := testAccNetworkNICs(t)
	client := testAccNetworkAdmin(t)
	testAccRestoreNetwork(t, client, []string{"tfaccbr0.20", "tfaccbr0", "tfaccbond0"}, nics)

	apply := func(names ...string) string {
		if !testAccNetworkReload() {
			return ""
		}
		var triggers []string
		for _, n := range names {
			triggers = append(triggers, fmt.Sprintf("    %s = jsonencode(pbs_network_interface.%s)", n, n))
		}
		return "\nresource \"pbs_network_apply\" \"this\" {\n  triggers = {\n" + strings.Join(triggers, "\n") + "\n  }\n}\n"
	}
	bond := func(mode, extra string) string {
		return fmt.Sprintf(`
resource "pbs_network_interface" "bond" {
  name      = "tfaccbond0"
  type      = "bond"
  slaves    = [%q, %q]
  bond_mode = %q
  %s
}
`, nics[0], nics[1], mode, extra)
	}
	bridge := func(comments, extra string) string {
		return fmt.Sprintf(`
resource "pbs_network_interface" "bridge" {
  name         = "tfaccbr0"
  type         = "bridge"
  bridge_ports = [pbs_network_interface.bond.name]
  cidr         = "198.51.100.2/24"
  mtu          = 1400
  comments     = %q
  %s
}
`, comments, extra)
	}
	vlan := func(cidr string) string {
		return fmt.Sprintf(`
resource "pbs_network_interface" "vlan" {
  name = "${pbs_network_interface.bridge.name}.20"
  type = "vlan"
  cidr = %q
}
`, cidr)
	}

	first := root + bond("active-backup", fmt.Sprintf("bond_primary = %q", nics[1])) +
		bridge("Terraform acceptance test\nsecond line", `cidr6 = "2001:db8:5100::2/64"`+"\n  bridge_vlan_aware = true") +
		vlan("203.0.113.2/24") + apply("bond", "bridge", "vlan")
	second := root + bond("802.3ad", `bond_xmit_hash_policy = "layer3+4"`) + bridge("Changed by Terraform", "") +
		vlan("203.0.113.3/24") + apply("bond", "bridge", "vlan")
	third := root + bond("802.3ad", `bond_xmit_hash_policy = "layer3+4"`) + bridge("Changed by Terraform", "") +
		apply("bond", "bridge")

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckNetworkConfigured("tfaccbr0.20", false),
			testAccCheckNetworkConfigured("tfaccbr0", false),
			testAccCheckNetworkConfigured("tfaccbond0", false),
		),
		Steps: []acc.TestStep{
			{
				Config: first,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_network_interface.bridge", "id", "localhost/tfaccbr0"),
					acc.TestCheckResourceAttr("pbs_network_interface.bridge", "method", "static"),
					acc.TestCheckResourceAttr("pbs_network_interface.bridge", "method6", "static"),
					acc.TestCheckResourceAttr("pbs_network_interface.bridge", "autostart", "true"),
					acc.TestCheckResourceAttr("pbs_network_interface.bond", "bond_primary", nics[1]),
					acc.TestCheckResourceAttr("pbs_network_interface.vlan", "method", "static"),
					acc.TestCheckNoResourceAttr("pbs_network_interface.vlan", "vlan_id"),
					testAccCheckNetworkPending(!testAccNetworkReload()),
					testAccCheckLink("tfaccbr0", 1400, "198.51.100.2/24", "2001:db8:5100::2/64"),
					testAccCheckLink("tfaccbr0.20", 1400, "203.0.113.2/24"),
				),
			},
			{
				Config: second,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_network_interface.bond", "bond_xmit_hash_policy", "layer3+4"),
					acc.TestCheckNoResourceAttr("pbs_network_interface.bond", "bond_primary"),
					acc.TestCheckResourceAttr("pbs_network_interface.bridge", "comments", "Changed by Terraform"),
					acc.TestCheckResourceAttr("pbs_network_interface.bridge", "method6", "manual"),
					acc.TestCheckResourceAttr("pbs_network_interface.bridge", "bridge_vlan_aware", "false"),
					testAccCheckNetworkPending(!testAccNetworkReload()),
					testAccCheckLink("tfaccbr0.20", 1400, "203.0.113.3/24"),
				),
			},
			{
				Config:            second,
				ResourceName:      "pbs_network_interface.bridge",
				ImportState:       true,
				ImportStateId:     "localhost/tfaccbr0",
				ImportStateVerify: true,
			},
			{
				// Removing the VLAN interface deletes it, then applies.
				Config: third,
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckNetworkConfigured("tfaccbr0.20", false),
					testAccCheckNetworkPending(!testAccNetworkReload()),
					testAccCheckLink("tfaccbr0.20", 0),
				),
			},
		},
	})
}

// Taking over a physical interface, which an API token may, applying it,
// and resetting it on destroy.
func TestAccNetworkInterfaceTakeOver(t *testing.T) {
	nics := testAccNetworkNICs(t)
	client := testAccNetworkAdmin(t)
	testAccRestoreNetwork(t, client, nil, nics)
	nic := nics[1]
	apply := ""
	if testAccNetworkReload() {
		apply = `
resource "pbs_network_apply" "this" {
  triggers = { nic = jsonencode(pbs_network_interface.nic) }
}
`
	}
	config := func(attributes string) string {
		return providerConfig + fmt.Sprintf(`
resource "pbs_network_interface" "nic" {
  name = %q
  type = "eth"
  %s
}
`, nic, attributes) + apply
	}
	first := config(`mtu = 1400
  cidr = "192.0.2.66/28"
  comments = "Taken over by Terraform"`)
	second := config(`mtu = 1450`)

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config: first,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_network_interface.nic", "type", "eth"),
					acc.TestCheckResourceAttr("pbs_network_interface.nic", "method", "static"),
					acc.TestCheckResourceAttr("pbs_network_interface.nic", "method6", "manual"),
					testAccCheckLink(nic, 1400, "192.0.2.66/28"),
				),
			},
			{
				Config: second,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("pbs_network_interface.nic", "method", "manual"),
					acc.TestCheckNoResourceAttr("pbs_network_interface.nic", "comments"),
					testAccCheckLink(nic, 1450),
				),
			},
			{
				Config:            second,
				ResourceName:      "pbs_network_interface.nic",
				ImportState:       true,
				ImportStateId:     "localhost/" + nic,
				ImportStateVerify: true,
			},
		},
		CheckDestroy: func(*terraform.State) error {
			iface, err := client.NetworkInterface(context.Background(), client.Node(), nic)
			if err != nil {
				return err
			}
			if iface.Autostart || iface.MTU != nil || iface.Comments != "" || iface.Method != "manual" {
				return fmt.Errorf("%s was not reset: %+v", nic, iface)
			}
			return nil
		},
	})
}

// Changes made outside Terraform show in the plan and are applied.
func TestAccNetworkApplyPendingChanges(t *testing.T) {
	nics := testAccNetworkNICs(t)
	if !testAccNetworkReload() {
		t.Skipf("%s is not set: PBS cannot apply network changes on this stand", envAccNetworkReload)
	}
	client := testAccNetworkAdmin(t)
	testAccRestoreNetwork(t, client, nil, nics)
	ctx := context.Background()
	stage := func(comment string) func() {
		return func() {
			params := map[string][]string{"comments": {comment}}
			if err := client.UpdateNetworkInterface(ctx, client.Node(), nics[0], params); err != nil {
				t.Fatalf("changing %s outside Terraform: %v", nics[0], err)
			}
		}
	}
	config := providerConfig + `
resource "pbs_network_apply" "this" {}
`
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				PreConfig: stage("pending before the apply"),
				Config:    config,
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckNetworkPending(false),
					acc.TestCheckNoResourceAttr("pbs_network_apply.this", "pending_changes"),
				),
			},
			{
				PreConfig:          stage("pending after the apply"),
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config,
				Check:  testAccCheckNetworkPending(false),
			},
		},
	})
}

func TestAccNetworkInterfaceImportByIdentity(t *testing.T) {
	nics := testAccNetworkNICs(t)
	client := testAccNetworkAdmin(t)
	testAccRestoreNetwork(t, client, nil, nics)
	config := providerConfig + fmt.Sprintf(`
resource "pbs_network_interface" "nic" {
  name     = %q
  type     = "eth"
  comments = "Imported by identity"
}
`, nics[0])
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_12_0)},
		Steps: []acc.TestStep{
			{Config: config},
			{Config: config, ResourceName: "pbs_network_interface.nic", ImportState: true, ImportStateKind: acc.ImportBlockWithResourceIdentity},
			{Config: config, ResourceName: "pbs_network_interface.nic", ImportState: true, ImportStateKind: acc.ImportBlockWithID},
		},
	})
}

// testAccPBSAtLeast reports whether the stand runs at least the given
// release, by PBS_ACC_VERSION; an unknown version counts as new enough.
func testAccPBSAtLeast(major, minor, release int) bool {
	line, patch, _ := strings.Cut(os.Getenv(envAccVersion), ".")
	minorText, releaseText, _ := strings.Cut(patch, ".")
	return pbsclient.Version{Version: line + "." + minorText, Release: releaseText}.AtLeast(major, minor, release)
}

// IPv6 settings and IPv4 DHCP, as PBS writes and reads them back; never
// applied, as the stand's network has no use for them.
func TestAccNetworkInterfaceMethods(t *testing.T) {
	root := testAccRootProvider(t)
	client := testAccNetworkAdmin(t)
	testAccRestoreNetwork(t, client, []string{"tfaccbr6", "tfaccbr7"}, nil)
	config := func(ipv6, dhcp string) string {
		return root + fmt.Sprintf(`
resource "pbs_network_interface" "v6" {
  name = "tfaccbr6"
  type = "bridge"
  %s
}

resource "pbs_network_interface" "dhcp" {
  name = "tfaccbr7"
  type = "bridge"
  %s
}
`, ipv6, dhcp)
	}
	staticV6 := `cidr6    = "2001:db8:5106::2/64"
  gateway6  = "2001:db8:5106::1"
  comments6 = "IPv6 side\nof tfaccbr6"`
	dhcp := `method   = "dhcp"
  comments = "changed"`
	steps := []acc.TestStep{
		{
			Config: config(staticV6, `method = "dhcp"`),
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr("pbs_network_interface.v6", "method", "manual"),
				acc.TestCheckResourceAttr("pbs_network_interface.v6", "method6", "static"),
				acc.TestCheckResourceAttr("pbs_network_interface.v6", "comments6", "IPv6 side\nof tfaccbr6"),
				acc.TestCheckResourceAttr("pbs_network_interface.dhcp", "method", "dhcp"),
				testAccCheckNetworkPending(true),
			),
		},
		{
			// PBS would turn DHCP into manual, so a change of an interface
			// whose configuration sets the method replaces it.
			Config: config(staticV6, dhcp),
			ConfigPlanChecks: acc.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("pbs_network_interface.dhcp", plancheck.ResourceActionDestroyBeforeCreate),
			}},
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr("pbs_network_interface.dhcp", "method", "dhcp"),
				acc.TestCheckResourceAttr("pbs_network_interface.dhcp", "comments", "changed"),
			),
		},
		{
			// With the method left out, the plan refuses the change.
			Config:      config(staticV6, `comments = "changed again"`),
			ExpectError: regexp.MustCompile(`PBS cannot change an interface with this IPv4 method`),
		},
	}
	imported := config(staticV6, dhcp)
	method6 := ""
	switch {
	case testAccPBSAtLeast(4, 2, 7):
		method6 = "auto"
	case testAccPBSAtLeast(4, 1, 7):
		method6 = "dhcp"
	}
	if method6 != "" {
		steps = append(steps, acc.TestStep{
			Config: config(fmt.Sprintf("method6 = %q", method6), dhcp),
			Check: acc.ComposeAggregateTestCheckFunc(
				acc.TestCheckResourceAttr("pbs_network_interface.v6", "method6", method6),
				acc.TestCheckNoResourceAttr("pbs_network_interface.v6", "cidr6"),
				acc.TestCheckNoResourceAttr("pbs_network_interface.v6", "comments6"),
			),
		}, acc.TestStep{
			// Keeping the method through a change needs PBS 4.1.7.
			Config: config(fmt.Sprintf("method6 = %q\n  mtu = 1400", method6), dhcp),
			Check:  acc.TestCheckResourceAttr("pbs_network_interface.v6", "method6", method6),
		})
		imported = config(fmt.Sprintf("method6 = %q\n  mtu = 1400", method6), dhcp)
	}
	steps = append(steps, acc.TestStep{
		Config:            imported,
		ResourceName:      "pbs_network_interface.v6",
		ImportState:       true,
		ImportStateId:     "localhost/tfaccbr6",
		ImportStateVerify: true,
	})
	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: acc.ComposeAggregateTestCheckFunc(
			testAccCheckNetworkConfigured("tfaccbr6", false),
			testAccCheckNetworkConfigured("tfaccbr7", false),
		),
		Steps: steps,
	})
}
