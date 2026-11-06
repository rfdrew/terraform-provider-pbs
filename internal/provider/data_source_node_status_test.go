package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestNodeStatusDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &nodeStatusDataSource{})
}

// testNodeStatusJSON is what PBS 4.2.8 answers on an EFI host without Secure
// Boot: every field, with the keys PBS uses, kebab-case among them.
const testNodeStatusJSON = `{"data":{"boot-info":{"mode":"efi","secureboot":false},"cpu":0.0213,
"cpuinfo":{"cpus":8,"model":"Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz","sockets":1},
"current-kernel":{"machine":"x86_64","release":"6.14.11-4-pve","sysname":"Linux","version":"#1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (2025-10-10T08:04Z)"},
"info":{"fingerprint":"` + fakeFingerprint + `"},
"kversion":"Linux 6.14.11-4-pve #1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (2025-10-10T08:04Z)",
"loadavg":[0.12,0.08,0.05],"memory":{"free":12884901888,"total":33395372032,"used":4294967296},
"root":{"avail":90194313216,"total":100861726720,"used":5523898368},
"swap":{"free":8589930496,"total":8589930496,"used":0},"uptime":1234567,"wait":0.0012}}`

func TestNodeStatusDataSourceReadsTheStatus(t *testing.T) {
	fake := newFakePBS()
	d := &nodeStatusDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/status", http.StatusOK, testNodeStatusJSON)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node":           "localhost",
		"memory":         map[string]any{"total": 33395372032, "used": 4294967296, "free": 12884901888},
		"swap":           map[string]any{"total": 8589930496, "used": 0, "free": 8589930496},
		"root":           map[string]any{"total": 100861726720, "used": 5523898368, "avail": 90194313216},
		"uptime":         1234567,
		"load_average":   []float64{0.12, 0.08, 0.05},
		"cpu":            0.0213,
		"io_wait":        0.0012,
		"kernel_version": "Linux 6.14.11-4-pve #1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (2025-10-10T08:04Z)",
		"kernel": map[string]any{
			"sysname": "Linux",
			"release": "6.14.11-4-pve",
			"version": "#1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (2025-10-10T08:04Z)",
			"machine": "x86_64",
		},
		"cpu_info":    map[string]any{"model": "Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz", "sockets": 1, "cpus": 8},
		"fingerprint": fakeFingerprint,
		"boot_mode":   "efi",
		"secure_boot": false,
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// The edges of the answer: another node, fractions PBS sends as null (NaN),
// an ARM host's /proc/cpuinfo without a model or physical IDs, no swap, a
// fingerprint in another form, a boot mode a later release might add, and no
// load average at all.
func TestNodeStatusDataSourceEdgeCases(t *testing.T) {
	fake := newFakePBS()
	d := &nodeStatusDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/pbs1/status", http.StatusOK, `{"data":{"boot-info":{"mode":"uefi-next","secureboot":true},
		"cpu":null,"wait":null,"cpuinfo":{"cpus":4,"model":"","sockets":0},
		"current-kernel":{"machine":"aarch64","release":"6.12.48+deb13-arm64","sysname":"Linux","version":"#1 SMP Debian 6.12.48-1 (2025-09-20)"},
		"info":{"fingerprint":"`+strings.ToUpper(fakeFingerprint)+`"},
		"kversion":"Linux 6.12.48+deb13-arm64 #1 SMP Debian 6.12.48-1 (2025-09-20)",
		"memory":{"free":1073741824,"total":8589934592,"used":2147483648},"root":{"avail":0,"total":0,"used":0},
		"swap":{"free":0,"total":0,"used":0},"uptime":42}}`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{"node": "pbs1"}))
	requireNoErrors(t, resp.Diagnostics)
	want := dataSourceValue(t, d, map[string]any{
		"node":           "pbs1",
		"memory":         map[string]any{"total": 8589934592, "used": 2147483648, "free": 1073741824},
		"swap":           map[string]any{"total": 0, "used": 0, "free": 0},
		"root":           map[string]any{"total": 0, "used": 0, "avail": 0},
		"uptime":         42,
		"load_average":   []float64{},
		"kernel_version": "Linux 6.12.48+deb13-arm64 #1 SMP Debian 6.12.48-1 (2025-09-20)",
		"kernel": map[string]any{
			"sysname": "Linux",
			"release": "6.12.48+deb13-arm64",
			"version": "#1 SMP Debian 6.12.48-1 (2025-09-20)",
			"machine": "aarch64",
		},
		"cpu_info":    map[string]any{"sockets": 0, "cpus": 4},
		"fingerprint": fakeFingerprint,
		"boot_mode":   "uefi-next",
		"secure_boot": true,
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

// Read the way Terraform reads it, through the protocol; node takes only a
// node name.
func TestNodeStatusDataSourceThroughTheProtocol(t *testing.T) {
	fake := newFakePBS()
	fake.reply("GET /nodes/localhost/status", http.StatusOK, testNodeStatusJSON)
	h := newProtocolHarness(t, fake)

	state := h.readDataSource(t, "pbs_node_status", h.dataSourceValue(t, "pbs_node_status", nil))
	if stringAt(t, state, "node") != "localhost" || int64At(t, state, "memory", "total") != 33395372032 ||
		int64At(t, state, "cpu_info", "cpus") != 8 || lengthAt(t, state, "load_average") != 3 {
		t.Fatalf("state = %s", state)
	}

	diags := dataSourceConfigDiagnostics(t, h, "pbs_node_status",
		h.dataSourceValue(t, "pbs_node_status", map[string]any{"node": "local host"}))
	requireProtocolErrorContaining(t, diags, "must be a node name")
}

// A token without Sys.Audit on /system/status gets 403, and the error says
// what is missing.
func TestNodeStatusDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &nodeStatusDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/status", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "Sys.Audit on /system/status")
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// --- acceptance --------------------------------------------------------------

// The status of the stand's node. Its figures change from one read to the
// next and differ from stand to stand — the packages run in a privileged
// container with systemd, the image in Docker, on whatever host and
// architecture — so the test checks that they are there and in range, and
// the fingerprint against the certificate's.
func TestAccNodeStatusDataSource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	testAccPreCheck(t)
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	// PBS 4.0 fails the call where it cannot read the kernel's KSM figures,
	// as in some confined containers: the stand cannot provide a status.
	if _, err := client.NodeStatus(context.Background(), client.Node()); err != nil {
		if strings.Contains(err.Error(), "unable to get KSM pages_sharing") {
			t.Skipf("the stand's PBS cannot read its node status: %v", err)
		}
		t.Fatalf("reading the node status: %v", err)
	}

	const name = "data.pbs_node_status.this"
	count := regexp.MustCompile(`^[0-9]+$`)
	positive := regexp.MustCompile(`^[1-9][0-9]*$`)
	checks := []acc.TestCheckFunc{
		acc.TestCheckResourceAttr(name, "node", client.Node()),
		acc.TestMatchResourceAttr(name, "memory.total", positive),
		acc.TestMatchResourceAttr(name, "root.total", positive),
		acc.TestMatchResourceAttr(name, "cpu_info.cpus", positive),
		acc.TestMatchResourceAttr(name, "cpu_info.sockets", count),
		acc.TestMatchResourceAttr(name, "uptime", count),
		acc.TestCheckResourceAttr(name, "load_average.#", "3"),
		acc.TestCheckResourceAttr(name, "kernel.sysname", "Linux"),
		acc.TestMatchResourceAttr(name, "kernel.release", regexp.MustCompile(`^[0-9]+\.[0-9]+`)),
		acc.TestMatchResourceAttr(name, "kernel.machine", regexp.MustCompile(`^\S+$`)),
		acc.TestCheckResourceAttrSet(name, "kernel.version"),
		acc.TestMatchResourceAttr(name, "kernel_version", regexp.MustCompile(`^Linux \S+ \S`)),
		acc.TestMatchResourceAttr(name, "fingerprint", regexp.MustCompile(`^([0-9a-f]{2}:){31}[0-9a-f]{2}$`)),
		acc.TestCheckResourceAttrPair(name, "fingerprint", "data.pbs_fingerprint.this", "fingerprint"),
		acc.TestMatchResourceAttr(name, "boot_mode", regexp.MustCompile(`^(efi|legacy-bios)$`)),
		acc.TestMatchResourceAttr(name, "secure_boot", regexp.MustCompile(`^(true|false)$`)),
		testAccCheckNodeStatusNumber(name, "cpu", 0, 1),
		testAccCheckNodeStatusNumber(name, "io_wait", 0, 1),
	}
	for _, figure := range []string{"memory.used", "memory.free", "swap.total", "swap.used", "swap.free", "root.used", "root.avail"} {
		checks = append(checks, acc.TestMatchResourceAttr(name, figure, count))
	}
	for i := range 3 {
		checks = append(checks, testAccCheckNodeStatusNumber(name, "load_average."+strconv.Itoa(i), 0, -1))
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{{
			Config: providerConfig + `
data "pbs_node_status" "this" {}

data "pbs_fingerprint" "this" {}
`,
			Check: acc.ComposeAggregateTestCheckFunc(checks...),
		}},
	})
}

// testAccCheckNodeStatusNumber checks that an attribute is a number from lo
// to hi, or from lo up when hi is negative.
func testAccCheckNodeStatusNumber(name, key string, lo, hi float64) acc.TestCheckFunc {
	return acc.TestCheckResourceAttrWith(name, key, func(value string) error {
		n, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("%s is not a number: %q", key, value)
		}
		if n < lo || (hi >= 0 && n > hi) {
			return fmt.Errorf("%s = %v is out of range", key, n)
		}
		return nil
	})
}
