package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	acc "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestDisksDataSourceSchemaIsValid(t *testing.T) {
	requireValidDataSourceSchema(t, &disksDataSource{})
}

// testDisksSMARTJSON is what PBS 4.2.8 answers with include-partitions=1 and
// SMART for a host installed on an NVMe disk, with a spare SATA SSD, a ZFS
// disk SMART finds failing and a USB disk: the disks sorted by name, their
// partitions in no order, every optional property sent, as null when PBS
// does not know it.
const testDisksSMARTJSON = `{"data":[
 {"name":"nvme0n1","used":"mounted","disk-type":"ssd","status":"passed","wearout":97.0,"vendor":null,
  "model":"Samsung SSD 980 PRO 1TB","wwn":"eui.002538b311a2c3d4","size":1000204886016,"serial":"S5GXNF0R123456","partitions":[
   {"name":"nvme0n1p3","used":"lvm","mounted":false,"filesystem":null,"devpath":"/dev/nvme0n1p3","size":999129049088,"gpt":true,"uuid":null},
   {"name":"nvme0n1p1","used":"bios","mounted":false,"filesystem":null,"devpath":"/dev/nvme0n1p1","size":1031168,"gpt":true,"uuid":null},
   {"name":"nvme0n1p2","used":"efi","mounted":true,"filesystem":null,"devpath":"/dev/nvme0n1p2","size":1073741824,"gpt":true,"uuid":null}],
  "devpath":"/dev/nvme0n1","gpt":true,"rpm":null},
 {"name":"sda","used":"unused","disk-type":"ssd","status":"passed","wearout":100.0,"vendor":"ATA","model":"Samsung_SSD_870_EVO_1TB",
  "wwn":"0x5002538f42a1b2c3","size":1000204886016,"serial":"S6PNNS0T123456A","partitions":[],"devpath":"/dev/sda","gpt":false,"rpm":0},
 {"name":"sdb","used":"zfs","disk-type":"hdd","status":"failed","wearout":null,"vendor":"ATA","model":"WDC_WD40EFRX-68N32N0",
  "wwn":"0x50014ee2b5c4d3e2","size":4000787030016,"serial":"WD-WCC7K1234567","partitions":[
   {"name":"sdb9","used":"zfsreserved","mounted":false,"filesystem":null,"devpath":"/dev/sdb9","size":8388608,"gpt":true,"uuid":null},
   {"name":"sdb1","used":"zfs","mounted":false,"filesystem":null,"devpath":"/dev/sdb1","size":4000776716288,"gpt":true,"uuid":null}],
  "devpath":"/dev/sdb","gpt":true,"rpm":5400},
 {"name":"sdc","used":"partitions","disk-type":"hdd","status":"unknown","wearout":null,"vendor":"WD","model":"Elements_25A2",
  "wwn":null,"size":2000398934016,"serial":"575833314131","partitions":[
   {"name":"sdc1","used":"filesystem","mounted":false,"filesystem":"ext4","devpath":"/dev/sdc1","size":2000397795328,"gpt":true,
    "uuid":"6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"}],
  "devpath":"/dev/sdc","gpt":true,"rpm":null}]}`

func TestDisksDataSourceReadsTheDisks(t *testing.T) {
	const route = "GET /nodes/localhost/disks/list"
	fake := newFakePBS()
	d := &disksDataSource{data: fake.configured(t)}
	fake.reply(route, http.StatusOK, testDisksSMARTJSON)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{"smart": true, "include_partitions": true}))
	requireNoErrors(t, resp.Diagnostics)
	// SMART is PBS's default: only the partitions are asked for.
	if got, want := fake.lastCall(t, route).query, (url.Values{"include-partitions": {"1"}}); !reflect.DeepEqual(got, want) {
		t.Errorf("query = %v, want %v", got, want)
	}
	partition := func(name, used string, mounted bool, size int64) map[string]any {
		return map[string]any{"name": name, "devpath": "/dev/" + name, "used": used, "mounted": mounted, "size": size, "gpt": true}
	}
	want := dataSourceValue(t, d, map[string]any{
		"node":               "localhost",
		"smart":              true,
		"include_partitions": true,
		"disks": []any{
			map[string]any{
				"name": "nvme0n1", "devpath": "/dev/nvme0n1", "used": "mounted", "disk_type": "ssd", "size": 1000204886016,
				"model": "Samsung SSD 980 PRO 1TB", "serial": "S5GXNF0R123456", "wwn": "eui.002538b311a2c3d4",
				"gpt": true, "health": "passed", "wearout": 97.0,
				"partitions": []any{
					partition("nvme0n1p1", "bios", false, 1031168),
					partition("nvme0n1p2", "efi", true, 1073741824),
					partition("nvme0n1p3", "lvm", false, 999129049088),
				},
			},
			map[string]any{
				"name": "sda", "devpath": "/dev/sda", "used": "unused", "disk_type": "ssd", "size": 1000204886016,
				"vendor": "ATA", "model": "Samsung_SSD_870_EVO_1TB", "serial": "S6PNNS0T123456A", "wwn": "0x5002538f42a1b2c3",
				"rpm": 0, "gpt": false, "health": "passed", "wearout": 100.0, "partitions": []any{},
			},
			map[string]any{
				"name": "sdb", "devpath": "/dev/sdb", "used": "zfs", "disk_type": "hdd", "size": 4000787030016,
				"vendor": "ATA", "model": "WDC_WD40EFRX-68N32N0", "serial": "WD-WCC7K1234567", "wwn": "0x50014ee2b5c4d3e2",
				"rpm": 5400, "gpt": true, "health": "failed",
				"partitions": []any{
					partition("sdb1", "zfs", false, 4000776716288),
					partition("sdb9", "zfsreserved", false, 8388608),
				},
			},
			map[string]any{
				"name": "sdc", "devpath": "/dev/sdc", "used": "partitions", "disk_type": "hdd", "size": 2000398934016,
				"vendor": "WD", "model": "Elements_25A2", "serial": "575833314131", "gpt": true, "health": "unknown",
				"partitions": []any{map[string]any{
					"name": "sdc1", "devpath": "/dev/sdc1", "used": "filesystem", "mounted": false, "filesystem": "ext4",
					"size": 2000397795328, "gpt": true, "uuid": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
				}},
			},
		},
	})
	if !resp.State.Raw.Equal(want) {
		t.Errorf("state = %s, want %s", resp.State.Raw, want)
	}
}

func TestDisksDataSourceEdgeCases(t *testing.T) {
	// Without smart, PBS is told to skip smartctl; no disks is an empty list.
	t.Run("no disks", func(t *testing.T) {
		const route = "GET /nodes/localhost/disks/list"
		fake := newFakePBS()
		d := &disksDataSource{data: fake.configured(t)}
		fake.reply(route, http.StatusOK, `{"data":[]}`)

		resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{"smart": false}))
		requireNoErrors(t, resp.Diagnostics)
		if got, want := fake.lastCall(t, route).query, (url.Values{"skipsmart": {"1"}}); !reflect.DeepEqual(got, want) {
			t.Errorf("query = %v, want %v", got, want)
		}
		want := dataSourceValue(t, d, map[string]any{"node": "localhost", "smart": false, "disks": []any{}})
		if !resp.State.Raw.Equal(want) {
			t.Errorf("state = %s, want %s", resp.State.Raw, want)
		}
	})

	// The disks and partitions come out of order; optional properties are
	// null, left out or empty; and a disk whose partitions PBS could not
	// read has null for them.
	t.Run("unsorted and unknown", func(t *testing.T) {
		const route = "GET /nodes/pbs1/disks/list"
		fake := newFakePBS()
		d := &disksDataSource{data: fake.configured(t)}
		fake.reply(route, http.StatusOK, `{"data":[
 {"name":"vdb","used":"partitions","disk-type":"hdd","status":"unknown","size":10737418240,"gpt":false},
 {"name":"sda","used":"partitions","disk-type":"unknown","status":"unknown","wearout":null,"vendor":"","model":null,"wwn":null,
  "size":34359738368,"serial":null,"partitions":[
   {"name":"sda10","used":"unused","mounted":false,"filesystem":null,"devpath":null,"size":null,"gpt":false,"uuid":null},
   {"name":"sda2","used":"unused","mounted":false,"gpt":false},
   {"name":"sda1","used":"unused","mounted":false,"filesystem":null,"devpath":"/dev/sda1","size":1048576,"gpt":false,"uuid":null}],
  "devpath":null,"gpt":false,"rpm":null}]}`)

		config := map[string]any{"node": "pbs1", "include_partitions": true, "usage_type": "partitions"}
		resp := readDataSource(t, d, dataSourceValue(t, d, config))
		requireNoErrors(t, resp.Diagnostics)
		wantQuery := url.Values{"skipsmart": {"1"}, "include-partitions": {"1"}, "usage-type": {"partitions"}}
		if got := fake.lastCall(t, route).query; !reflect.DeepEqual(got, wantQuery) {
			t.Errorf("query = %v, want %v", got, wantQuery)
		}
		unused := func(name string) map[string]any {
			return map[string]any{"name": name, "used": "unused", "mounted": false, "gpt": false}
		}
		sda1 := unused("sda1")
		sda1["devpath"], sda1["size"] = "/dev/sda1", 1048576
		want := dataSourceValue(t, d, map[string]any{
			"node": "pbs1", "include_partitions": true, "usage_type": "partitions",
			"disks": []any{
				map[string]any{
					"name": "sda", "used": "partitions", "disk_type": "unknown", "size": 34359738368, "gpt": false,
					"health": "unknown", "partitions": []any{sda1, unused("sda2"), unused("sda10")},
				},
				map[string]any{
					"name": "vdb", "used": "partitions", "disk_type": "hdd", "size": 10737418240, "gpt": false,
					"health": "unknown", "partitions": []any{},
				},
			},
		})
		if !resp.State.Raw.Equal(want) {
			t.Errorf("state = %s, want %s", resp.State.Raw, want)
		}
	})
}

// A token without Sys.Audit on /system/disks gets 403, and the error says
// what is missing.
func TestDisksDataSourceExplainsAMissingPrivilege(t *testing.T) {
	fake := newFakePBS()
	d := &disksDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/disks/list", http.StatusForbidden, "permission check failed")

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, "Unable to list the PBS disks")
	requireErrorContaining(t, resp.Diagnostics, disksReadPrivilege)
	requireErrorContaining(t, resp.Diagnostics, "An API token has no privileges of its own")
}

// PBS fails the whole list when a command it runs fails, such as pvs on a
// host without LVM's tools; the error is PBS's.
func TestDisksDataSourceReportsAFailedCommand(t *testing.T) {
	fake := newFakePBS()
	d := &disksDataSource{data: fake.configured(t)}
	fake.reply("GET /nodes/localhost/disks/list", http.StatusBadRequest,
		`failed to execute "pvs" "--reportformat" "json" "--noheadings" "--readonly" "-o" "pv_name" - No such file or directory (os error 2)`)

	resp := readDataSource(t, d, dataSourceValue(t, d, map[string]any{}))
	requireErrorContaining(t, resp.Diagnostics, `failed to execute "pvs"`)
}

// usage_type takes only the types PBS knows, which it would refuse anyway.
func TestDisksDataSourceRefusesAnUnknownUsageType(t *testing.T) {
	h := newProtocolHarness(t, newFakePBS())

	diags := dataSourceConfigDiagnostics(t, h, "pbs_disks", h.dataSourceValue(t, "pbs_disks", map[string]any{"usage_type": "ssd"}))
	requireProtocolErrorContaining(t, diags, "value must be one of")
}

// --- acceptance --------------------------------------------------------------

// testAccDiskName is the name of a disk PBS lists, testAccDiskSize a size.
var (
	testAccDiskName = regexp.MustCompile(`^(?:(?:(?:h|s|x?v)d[a-z]+)|(?:nvme\d+n\d+))$`)
	testAccDiskSize = regexp.MustCompile(`^[0-9]+$`)
)

// Every stand is a container, which may see the host's disks or none, and
// may lack udev's data, or the commands PBS runs to list disks: the test
// checks what holds for any disk, and skips when PBS cannot list them.
func TestAccDisksDataSource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC")
	}
	testAccPreCheck(t)
	client, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Disks(context.Background(), client.Node(), pbsclient.DiskListOptions{SkipSMART: true}); err != nil {
		// A failed lsblk or pvs, or a device PBS cannot inspect, fails the
		// whole list with 400; a parameter PBS refuses is the provider's
		// fault.
		var apiErr *pbsclient.Error
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest &&
			!strings.HasPrefix(apiErr.Message, "parameter verification failed") {
			t.Skipf("PBS cannot list the stand's disks: %v", err)
		}
		t.Fatal(err)
	}

	acc.Test(t, acc.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []acc.TestStep{
			{
				Config: providerConfig + `
data "pbs_disks" "all" {}
`,
				Check: acc.ComposeAggregateTestCheckFunc(
					acc.TestCheckResourceAttr("data.pbs_disks.all", "node", client.Node()),
					testAccCheckDisks("data.pbs_disks.all", false, ""),
				),
			},
			{
				Config: providerConfig + `
data "pbs_disks" "partitions" {
  include_partitions = true
}

data "pbs_disks" "unused" {
  usage_type = "unused"
}
`,
				Check: acc.ComposeAggregateTestCheckFunc(
					testAccCheckDisks("data.pbs_disks.partitions", true, ""),
					testAccCheckDisks("data.pbs_disks.unused", false, pbsclient.DiskUsageUnused),
				),
			},
		},
	})
}

// testAccCheckDisks checks what holds for every disk of a pbs_disks state
// read without smart: a name PBS lists, in order, a size, a usage type of
// usageType when it is set, health unknown and no wearout. With partitions,
// each partition is named after its disk, in partition order; without, a
// disk has none.
func testAccCheckDisks(name string, partitions bool, usageType string) acc.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s not found in state", name)
		}
		attrs := rs.Primary.Attributes
		count, err := strconv.Atoi(attrs["disks.#"])
		if err != nil {
			return fmt.Errorf("%s: disks.# = %q", name, attrs["disks.#"])
		}
		previous := ""
		for i := range count {
			disk := func(attr string) string { return attrs[fmt.Sprintf("disks.%d.%s", i, attr)] }
			diskName := disk("name")
			switch {
			case !testAccDiskName.MatchString(diskName):
				return fmt.Errorf("%s: disk %d is named %q", name, i, diskName)
			case diskName <= previous:
				return fmt.Errorf("%s: disk %q comes after %q", name, diskName, previous)
			case !testAccDiskSize.MatchString(disk("size")):
				return fmt.Errorf("%s: %s has size %q", name, diskName, disk("size"))
			case !slices.Contains(pbsclient.DiskUsageTypes, disk("used")) || (usageType != "" && disk("used") != usageType):
				return fmt.Errorf("%s: %s is used as %q", name, diskName, disk("used"))
			case disk("health") != "unknown" || disk("wearout") != "":
				return fmt.Errorf("%s: %s has health %q and wearout %q without smart", name, diskName, disk("health"), disk("wearout"))
			case !partitions && disk("partitions.#") != "0":
				return fmt.Errorf("%s: %s has %s partitions without include_partitions", name, diskName, disk("partitions.#"))
			}
			previous = diskName

			n, err := strconv.Atoi(disk("partitions.#"))
			if err != nil {
				return fmt.Errorf("%s: %s has partitions.# = %q", name, diskName, disk("partitions.#"))
			}
			previousPartition := ""
			for j := range n {
				partition := disk(fmt.Sprintf("partitions.%d.name", j))
				if !strings.HasPrefix(partition, diskName) || len(partition) == len(diskName) {
					return fmt.Errorf("%s: %s has partition %q", name, diskName, partition)
				}
				if len(partition) < len(previousPartition) ||
					(len(partition) == len(previousPartition) && partition <= previousPartition) {
					return fmt.Errorf("%s: partition %q comes after %q", name, partition, previousPartition)
				}
				previousPartition = partition
			}
		}
		return nil
	}
}
