package pbsclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// testDisksJSON is what PBS 4.2.8 answers with include-partitions=1, but
// with the disks out of order, which PBS sorts, as well as the partitions,
// which it does not. Every optional property is there, null when PBS does
// not know it, except on vdb, where they are left out; smartctl could not
// read the virtual disks.
const testDisksJSON = `{"data":[
 {"name":"sda","used":"mounted","disk-type":"hdd","status":"unknown","wearout":null,"vendor":"QEMU","model":"QEMU_HARDDISK",
  "wwn":null,"size":34359738368,"serial":"drive-scsi0","partitions":[
   {"name":"sda10","used":"filesystem","mounted":false,"filesystem":"xfs","devpath":"/dev/sda10","size":1048576,"gpt":true,
    "uuid":"0b6ad3c0-5d34-4a3b-9b8c-2f0e1d7c6a51"},
   {"name":"sda2","used":"efi","mounted":true,"filesystem":null,"devpath":"/dev/sda2","size":1073741824,"gpt":true,"uuid":null},
   {"name":"sda1","used":"bios","mounted":false,"filesystem":null,"devpath":"/dev/sda1","size":1031168,"gpt":true,"uuid":null}],
  "devpath":"/dev/sda","gpt":true,"rpm":null},
 {"name":"vdb","used":"unused","disk-type":"hdd","status":"unknown","size":10737418240,"gpt":false},
 {"name":"nvme0n1","used":"zfs","disk-type":"ssd","status":"passed","wearout":97.5,"vendor":null,"model":"Samsung SSD 980 PRO 1TB",
  "wwn":"eui.002538b311a2c3d4","size":1000204886016,"serial":"S5GXNF0R123456","partitions":[],"devpath":"/dev/nvme0n1",
  "gpt":true,"rpm":null}]}`

func TestDisksSortsDisksAndPartitions(t *testing.T) {
	const route = "GET /nodes/pbs1/disks/list"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, testDisksJSON)
	c := fake.client(t)

	disks, err := c.Disks(context.Background(), "pbs1", DiskListOptions{IncludePartitions: true})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range disks {
		names = append(names, d.Name)
	}
	if want := []string{"nvme0n1", "sda", "vdb"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("disks = %v, want %v", names, want)
	}
	var partitions []string
	for _, p := range disks[1].Partitions {
		partitions = append(partitions, p.Name)
	}
	if want := []string{"sda1", "sda2", "sda10"}; !reflect.DeepEqual(partitions, want) {
		t.Errorf("partitions = %v, want %v", partitions, want)
	}

	nvme := disks[0]
	if nvme.Wearout == nil || *nvme.Wearout != 97.5 || nvme.Vendor != nil || nvme.RPM != nil || nvme.Size != 1000204886016 ||
		nvme.Partitions == nil || len(nvme.Partitions) != 0 {
		t.Errorf("nvme0n1 = %+v", nvme)
	}
	if vdb := disks[2]; vdb.DevPath != nil || vdb.Model != nil || vdb.Wearout != nil || vdb.Partitions != nil {
		t.Errorf("vdb = %+v", vdb)
	}
	if efi := disks[1].Partitions[1]; efi.Used != "efi" || !efi.Mounted || efi.Filesystem != nil || efi.UUID != nil ||
		efi.Size == nil || *efi.Size != 1073741824 {
		t.Errorf("sda2 = %+v", efi)
	}
}

// Only what differs from PBS's defaults goes into the query: PBS runs
// smartctl unless told not to.
func TestDisksQueryParameters(t *testing.T) {
	const route = "GET /nodes/localhost/disks/list"
	fake := newFakePBS()
	fake.reply(route, http.StatusOK, `{"data":[]}`)
	c := fake.client(t)

	for _, tc := range []struct {
		opts DiskListOptions
		want url.Values
	}{
		{DiskListOptions{}, url.Values{}},
		{DiskListOptions{SkipSMART: true}, url.Values{"skipsmart": {"1"}}},
		{DiskListOptions{SkipSMART: true, IncludePartitions: true, UsageType: DiskUsageUnused},
			url.Values{"skipsmart": {"1"}, "include-partitions": {"1"}, "usage-type": {"unused"}}},
	} {
		disks, err := c.Disks(context.Background(), "localhost", tc.opts)
		if err != nil {
			t.Fatal(err)
		}
		if disks == nil || len(disks) != 0 {
			t.Errorf("%+v: disks = %#v, want an empty list", tc.opts, disks)
		}
		if got := fake.lastCall(t, route).query; !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%+v: query = %v, want %v", tc.opts, got, tc.want)
		}
	}
}
