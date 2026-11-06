package pbsclient

import (
	"cmp"
	"context"
	"net/url"
	"slices"
)

// The disks of a node are the block devices PBS can put datastores on. What
// PBS 4.0 and 4.2 do when listing them, read in their source
// (src/api2/node/disks/mod.rs, src/tools/disks/mod.rs and smart.rs):
//
//   - GET /nodes/{node}/disks/list lists the whole disks in /sys/block
//     named as SCSI, SATA, IDE, virtio and Xen disks are (sda, hda, vda,
//     xvda) or as NVMe namespaces (nvme0n1): never loop, device-mapper, md,
//     mmcblk, zram or nbd devices, and no iSCSI disks. It needs Sys.Audit on
//     /system/disks, and runs as root in the API daemon. A PBS in a
//     container sees the host's /sys/block.
//   - It runs lsblk and pvs to tell what the disks are used for, and fails
//     with 400 and the command's error — such as `failed to execute "pvs"
//     ... - No such file or directory (os error 2)` — when either is missing
//     or fails. A failing zpool is ignored.
//   - Unless skipsmart is set, it also runs smartctl on every disk, four at
//     a time and without a timeout, which can take long with many disks and
//     wakes those that are spun down. A disk smartctl fails on keeps status
//     "unknown" and no wearout; with skipsmart, every disk does.
//   - include-partitions fills partitions, which is null otherwise, in no
//     particular order. usage-type keeps the disks whose used is that type.
//   - Disks come sorted by name. Every optional property is sent, as null
//     when PBS does not know it. Model, serial number, WWN, rotation rate
//     and partition table come from udev's database: a PBS without it, as in
//     a container without /run/udev, knows none of them.

// What a disk is used for, as Disk.Used and DiskListOptions.UsageType name
// it.
const (
	DiskUsageUnused       = "unused"
	DiskUsageMounted      = "mounted"
	DiskUsageLVM          = "lvm"
	DiskUsageZFS          = "zfs"
	DiskUsageDeviceMapper = "devicemapper"
	DiskUsagePartitions   = "partitions"
	DiskUsageFileSystem   = "filesystem"
)

// DiskUsageTypes are the usage types of a disk, in PBS's order.
var DiskUsageTypes = []string{
	DiskUsageUnused, DiskUsageMounted, DiskUsageLVM, DiskUsageZFS,
	DiskUsageDeviceMapper, DiskUsagePartitions, DiskUsageFileSystem,
}

// Disk is a disk as GET /nodes/{node}/disks/list lists it. PBS sends a
// property it does not know as null, which leaves its pointer nil.
type Disk struct {
	// Name is the kernel's name of the disk, such as "sda" or "nvme0n1".
	Name string `json:"name"`
	// DevPath is the device node, such as "/dev/sda".
	DevPath *string `json:"devpath"`
	// Used is one of the DiskUsage constants.
	Used string `json:"used"`
	// DiskType is "hdd", "ssd", "usb" or "unknown".
	DiskType string `json:"disk-type"`
	// Size is in bytes.
	Size int64 `json:"size"`
	// Vendor is the kernel's, from sysfs; Model, Serial, WWN and RPM are
	// udev's.
	Vendor *string `json:"vendor"`
	Model  *string `json:"model"`
	Serial *string `json:"serial"`
	WWN    *string `json:"wwn"`
	RPM    *int64  `json:"rpm"`
	// GPT is whether udev reports a GPT partition table.
	GPT bool `json:"gpt"`
	// Status is the SMART health, "passed", "failed" or "unknown": always
	// "unknown" with SkipSMART.
	Status string `json:"status"`
	// Wearout is the percentage of the disk's rated life left, from SMART;
	// nil with SkipSMART.
	Wearout *float64 `json:"wearout"`
	// Partitions is nil unless IncludePartitions asks for them.
	Partitions []DiskPartition `json:"partitions"`
}

// DiskPartition is a partition of a Disk.
type DiskPartition struct {
	// Name is the kernel's name of the partition, such as "sda1" or
	// "nvme0n1p1".
	Name    string  `json:"name"`
	DevPath *string `json:"devpath"`
	// Used is "unused", "lvm", "zfs", "zfsreserved", "efi", "bios" or
	// "filesystem".
	Used    string `json:"used"`
	Mounted bool   `json:"mounted"`
	// Filesystem is the file system type lsblk reports, set only when Used
	// is "filesystem".
	Filesystem *string `json:"filesystem"`
	// Size is in bytes.
	Size *int64 `json:"size"`
	GPT  bool   `json:"gpt"`
	// UUID is the file system's UUID lsblk reports, when it is in the usual
	// UUID form.
	UUID *string `json:"uuid"`
}

// DiskListOptions are what a disk list asks PBS for.
type DiskListOptions struct {
	// SkipSMART leaves smartctl out: Status is "unknown" and Wearout nil.
	SkipSMART bool
	// IncludePartitions fills Partitions.
	IncludePartitions bool
	// UsageType, one of the DiskUsage constants, lists only the disks used
	// so; every disk when empty.
	UsageType string
}

// params returns the query parameters of o, leaving out PBS's defaults.
func (o DiskListOptions) params() url.Values {
	params := url.Values{}
	if o.SkipSMART {
		params.Set("skipsmart", "1")
	}
	if o.IncludePartitions {
		params.Set("include-partitions", "1")
	}
	if o.UsageType != "" {
		params.Set("usage-type", o.UsageType)
	}
	return params
}

// Disks lists a node's disks, sorted by name, each with its partitions in
// partition order. It needs Sys.Audit on /system/disks.
func (c *Client) Disks(ctx context.Context, node string, opts DiskListOptions) ([]Disk, error) {
	var disks []Disk
	if _, err := c.Get(ctx, Path("nodes", node, "disks", "list"), opts.params(), &disks); err != nil {
		return nil, err
	}
	// PBS sorts the disks already, but its partitions come in hash map
	// order.
	slices.SortFunc(disks, func(a, b Disk) int { return cmp.Compare(a.Name, b.Name) })
	for i := range disks {
		slices.SortFunc(disks[i].Partitions, func(a, b DiskPartition) int { return comparePartitionNames(a.Name, b.Name) })
	}
	return disks, nil
}

// comparePartitionNames orders partition names shorter first, then by
// name. The partitions of a disk are named after it, with their number
// last, so that is partition order: sda2 before sda10.
func comparePartitionNames(a, b string) int {
	if c := cmp.Compare(len(a), len(b)); c != 0 {
		return c
	}
	return cmp.Compare(a, b)
}
