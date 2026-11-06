package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &disksDataSource{}
	_ datasource.DataSourceWithConfigure = &disksDataSource{}
)

// disksReadPrivilege is what listing a node's disks needs.
const disksReadPrivilege = "Sys.Audit on /system/disks"

// NewDisksDataSource returns the pbs_disks data source.
func NewDisksDataSource() datasource.DataSource { return &disksDataSource{} }

type disksDataSource struct {
	data *providerData
}

type disksDataSourceModel struct {
	Node              types.String    `tfsdk:"node"`
	IncludePartitions types.Bool      `tfsdk:"include_partitions"`
	SMART             types.Bool      `tfsdk:"smart"`
	UsageType         types.String    `tfsdk:"usage_type"`
	Disks             []diskDataModel `tfsdk:"disks"`
}

type diskDataModel struct {
	Name       types.String             `tfsdk:"name"`
	DevPath    types.String             `tfsdk:"devpath"`
	Used       types.String             `tfsdk:"used"`
	DiskType   types.String             `tfsdk:"disk_type"`
	Size       types.Int64              `tfsdk:"size"`
	Vendor     types.String             `tfsdk:"vendor"`
	Model      types.String             `tfsdk:"model"`
	Serial     types.String             `tfsdk:"serial"`
	WWN        types.String             `tfsdk:"wwn"`
	RPM        types.Int64              `tfsdk:"rpm"`
	GPT        types.Bool               `tfsdk:"gpt"`
	Health     types.String             `tfsdk:"health"`
	Wearout    types.Float64            `tfsdk:"wearout"`
	Partitions []diskPartitionDataModel `tfsdk:"partitions"`
}

type diskPartitionDataModel struct {
	Name       types.String `tfsdk:"name"`
	DevPath    types.String `tfsdk:"devpath"`
	Used       types.String `tfsdk:"used"`
	Mounted    types.Bool   `tfsdk:"mounted"`
	Filesystem types.String `tfsdk:"filesystem"`
	Size       types.Int64  `tfsdk:"size"`
	GPT        types.Bool   `tfsdk:"gpt"`
	UUID       types.String `tfsdk:"uuid"`
}

func (d *disksDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_disks"
}

func (d *disksDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	computedBool := func(description string) schema.BoolAttribute {
		return schema.BoolAttribute{Computed: true, MarkdownDescription: description}
	}
	computedInt64 := func(description string) schema.Int64Attribute {
		return schema.Int64Attribute{Computed: true, MarkdownDescription: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the disks of a Proxmox Backup Server node, as its interface shows them under " +
			"Storage / Disks: what each is used for, its size, model and serial number and, when asked for, its " +
			"SMART health and its partitions. PBS lists the whole disks the kernel names as SCSI, SATA, IDE, virtio " +
			"or Xen disks (`sda`, `hda`, `vda`, `xvda`) or as NVMe namespaces (`nvme0n1`); it leaves out loop, " +
			"device-mapper, software RAID (`md`) and SD card (`mmcblk`) devices, and iSCSI disks.\n\n" +
			"Needs `" + disksReadPrivilege + "`.\n\n" +
			"PBS runs `lsblk` and `pvs` to tell what the disks are used for, and reading fails when either does. " +
			"A PBS in a container lists the host's disks it sees in `/sys/block`; without udev's database " +
			"(`/run/udev`) it cannot tell their `model`, `serial`, `wwn` and `rpm`, which are null then, nor " +
			"their partition tables, so that `gpt` is `false`.",
		Attributes: map[string]schema.Attribute{
			"node": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Node to read: `localhost` or the node's host name. Defaults to the provider's `node`.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 63),
					stringvalidator.RegexMatches(nodeNamePattern, "must be a node name such as localhost or pbs1"),
				},
			},
			"include_partitions": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether to list the partitions of each disk in `partitions`. Defaults to `false`.",
			},
			"smart": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Whether to read the SMART data of the disks, for `health` and `wearout`. PBS then " +
					"runs `smartctl` on every disk, four at a time and without a timeout, which can take long with many " +
					"disks and wakes those that are spun down. Defaults to `false`, which leaves `health` `unknown` " +
					"and `wearout` null.",
			},
			"usage_type": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "List only the disks used so, as `used` names it: `unused`, `mounted`, `lvm`, " +
					"`zfs`, `devicemapper`, `partitions` or `filesystem`. Every disk when left out.",
				Validators: []validator.String{stringvalidator.OneOf(pbsclient.DiskUsageTypes...)},
			},
			"disks": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The disks, sorted by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":    computedString("Kernel name of the disk, such as `sda` or `nvme0n1`."),
					"devpath": computedString("Path of the disk's device node, such as `/dev/sda`; null when it has none."),
					"used": computedString("What PBS finds the disk used for: `mounted` (a file system on it or on " +
						"one of its partitions is mounted), `lvm` (it or a partition is an LVM physical volume), `zfs` " +
						"(it or a partition is in a ZFS pool), `devicemapper` (another device, such as a device-mapper " +
						"or software RAID device, is built on it or a partition), `partitions` (it has partitions, " +
						"none of them in use), `filesystem` (it holds a file system that is not mounted) or `unused`."),
					"disk_type": computedString("Kind of disk, as PBS guesses it: `ssd` or `hdd` by whether the kernel " +
						"reports it as rotational, which virtual disks often are; `usb` or `unknown` when the kernel " +
						"does not say."),
					"size":   computedInt64("Size of the disk, in bytes."),
					"vendor": computedString("Vendor of the disk, as the kernel reports it, such as `ATA` for a SATA disk; null when it reports none."),
					"model": computedString("Model of the disk, as udev reports it, such as `Samsung_SSD_870_EVO_1TB`; " +
						"null without udev's data."),
					"serial": computedString("Serial number of the disk, as udev reports it; null without udev's data."),
					"wwn": computedString("World Wide Name of the disk, as udev reports it, such as " +
						"`0x5002538f42a1b2c3`; null when the disk has none, and without udev's data."),
					"rpm": computedInt64("Rotation rate of an ATA disk, in revolutions per minute, as udev reports it: " +
						"`0` for one that does not rotate, such as an SSD. Null for other disks, and without udev's data."),
					"gpt": computedBool("Whether the disk has a GPT partition table, as udev reports it; `false` " +
						"without udev's data."),
					"health": computedString("SMART health of the disk, as `smartctl` reports it: `passed`, `failed` " +
						"or `unknown`. Always `unknown` without `smart`, and for a disk whose health `smartctl` cannot " +
						"read, such as most virtual disks."),
					"wearout": schema.Float64Attribute{
						Computed: true,
						MarkdownDescription: "Percentage of the disk's rated life left, from SMART: for an NVMe disk, 100 " +
							"minus the percentage used it reports; for an ATA disk, the normalised value of its wear " +
							"attribute, such as `Media_Wearout_Indicator`. Null without `smart`, for a disk that reports " +
							"no wear, such as most HDDs, and for an NVMe disk used beyond its rated life.",
					},
					"partitions": schema.ListNestedAttribute{
						Computed: true,
						MarkdownDescription: "The partitions of the disk, in partition order: `sda2` before `sda10`. " +
							"Empty without `include_partitions`.",
						NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
							"name": computedString("Kernel name of the partition, such as `sda1` or `nvme0n1p1`."),
							"devpath": computedString("Path of the partition's device node, such as `/dev/sda1`; null " +
								"when it has none."),
							"used": computedString("What PBS finds the partition used for: `lvm` (an LVM physical " +
								"volume), `zfs` (in a ZFS pool), `zfsreserved` (the reserved partition ZFS makes on a " +
								"whole disk), `efi` (an EFI system partition), `bios` (a BIOS boot partition), " +
								"`filesystem` (it holds a file system) or `unused`."),
							"mounted": computedBool("Whether a file system on the partition is mounted."),
							"filesystem": computedString("Type of the file system on the partition, as `lsblk` reports " +
								"it, such as `ext4`; null unless `used` is `filesystem`."),
							"size": computedInt64("Size of the partition, in bytes; null when PBS cannot read it."),
							"gpt":  computedBool("Whether udev reports a GPT partition table for the partition; `false` without udev's data."),
							"uuid": computedString("UUID of the file system on the partition, as `lsblk` reports it; " +
								"null when it has none, or one that is not in the usual UUID form, such as the volume " +
								"ID of a FAT file system."),
						}},
					},
				}},
			},
		},
	}
}

func (d *disksDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *disksDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config disksDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := config.Node.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	disks, err := d.data.client.Disks(ctx, node, pbsclient.DiskListOptions{
		SkipSMART:         !config.SMART.ValueBool(),
		IncludePartitions: config.IncludePartitions.ValueBool(),
		UsageType:         config.UsageType.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to list the PBS disks", apiErrorDetail(d.data.client, disksReadPrivilege, err))
		return
	}
	config.Node = types.StringValue(node)
	config.Disks = []diskDataModel{}
	for _, disk := range disks {
		m := diskDataModel{
			Name:       types.StringValue(disk.Name),
			DevPath:    optionalString(disk.DevPath),
			Used:       types.StringValue(disk.Used),
			DiskType:   types.StringValue(disk.DiskType),
			Size:       types.Int64Value(disk.Size),
			Vendor:     optionalString(disk.Vendor),
			Model:      optionalString(disk.Model),
			Serial:     optionalString(disk.Serial),
			WWN:        optionalString(disk.WWN),
			RPM:        int64OrNull(disk.RPM),
			GPT:        types.BoolValue(disk.GPT),
			Health:     types.StringValue(disk.Status),
			Wearout:    types.Float64PointerValue(disk.Wearout),
			Partitions: []diskPartitionDataModel{},
		}
		for _, p := range disk.Partitions {
			m.Partitions = append(m.Partitions, diskPartitionDataModel{
				Name:       types.StringValue(p.Name),
				DevPath:    optionalString(p.DevPath),
				Used:       types.StringValue(p.Used),
				Mounted:    types.BoolValue(p.Mounted),
				Filesystem: optionalString(p.Filesystem),
				Size:       int64OrNull(p.Size),
				GPT:        types.BoolValue(p.GPT),
				UUID:       optionalString(p.UUID),
			})
		}
		config.Disks = append(config.Disks, m)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// optionalString is *s, or null when PBS sends null or an empty string.
func optionalString(s *string) types.String {
	if s == nil {
		return types.StringNull()
	}
	return stringOrNull(*s)
}
