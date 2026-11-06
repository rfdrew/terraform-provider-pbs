package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

var (
	_ datasource.DataSource              = &nodeStatusDataSource{}
	_ datasource.DataSourceWithConfigure = &nodeStatusDataSource{}
)

// nodeStatusPrivilege is what reading a node's status needs.
const nodeStatusPrivilege = "Sys.Audit on /system/status"

// NewNodeStatusDataSource returns the pbs_node_status data source.
func NewNodeStatusDataSource() datasource.DataSource { return &nodeStatusDataSource{} }

type nodeStatusDataSource struct {
	data *providerData
}

type nodeStatusDataSourceModel struct {
	Node          types.String           `tfsdk:"node"`
	Memory        nodeStatusMemoryModel  `tfsdk:"memory"`
	Swap          nodeStatusMemoryModel  `tfsdk:"swap"`
	Root          nodeStatusRootModel    `tfsdk:"root"`
	Uptime        types.Int64            `tfsdk:"uptime"`
	LoadAverage   types.List             `tfsdk:"load_average"`
	CPU           types.Float64          `tfsdk:"cpu"`
	IOWait        types.Float64          `tfsdk:"io_wait"`
	KernelVersion types.String           `tfsdk:"kernel_version"`
	Kernel        nodeStatusKernelModel  `tfsdk:"kernel"`
	CPUInfo       nodeStatusCPUInfoModel `tfsdk:"cpu_info"`
	Fingerprint   types.String           `tfsdk:"fingerprint"`
	BootMode      types.String           `tfsdk:"boot_mode"`
	SecureBoot    types.Bool             `tfsdk:"secure_boot"`
}

type nodeStatusMemoryModel struct {
	Total types.Int64 `tfsdk:"total"`
	Used  types.Int64 `tfsdk:"used"`
	Free  types.Int64 `tfsdk:"free"`
}

type nodeStatusRootModel struct {
	Total types.Int64 `tfsdk:"total"`
	Used  types.Int64 `tfsdk:"used"`
	Avail types.Int64 `tfsdk:"avail"`
}

type nodeStatusKernelModel struct {
	Sysname types.String `tfsdk:"sysname"`
	Release types.String `tfsdk:"release"`
	Version types.String `tfsdk:"version"`
	Machine types.String `tfsdk:"machine"`
}

type nodeStatusCPUInfoModel struct {
	Model   types.String `tfsdk:"model"`
	Sockets types.Int64  `tfsdk:"sockets"`
	CPUs    types.Int64  `tfsdk:"cpus"`
}

func (d *nodeStatusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node_status"
}

func (d *nodeStatusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	byteFigure := func(description string) schema.Int64Attribute {
		return schema.Int64Attribute{Computed: true, MarkdownDescription: description}
	}
	computedString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Computed: true, MarkdownDescription: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads how a Proxmox Backup Server node is doing: its memory, swap and root file " +
			"system, its load and CPU use, its uptime, kernel and CPUs, how it booted, and the fingerprint of its " +
			"certificate. The figures are those of the moment Terraform reads the data source, so most of them " +
			"change from one plan to the next.\n\n" +
			"In a container, PBS sees the host's `/proc` and kernel: `memory`, `swap`, `load_average`, `cpu`, " +
			"`io_wait`, `uptime`, `kernel` and `cpu_info` are the host's, unless the container uses lxcfs, while " +
			"`root` is the container's own root file system.\n\n" +
			"Needs `" + nodeStatusPrivilege + "`.",
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
			"memory": schema.SingleNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Memory of the node, from `/proc/meminfo`.",
				Attributes: map[string]schema.Attribute{
					"total": byteFigure("Total memory, in bytes."),
					"used": byteFigure("Memory in use, in bytes: `total` minus the memory the kernel reports as " +
						"available (`MemAvailable`), so cache the kernel can free does not count."),
					"free": byteFigure("Memory not used at all, not even as cache, in bytes (`MemFree`). It is usually " +
						"less than `total` minus `used`."),
				},
			},
			"swap": schema.SingleNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Swap space of the node, from `/proc/meminfo`; all `0` without swap.",
				Attributes: map[string]schema.Attribute{
					"total": byteFigure("Total swap space, in bytes."),
					"used":  byteFigure("Swap space in use, in bytes: `total` minus `free`."),
					"free":  byteFigure("Free swap space, in bytes."),
				},
			},
			"root": schema.SingleNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The root file system, `/`, as `statfs` reports it.",
				Attributes: map[string]schema.Attribute{
					"total": byteFigure("Size of the file system, in bytes."),
					"used":  byteFigure("Bytes in use on the file system."),
					"avail": byteFigure("Bytes free for users other than root: the blocks the file system " +
						"reserves for root do not count, so it may be less than `total` minus `used`."),
				},
			},
			"uptime": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "How long the node has been up, in seconds.",
			},
			"load_average": schema.ListAttribute{
				Computed:    true,
				ElementType: types.Float64Type,
				MarkdownDescription: "Load average over the last 1, 5 and 15 minutes, in that order: the average " +
					"number of processes running, waiting for a CPU or waiting in uninterruptible sleep, usually " +
					"for I/O.",
			},
			"cpu": schema.Float64Attribute{
				Computed: true,
				MarkdownDescription: "Fraction of CPU time in use, from `0` to `1` (not a percentage), over " +
					"roughly the last 1 to 10 seconds: PBS compares the kernel's CPU counters with its previous " +
					"sample of them, which it takes at least every 10 seconds. Null if PBS reports no number.",
			},
			"io_wait": schema.Float64Attribute{
				Computed: true,
				MarkdownDescription: "Fraction of CPU time spent idle waiting for I/O, from `0` to `1`, over the " +
					"same period as `cpu`. Null if PBS reports no number.",
			},
			"kernel_version": computedString("The running kernel as one string, `<sysname> <release> <version>`, " +
				"such as `Linux 6.14.11-4-pve #1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (...)`."),
			"kernel": schema.SingleNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The running kernel, as `uname` reports it.",
				Attributes: map[string]schema.Attribute{
					"sysname": computedString("Name of the operating system, `Linux`; not the host name."),
					"release": computedString("Kernel release, such as `6.14.11-4-pve`."),
					"version": computedString("Kernel build, such as `#1 SMP PREEMPT_DYNAMIC PMX 6.14.11-4 (...)`."),
					"machine": computedString("Hardware architecture, such as `x86_64` or `aarch64`."),
				},
			},
			"cpu_info": schema.SingleNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The node's CPUs, from `/proc/cpuinfo`.",
				Attributes: map[string]schema.Attribute{
					"model": computedString("CPU model, such as `Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz`; null " +
						"when `/proc/cpuinfo` names none, as on ARM."),
					"sockets": schema.Int64Attribute{
						Computed: true,
						MarkdownDescription: "Number of CPU sockets; `0` when `/proc/cpuinfo` does not tell, as " +
							"on ARM.",
					},
					"cpus": schema.Int64Attribute{
						Computed:            true,
						MarkdownDescription: "Number of logical CPUs, hyper-threads included.",
					},
				},
			},
			"fingerprint": computedString("SHA-256 fingerprint of the certificate the server's web interface and " +
				"API serve on port 8007 (`proxy.pem`): 32 lower-case hexadecimal pairs separated by colons. It is " +
				"the same as the `fingerprint` of `pbs_fingerprint`, which needs `" + certificatesPrivilege + "`, " +
				"where this data source needs only `" + nodeStatusPrivilege + "`."),
			"boot_mode": computedString("How the node booted: `efi` or `legacy-bios`. Docker hides the firmware " +
				"from its containers by default, so PBS in Docker normally reports `legacy-bios` whatever the host " +
				"booted with."),
			"secure_boot": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the node booted with UEFI Secure Boot on; always `false` with `legacy-bios`.",
			},
		},
	}
}

func (d *nodeStatusDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *nodeStatusDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var configured types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("node"), &configured)...)
	if resp.Diagnostics.HasError() {
		return
	}
	node := configured.ValueString()
	if node == "" {
		node = d.data.client.Node()
	}
	status, err := d.data.client.NodeStatus(ctx, node)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read the PBS node status", apiErrorDetail(d.data.client, nodeStatusPrivilege, err))
		return
	}

	// As pbs_fingerprint does: PBS sends the fingerprint in this form
	// already, and formatting it again keeps the two attributes equal should
	// a release change the case or separators.
	fingerprint := status.Info.Fingerprint
	if normalised, err := pbsclient.NormaliseFingerprint(fingerprint); err == nil {
		fingerprint = pbsclient.FormatFingerprint(normalised)
	}

	loads := status.LoadAvg
	if loads == nil {
		loads = []float64{}
	}
	loadAverage, diags := types.ListValueFrom(ctx, types.Float64Type, loads)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &nodeStatusDataSourceModel{
		Node: types.StringValue(node),
		Memory: nodeStatusMemoryModel{
			Total: types.Int64Value(status.Memory.Total),
			Used:  types.Int64Value(status.Memory.Used),
			Free:  types.Int64Value(status.Memory.Free),
		},
		Swap: nodeStatusMemoryModel{
			Total: types.Int64Value(status.Swap.Total),
			Used:  types.Int64Value(status.Swap.Used),
			Free:  types.Int64Value(status.Swap.Free),
		},
		Root: nodeStatusRootModel{
			Total: types.Int64Value(status.Root.Total),
			Used:  types.Int64Value(status.Root.Used),
			Avail: types.Int64Value(status.Root.Avail),
		},
		Uptime:        types.Int64Value(status.Uptime),
		LoadAverage:   loadAverage,
		CPU:           types.Float64PointerValue(status.CPU),
		IOWait:        types.Float64PointerValue(status.Wait),
		KernelVersion: stringOrNull(status.KVersion),
		Kernel: nodeStatusKernelModel{
			Sysname: stringOrNull(status.CurrentKernel.Sysname),
			Release: stringOrNull(status.CurrentKernel.Release),
			Version: stringOrNull(status.CurrentKernel.Version),
			Machine: stringOrNull(status.CurrentKernel.Machine),
		},
		CPUInfo: nodeStatusCPUInfoModel{
			Model:   stringOrNull(status.CPUInfo.Model),
			Sockets: types.Int64Value(status.CPUInfo.Sockets),
			CPUs:    types.Int64Value(status.CPUInfo.CPUs),
		},
		Fingerprint: stringOrNull(fingerprint),
		BootMode:    stringOrNull(status.BootInfo.Mode),
		SecureBoot:  types.BoolValue(status.BootInfo.SecureBoot),
	})...)
}
