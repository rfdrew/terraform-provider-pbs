package pbsclient

import "context"

// GET /nodes/{node}/status reports how a node is doing: its memory, swap and
// root file system, its load and CPU use, its kernel and CPUs, how it booted
// and the fingerprint of its certificate. What PBS 4.0 and 4.2 do, read in
// their source (src/api2/node/status.rs, pbs-api-types/src/node.rs,
// proxmox-sys/src/linux/procfs/mod.rs, proxmox-sys/src/boot_mode.rs):
//
//   - It needs Sys.Audit on /system/status, and reads only procfs, sysfs, one
//     statfs and the certificate; it changes nothing. The answer has had the
//     same shape since 2023, and every field is always there.
//   - Memory is in bytes from /proc/meminfo: used is MemTotal minus
//     MemAvailable, so cache the kernel can drop does not count, and free is
//     MemFree. Swap's used is its total minus its free.
//   - Root is statfs("/") in bytes: used is the blocks not free, avail the
//     blocks free for unprivileged users, which leaves out those reserved for
//     root, so avail may be less than total minus used.
//   - cpu and wait are fractions from 0 to 1, not percentages, of the CPU time
//     since an earlier sample of /proc/stat, kept per process. The proxy also
//     samples it every 10 seconds, and a sample less than a second old is
//     reused, so they cover roughly the last 1 to 10 seconds. A process's
//     first sample gives the average since boot for cpu and 0 for wait. A
//     fraction that is not a number would be sent as null.
//   - loadavg is the load average over 1, 5 and 15 minutes, in that order.
//   - kversion is "<sysname> <release> <version>" of uname, which
//     current-kernel has one by one; sysname is "Linux", not the host name.
//   - cpuinfo counts the "processor" lines of /proc/cpuinfo, hyper-threads
//     included, and the distinct "physical id"s as sockets, and takes the
//     "model name": without those lines, as on ARM, sockets is 0 and model
//     empty.
//   - info.fingerprint is the SHA-256 fingerprint of proxy.pem, as
//     colon-separated lower-case hex pairs: the same as the certificate's in
//     GET /nodes/{node}/certificates/info, which needs Sys.Modify. A
//     certificate PBS cannot load fails the call with "failed to load
//     certificate from ...".
//   - boot-info's mode is "efi" when /sys/firmware/efi exists and
//     "legacy-bios" otherwise, and secureboot is true only under EFI with
//     Secure Boot on; PBS reads them once per process. Docker hides
//     /sys/firmware, so a container of it should report legacy-bios whatever
//     the host booted with.
//   - In a container, /proc and uname are the host's: memory, swap, load, CPU
//     use, uptime, CPUs and kernel are the host's, unless lxcfs stands in for
//     /proc; root is the container's own root file system.
//   - PBS 4.0, built with proxmox-sys 1.0.0, fails the call with "unable to
//     get KSM pages_sharing - Permission denied (os error 13)" where it cannot
//     read /sys/kernel/mm/ksm/pages_sharing, as in some confined containers;
//     proxmox-sys 1.0.1 and later read it as 0. PBS does not report the value.

// NodeStatus is what GET /nodes/{node}/status reports.
type NodeStatus struct {
	Memory NodeStatusMemory `json:"memory"`
	Swap   NodeStatusMemory `json:"swap"`
	Root   NodeStatusRoot   `json:"root"`
	// Uptime is in seconds.
	Uptime int64 `json:"uptime"`
	// LoadAvg is the load average over 1, 5 and 15 minutes.
	LoadAvg []float64 `json:"loadavg"`
	// CPU is the fraction of CPU time in use lately, from 0 to 1; nil when
	// PBS sends null.
	CPU *float64 `json:"cpu"`
	// Wait is the fraction of CPU time spent waiting for I/O lately, from 0
	// to 1; nil when PBS sends null.
	Wait *float64 `json:"wait"`
	// KVersion is "<sysname> <release> <version>" of CurrentKernel.
	KVersion      string             `json:"kversion"`
	CurrentKernel NodeStatusKernel   `json:"current-kernel"`
	CPUInfo       NodeStatusCPUInfo  `json:"cpuinfo"`
	Info          NodeStatusInfo     `json:"info"`
	BootInfo      NodeStatusBootInfo `json:"boot-info"`
}

// NodeStatusMemory is memory or swap, in bytes.
type NodeStatusMemory struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
	Free  int64 `json:"free"`
}

// NodeStatusRoot is the root file system, in bytes.
type NodeStatusRoot struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
	Avail int64 `json:"avail"`
}

// NodeStatusKernel is the running kernel, as uname reports it.
type NodeStatusKernel struct {
	Sysname string `json:"sysname"`
	Release string `json:"release"`
	Version string `json:"version"`
	Machine string `json:"machine"`
}

// NodeStatusCPUInfo describes the CPUs, from /proc/cpuinfo.
type NodeStatusCPUInfo struct {
	// Model is empty when /proc/cpuinfo names none.
	Model string `json:"model"`
	// Sockets is 0 when /proc/cpuinfo has no physical IDs.
	Sockets int64 `json:"sockets"`
	// CPUs counts logical CPUs, hyper-threads included.
	CPUs int64 `json:"cpus"`
}

// NodeStatusInfo is general information on the node.
type NodeStatusInfo struct {
	// Fingerprint is the SHA-256 fingerprint of proxy.pem, as colon-separated
	// lower-case hex pairs.
	Fingerprint string `json:"fingerprint"`
}

// NodeStatusBootInfo is how the node booted.
type NodeStatusBootInfo struct {
	// Mode is "efi" or "legacy-bios".
	Mode       string `json:"mode"`
	SecureBoot bool   `json:"secureboot"`
}

// NodeStatus reads the status of a node. It needs Sys.Audit on
// /system/status.
func (c *Client) NodeStatus(ctx context.Context, node string) (NodeStatus, error) {
	var status NodeStatus
	if _, err := c.Get(ctx, Path("nodes", node, "status"), nil, &status); err != nil {
		return NodeStatus{}, err
	}
	return status, nil
}
