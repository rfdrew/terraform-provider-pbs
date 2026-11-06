data "pbs_disks" "unused" {
  usage_type = "unused"
}

# Disks free for a new datastore, such as ["/dev/sdb", "/dev/sdc"].
output "unused_disks" {
  value = [for d in data.pbs_disks.unused.disks : d.devpath]
}

# SMART health of every disk. PBS runs smartctl on each, which takes a while
# and wakes disks that are spun down.
data "pbs_disks" "smart" {
  smart = true
}

check "disks_are_healthy" {
  assert {
    condition     = alltrue([for d in data.pbs_disks.smart.disks : d.health != "failed"])
    error_message = "SMART reports failing disks: ${join(", ", [for d in data.pbs_disks.smart.disks : d.name if d.health == "failed"])}."
  }
}

# Disks with less than a fifth of their rated life left. HDDs report no
# wear; neither does an NVMe disk used beyond its rated life, which is listed
# too when SMART answered for it.
output "worn_disks" {
  value = [
    for d in data.pbs_disks.smart.disks : d.name
    if d.wearout != null ? d.wearout < 20 : startswith(d.name, "nvme") && d.health != "unknown"
  ]
}
