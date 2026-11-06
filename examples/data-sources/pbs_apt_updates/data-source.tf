data "pbs_apt_updates" "this" {}

# The versions of PBS's own packages an upgrade would install, such as
# { "proxmox-backup-server" = "4.2.8" }. The list is as current as the node's
# last apt update, which PBS's daily update runs.
locals {
  pbs_updates = {
    for u in data.pbs_apt_updates.this.updates : u.package => u.version
    if startswith(u.package, "proxmox-backup-")
  }
}

check "pbs_is_up_to_date" {
  assert {
    condition     = length(local.pbs_updates) == 0
    error_message = "PBS updates are available: ${jsonencode(local.pbs_updates)}."
  }
}

# Packages an upgrade would install anew, such as a new kernel.
output "new_packages" {
  value = [for u in data.pbs_apt_updates.this.updates : "${u.package} ${u.version}" if u.old_version == null]
}
