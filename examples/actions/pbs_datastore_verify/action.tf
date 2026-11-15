terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# Verify every backup of a namespace again, verified before or not, such as
# after moving the datastore's disks. Nothing triggers it; run it with
# terraform apply -invoke=action.pbs_datastore_verify.dept1
action "pbs_datastore_verify" "dept1" {
  config {
    store           = "store1"
    ns              = "dept1"
    ignore_verified = false
    # Reading every chunk of a big namespace takes hours.
    timeout = "6h"
  }
}

# Verify the backups of one VM that were not verified in the last 30 days, as
# Verify All in the web interface does by default. Without outdated_after, PBS
# skips a backup verified once for good.
action "pbs_datastore_verify" "vm100" {
  config {
    store          = "store1"
    group          = "vm/100"
    outdated_after = 30
  }
}

# Verify one backup, as its Verify button in the web interface does; the time
# is in UTC, as `proxmox-backup-client snapshot list` shows it.
action "pbs_datastore_verify" "before_restore" {
  config {
    store    = "store1"
    snapshot = "vm/100/2026-11-14T02:00:05Z"
  }
}
