terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# The removable datastore offsite of the pbs_datastore example, on a USB disk
# that is taken offsite and brought back every week, and store1 of that
# example, both assumed in the same configuration. When the disk is plugged
# back in, PBS mounts the datastore by itself, copies the backups of store1
# onto it, and unmounts it when the copy is done.
resource "pbs_sync_job" "offsite" {
  id              = "offsite-copy"
  store           = pbs_datastore.offsite.name
  remote_store    = pbs_datastore.store1.name
  run_on_mount    = true
  unmount_on_done = true
}

# To copy the newest backups once more before the disk leaves, while it is
# still plugged in, change var.last_copy: that mounts the datastore again,
# which starts the copy. Or mount it yourself:
# terraform apply -invoke=action.pbs_datastore_mount.offsite
resource "terraform_data" "last_copy" {
  input = var.last_copy

  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.pbs_datastore_mount.offsite]
    }
  }
}

action "pbs_datastore_mount" "offsite" {
  config {
    store = pbs_datastore.offsite.name
  }
}

variable "last_copy" {
  description = "Day of the last copy before the disk leaves, such as 2026-11-14."
  type        = string
}
