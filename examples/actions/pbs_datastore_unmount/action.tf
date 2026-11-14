terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# The removable datastore offsite of the pbs_datastore example, assumed in
# the same configuration, whose disk is taken offsite once a week. Setting
# var.offsite_disk_leaves to the day it leaves unmounts it, after the garbage
# collection its gc_on_unmount runs first. Or unmount it yourself:
# terraform apply -invoke=action.pbs_datastore_unmount.offsite
resource "terraform_data" "offsite_departure" {
  input = var.offsite_disk_leaves

  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.pbs_datastore_unmount.offsite]
    }
  }
}

action "pbs_datastore_unmount" "offsite" {
  config {
    store = pbs_datastore.offsite.name

    # The unmount waits for the garbage collection and for every backup,
    # sync or verification that uses the datastore. Should they take longer,
    # the action asks PBS to stop the unmount, and the disk stays mounted.
    timeout = "2h"
  }
}

variable "offsite_disk_leaves" {
  description = "Day the offsite disk last left, such as 2026-11-14."
  type        = string
}
