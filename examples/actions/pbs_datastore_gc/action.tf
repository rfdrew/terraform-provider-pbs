terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# Collect garbage now rather than at the datastore's next gc_schedule, such
# as when the datastore runs short of space:
# terraform apply -invoke=action.pbs_datastore_gc.store1
#
# It frees only the chunks that no backup has used for longer than the
# datastore's tuning.gc_atime_cutoff, 24 hours and 5 minutes by default.
# Chunks that a prune has just released are mostly reported as pending
# removal; a later garbage collection frees them.
action "pbs_datastore_gc" "store1" {
  config {
    store = "store1"
    # It reads every index of the datastore, which can take hours; with
    # wait = false the action only starts it.
    timeout = "4h"
  }
}

# Or keep such runs in the configuration: changing input runs the garbage
# collection at the next apply.
resource "terraform_data" "free_space" {
  input = "2026-11"

  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.pbs_datastore_gc.store1]
    }
  }
}
