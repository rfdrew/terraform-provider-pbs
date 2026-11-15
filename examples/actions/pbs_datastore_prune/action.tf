terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# The retention of the daily prune job, assumed in the same configuration.
# Preview what pruning store1 with it now would remove, without removing
# anything:
# terraform apply -invoke=action.pbs_datastore_prune.preview
action "pbs_datastore_prune" "preview" {
  config {
    store   = pbs_prune_job.daily.store
    keep    = pbs_prune_job.daily.keep
    dry_run = true
  }
}

# Prune namespace dept1 to the last three backups of each guest when input
# changes, then start a garbage collection. It frees only the chunks that no
# backup has used for longer than the datastore's tuning.gc_atime_cutoff,
# 24 hours and 5 minutes by default: those the prune released are mostly
# reported as pending removal, and a later garbage collection frees them.
resource "terraform_data" "shrink_dept1" {
  input = "2026-11"

  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.pbs_datastore_prune.dept1, action.pbs_datastore_gc.store1]
    }
  }
}

action "pbs_datastore_prune" "dept1" {
  config {
    store = "store1"
    ns    = "dept1"
    keep  = { last = 3 }
  }
}

action "pbs_datastore_gc" "store1" {
  config {
    store = "store1"
    wait  = false
  }
}
