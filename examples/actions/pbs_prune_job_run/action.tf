terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# Apply new retention options at once, rather than at the next scheduled
# prune, then start a garbage collection. Or run the job yourself:
# terraform apply -invoke=action.pbs_prune_job_run.daily
resource "pbs_prune_job" "daily" {
  id       = "daily-store1"
  store    = "store1"
  schedule = "daily"

  keep = {
    daily  = 7
    weekly = 4
  }

  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.pbs_prune_job_run.daily, action.pbs_datastore_gc.store1]
    }
  }
}

action "pbs_prune_job_run" "daily" {
  config {
    id = pbs_prune_job.daily.id
  }
}

# Garbage collection right after the prune frees only the chunks that no
# backup has used for longer than the datastore's tuning.gc_atime_cutoff,
# 24 hours and 5 minutes by default: those the prune released are mostly
# reported as pending removal, and a later garbage collection frees them.
# It can take hours, so the action only starts it.
action "pbs_datastore_gc" "store1" {
  config {
    store = pbs_prune_job.daily.store
    wait  = false
  }
}
