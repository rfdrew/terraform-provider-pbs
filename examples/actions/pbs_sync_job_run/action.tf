terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# A nightly push of store1 to the remote offsite. The first copy runs as soon
# as the job exists, rather than at 21:00. Run it again at any time with:
# terraform apply -invoke=action.pbs_sync_job_run.offsite
resource "pbs_sync_job" "offsite" {
  id             = "push-offsite"
  sync_direction = "push"
  store          = "store1"
  remote         = "offsite"
  remote_store   = "offsite1"
  schedule       = "21:00"

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.pbs_sync_job_run.offsite]
    }
  }
}

action "pbs_sync_job_run" "offsite" {
  config {
    id = pbs_sync_job.offsite.id
    # The first copy sends every backup: wait for it up to an hour, and report
    # what it copied. Should it take longer, the action, and with it the
    # apply, fails while the sync goes on in PBS; for a first copy that takes
    # hours, set wait = false instead.
    timeout = "1h"
  }
}
