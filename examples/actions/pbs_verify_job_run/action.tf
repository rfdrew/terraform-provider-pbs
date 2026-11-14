terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# A weekly verification of store1 whose first run starts as soon as the job
# exists. Run it again at any time with:
# terraform apply -invoke=action.pbs_verify_job_run.weekly
resource "pbs_verify_job" "weekly" {
  id             = "verify-weekly"
  store          = "store1"
  schedule       = "sat 03:00"
  outdated_after = 30

  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.pbs_verify_job_run.weekly]
    }
  }
}

action "pbs_verify_job_run" "weekly" {
  config {
    id = pbs_verify_job.weekly.id
    # Reading every chunk of a big datastore takes hours: start the run and
    # leave it to PBS, which sends its notification when it is done.
    wait = false
  }
}
