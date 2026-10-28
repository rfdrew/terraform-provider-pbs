data "pbs_prune_jobs" "all" {}

# Warn about prune jobs that someone disabled: their datastores keep every
# backup until the disk is full.
check "no_prune_job_is_disabled" {
  assert {
    condition     = alltrue([for j in data.pbs_prune_jobs.all.jobs : !j.disable])
    error_message = "Disabled prune jobs: ${join(", ", [for j in data.pbs_prune_jobs.all.jobs : j.id if j.disable])}."
  }
}
