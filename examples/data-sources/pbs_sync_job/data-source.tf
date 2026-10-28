data "pbs_sync_job" "offsite" {
  id = "push-offsite"
}

# The offsite copy only runs on a schedule; warn when someone removed it.
check "offsite_copy_is_scheduled" {
  assert {
    condition     = data.pbs_sync_job.offsite.schedule != null
    error_message = "Sync job push-offsite has no schedule, so no offsite copy is made."
  }
}
