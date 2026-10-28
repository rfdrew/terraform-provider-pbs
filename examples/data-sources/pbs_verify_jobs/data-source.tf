data "pbs_verify_jobs" "store1" {
  store = "store1"
}

# Every datastore should be verified on a schedule.
check "store1_is_verified" {
  assert {
    condition     = anytrue([for j in data.pbs_verify_jobs.store1.jobs : j.schedule != null])
    error_message = "No verify job checks the backups of store1 on a schedule."
  }
}
