# A warning in every plan when a PBS task failed in the last day, or PBS
# lost track of one. Without Sys.Audit on /system/tasks, PBS leaves out the
# tasks of others, such as scheduled jobs, which run as root@pam: the first
# assertion catches that.
check "pbs_failed_tasks" {
  data "pbs_tasks" "failed" {
    status = ["error", "unknown"]
    since  = timeadd(plantimestamp(), "-24h")
    limit  = 0
  }

  assert {
    condition     = data.pbs_tasks.failed.sees_all_tasks
    error_message = "The provider cannot see every PBS task: give it the Audit role on /system/tasks."
  }

  assert {
    condition = length(data.pbs_tasks.failed.tasks) == 0
    error_message = join("\n", concat(["PBS tasks failed in the last day:"], [
      for t in data.pbs_tasks.failed.tasks :
      "${t.start_time} ${t.worker_type} ${coalesce(t.worker_id, "-")}: ${t.exit_status}"
    ]))
  }
}

# The last verify job run on store1, if PBS still has one.
data "pbs_tasks" "store1_verify" {
  store       = "store1"
  worker_type = "verificationjob"
  limit       = 1
}

output "store1_last_verification" {
  value = one(data.pbs_tasks.store1_verify.tasks)
}

# How the runs of the sync job "offsite" in the last week ended: the worker
# ID of a sync job's task ends in ":<job>".
data "pbs_tasks" "syncs" {
  worker_type = "syncjob"
  since       = timeadd(plantimestamp(), "-168h")
  limit       = 0
}

output "offsite_sync_runs" {
  value = [
    for t in data.pbs_tasks.syncs.tasks : "${t.start_time}: ${t.status}"
    if endswith(coalesce(t.worker_id, "-"), ":offsite")
  ]
}
