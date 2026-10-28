# The push jobs of store1: where its backups are copied to.
data "pbs_sync_jobs" "store1_pushes" {
  store          = "store1"
  sync_direction = "push"
}

output "store1_copies" {
  value = [for j in data.pbs_sync_jobs.store1_pushes.jobs : "${j.remote}:${j.remote_store}"]
}
