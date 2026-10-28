data "pbs_prune_job" "store1" {
  id = "daily-store1"
}

output "store1_daily_backups_kept" {
  # keep is null for a job that sets no retention option.
  value = coalesce(try(data.pbs_prune_job.store1.keep.daily, null), 0)
}
