data "pbs_gc_status" "store1" {
  store = "store1"
}

# The end of the log of the last garbage collection of store1; there is
# none before its first run.
data "pbs_task" "store1_gc" {
  count = data.pbs_gc_status.store1.upid != null ? 1 : 0

  upid      = data.pbs_gc_status.store1.upid
  log_lines = 10
}

output "store1_gc_log" {
  value = one(data.pbs_task.store1_gc[*].log)
}
