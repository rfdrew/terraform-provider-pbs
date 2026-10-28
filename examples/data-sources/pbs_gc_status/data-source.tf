# A warning in every plan when the last garbage collection of store1 failed.
# Read inside the check block, a datastore PBS cannot read — a removable one
# that is not mounted, say — is a warning too, rather than an error.
check "store1_gc" {
  data "pbs_gc_status" "store1" {
    store = "store1"
  }

  assert {
    condition     = coalesce(data.pbs_gc_status.store1.last_run_state, "OK") == "OK"
    error_message = "The last garbage collection of store1 ended with: ${coalesce(data.pbs_gc_status.store1.last_run_state, "-")}"
  }
}
