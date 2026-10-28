# A weekly verification of pbs_datastore.store1, of the pbs_datastore
# example, assumed in the same configuration. Every Saturday at 03:00 it
# reads the backups that were never verified, or last verified more than 30
# days ago, and checks each chunk: ignore_verified, true by default, skips
# the others.
resource "pbs_verify_job" "store1" {
  id             = "verify-store1"
  store          = pbs_datastore.store1.name
  schedule       = "sat 03:00"
  outdated_after = 30
  comment        = "Weekly verification of cluster1's backups"

  # From PBS 4.1, read_threads and verify_threads set how many threads read
  # and check chunks; with PBS 4.0, the plan fails when they are set.
}
