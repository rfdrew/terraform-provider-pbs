# The retention of a datastore lives in its prune jobs. This one prunes
# pbs_datastore.store1, of the pbs_datastore example, assumed in the same
# configuration; referring to its name creates the job after the datastore.
resource "pbs_prune_job" "store1" {
  id       = "daily-store1"
  store    = pbs_datastore.store1.name
  schedule = "daily"
  comment  = "Retention of cluster1's backups"

  # In each backup group, the backups of one guest: the 3 most recent
  # backups, then the last backup of each of 7 more days, 4 more weeks and 6
  # more months. A backup one option keeps is not counted again by the next.
  keep = {
    last    = 3
    daily   = 7
    weekly  = 4
    monthly = 6
  }
}
