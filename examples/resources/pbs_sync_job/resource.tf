# Every night, push the backups of pbs_datastore.store1, of the pbs_datastore
# example, to the datastore offsite1 of pbs_remote.offsite, of the pbs_remote
# example, both assumed in the same configuration. Only backups the offsite
# copy lacks are sent, at most 50 MB per second. Retention offsite is the
# offsite server's own: a prune job there.
resource "pbs_sync_job" "offsite" {
  id             = "push-offsite"
  sync_direction = "push"
  store          = pbs_datastore.store1.name
  remote         = pbs_remote.offsite.name
  remote_store   = "offsite1"
  schedule       = "21:00"
  rate_out       = "50MB"
  comment        = "Offsite copy of cluster1's backups"
}

# Pull, the default direction, copies the other way: here, every Saturday,
# the backups of VMs in the offsite server's datastore archive, but for those
# of VM 100, into the namespace archive of store1, which the job creates. The
# remote's auth_id needs to read the archive datastore there, with the role
# DatastoreReader, say.
resource "pbs_sync_job" "archive" {
  id           = "pull-archive"
  store        = pbs_datastore.store1.name
  ns           = "archive"
  remote       = pbs_remote.offsite.name
  remote_store = "archive"
  schedule     = "sat 04:00"
  group_filter = ["type:vm", "exclude:group:vm/100"]
}
