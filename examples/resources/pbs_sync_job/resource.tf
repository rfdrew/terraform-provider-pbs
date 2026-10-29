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

# A push to a PBS someone else runs, set up outside Terraform as the remote
# hosted, which is to hold the backups encrypted (PBS 4.2+): the job
# encrypts the backups it copies with the key of the pbs_sync_encryption_key
# example, which never leaves this server. Backups a client encrypted already
# are copied as they are. When active_encryption_key changes, PBS keeps the
# key before in associated_key, so that the key the remote's backups need
# cannot be deleted by mistake.
resource "pbs_sync_job" "hosted" {
  id                    = "push-hosted"
  sync_direction        = "push"
  store                 = pbs_datastore.store1.name
  remote                = "hosted"
  remote_store          = "customer1"
  schedule              = "sun 02:00"
  active_encryption_key = pbs_sync_encryption_key.hosted.id
}
