# A datastore on a disk mounted at /mnt/datastore/store1 outside Terraform.
# PBS creates its chunk store in the directory, which must be empty, and the
# provider waits for that task to finish.
resource "pbs_datastore" "store1" {
  name    = "store1"
  path    = "/mnt/datastore/store1"
  comment = "Backups of cluster1"

  # Garbage collection frees the space of the backups a prune job removed.
  # Retention itself is not set here, but in a pbs_prune_job.
  gc_schedule = "daily"

  # The defaults: destroying the datastore leaves its backups on disk, but PBS
  # deletes its prune, verify, sync and tape backup jobs and its ACL entries
  # with it. Both are read from state: change them in an apply before the one
  # that destroys or replaces the datastore.
  destroy_data     = false
  keep_job_configs = false

  # For work on the disk, maintenance_mode = { type = "offline" } stops all
  # access to the datastore until it is removed again; "read-only" still
  # allows restores.
}

# A removable datastore on a USB disk, for backups kept offsite: the disk's
# file system is named by its UUID, which `blkid` shows, and path is a
# directory on it. The disk must be connected when the datastore is created.
# PBS mounts the directory at /mnt/datastore/offsite then, and whenever the
# disk is plugged in, and unmounts it when told to, for the disk to be taken
# away.
resource "pbs_datastore" "offsite" {
  name           = "offsite"
  path           = "pbs/offsite"
  backing_device = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"

  # Free the space of pruned backups before the disk leaves (PBS 4.2+).
  gc_on_unmount = true
}

# A datastore on S3 object storage: its backups go to the bucket pbs-backups,
# under the prefix s3store1/, the datastore's name, through the endpoint of
# the pbs_s3_endpoint example, assumed in the same configuration. path is a
# local cache, on a disk of its own. PBS checks that it reaches the bucket
# when it creates the datastore. The guide Back up to S3 object storage has
# the rest.
resource "pbs_datastore" "s3store1" {
  name        = "s3store1"
  path        = "/mnt/datastore/s3store1"
  gc_schedule = "daily"

  # PBS cannot change the backend: a change replaces the datastore.
  backend = {
    type           = "s3"
    client         = pbs_s3_endpoint.aws.id
    bucket         = "pbs-backups"
    max_cache_size = "100GiB"
  }

  # Backups the bucket already holds under this name, such as after a
  # destroy without destroy_data, are found only with reuse_datastore = true.
  # Created without it, the datastore starts empty, and its next garbage
  # collection deletes their chunks.
  reuse_datastore = true
}
