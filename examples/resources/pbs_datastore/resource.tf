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
