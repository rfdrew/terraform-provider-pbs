# PBS signs in to the remote to list its datastores, so reading this fails
# when the remote's host, fingerprint or credentials are wrong. Referring to
# the name of pbs_remote.offsite, of the pbs_remote example, reads it after
# the remote is created or changed.
data "pbs_remote_datastores" "offsite" {
  remote = pbs_remote.offsite.name
}

# The datastore the offsite sync job pushes to must be there, and writable.
check "offsite_datastore_is_ready" {
  assert {
    condition = anytrue([
      for ds in data.pbs_remote_datastores.offsite.datastores :
      ds.store == "offsite1" && ds.maintenance_mode == null
    ])
    error_message = "The offsite PBS has no datastore offsite1 that sync@pbs!primary may see, or it is in maintenance mode."
  }
}
