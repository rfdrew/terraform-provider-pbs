import {
  to = pbs_acl.pve_token
  identity = {
    path    = "/datastore/store1"
    auth_id = "pve@pbs!cluster1"
    role    = "DatastoreBackup"
  }
}
