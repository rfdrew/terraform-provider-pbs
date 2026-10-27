# The main scenario: a user and an API token for a Proxmox VE cluster, allowed
# to back up to one datastore. A token acts with those of its own privileges
# that its user has too, so both need the role.
resource "pbs_user" "pve" {
  userid  = "pve@pbs"
  comment = "PVE cluster"
}

resource "pbs_api_token" "pve" {
  userid     = pbs_user.pve.userid
  token_name = "cluster1"
}

resource "pbs_acl" "pve_user" {
  path    = "/datastore/store1"
  auth_id = pbs_user.pve.userid
  role    = "DatastoreBackup"
}

resource "pbs_acl" "pve_token" {
  path    = "/datastore/store1"
  auth_id = pbs_api_token.pve.tokenid
  role    = "DatastoreBackup"
}

# Read-only access to the server's own settings for an existing user, without
# inheritance below /: propagate = false limits the role to the path itself.
resource "pbs_acl" "auditor" {
  path      = "/"
  auth_id   = "auditor@pbs"
  role      = "Audit"
  propagate = false
}
