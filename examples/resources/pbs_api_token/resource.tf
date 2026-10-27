resource "pbs_user" "pve" {
  userid  = "pve@pbs"
  comment = "PVE cluster"
}

# The token a Proxmox VE cluster backs up with. Its secret, value, is in
# Terraform state, marked sensitive.
resource "pbs_api_token" "pve" {
  userid     = pbs_user.pve.userid
  token_name = "cluster1"
  comment    = "Backups of cluster1"

  # Any change of this value has PBS generate a new secret; the old one stops
  # working at once. With the hashicorp/time provider, a time_rotating
  # resource's id rotates it on a schedule.
  regenerate = "2026-10"
}

# A token has no privileges of its own: it acts with those of its own ACL
# entries that its user has too.
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

# PVE's PBS storage signs in with the token ID as the user name and the
# secret as the password.
output "pve_storage_username" {
  value = pbs_api_token.pve.tokenid
}

output "pve_storage_password" {
  value     = pbs_api_token.pve.value
  sensitive = true
}
