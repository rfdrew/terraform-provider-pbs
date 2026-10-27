# What the Proxmox VE cluster's API token may do on the datastore it backs up
# to: the privileges of the token's own ACL entries that its user has too.
data "pbs_permissions" "pve_on_store1" {
  auth_id = "pve@pbs!cluster1"
  path    = "/datastore/store1"
}

output "pve_can_back_up_to_store1" {
  value = contains(keys(lookup(data.pbs_permissions.pve_on_store1.permissions, "/datastore/store1", {})), "Datastore.Backup")
}
