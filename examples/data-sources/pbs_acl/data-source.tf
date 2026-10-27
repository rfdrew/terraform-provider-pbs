# Who has which role on the datastore store1 and on its namespaces.
data "pbs_acl" "store1" {
  path = "/datastore/store1"
}

output "store1_roles" {
  value = [for e in data.pbs_acl.store1.entries : "${e.path}: ${e.auth_id} has ${e.role}"]
}

# The roles of the Proxmox VE cluster's API token, on every path.
data "pbs_acl" "pve_token" {
  auth_id = "pve@pbs!cluster1"
}

output "pve_token_roles" {
  value = { for e in data.pbs_acl.pve_token.entries : e.path => e.role... }
}
