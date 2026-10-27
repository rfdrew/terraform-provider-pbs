data "pbs_roles" "all" {}

locals {
  # The privileges each role grants, by role name.
  role_privileges = { for r in data.pbs_roles.all.roles : r.roleid => r.privileges }
}

# The roles that let an API token back up to a datastore.
output "backup_roles" {
  value = [for name, privileges in local.role_privileges : name if contains(privileges, "Datastore.Backup")]
}
