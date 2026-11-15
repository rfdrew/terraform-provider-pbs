terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# Restart postfix, for a change of its configuration that a reload does not
# apply, such as new inet_interfaces:
# terraform apply -invoke=action.pbs_service_restart.postfix
#
# Prefer pbs_service_reload where a reload is enough. The action refuses to
# restart PBS's API daemon, proxmox-backup: reload it instead.
action "pbs_service_restart" "postfix" {
  config {
    service = "postfix"
    timeout = "2m"
  }
}
