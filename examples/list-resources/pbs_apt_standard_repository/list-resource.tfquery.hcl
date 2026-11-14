# terraform query lists the standard repositories the node has; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_apt_standard_repository resource for each. Destroying such a resource
# disables its repository.
list "pbs_apt_standard_repository" "all" {
  provider         = pbs
  include_resource = true
}
