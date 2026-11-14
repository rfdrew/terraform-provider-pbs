# terraform query lists the datastores; with -generate-config-out=generated.tf
# it also writes an import block and a pbs_datastore resource for each.
list "pbs_datastore" "all" {
  provider         = pbs
  include_resource = true
}
