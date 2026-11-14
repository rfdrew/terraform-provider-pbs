# terraform query lists the namespaces of datastore store1; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_namespace resource for each.
list "pbs_namespace" "store1" {
  provider         = pbs
  include_resource = true

  config {
    store = "store1"
  }
}
