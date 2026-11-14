# terraform query lists the prune jobs of datastore store1; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_prune_job resource for each.
list "pbs_prune_job" "store1" {
  provider         = pbs
  include_resource = true

  config {
    store = "store1"
  }
}
