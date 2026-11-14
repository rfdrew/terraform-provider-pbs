# terraform query lists the push jobs; with -generate-config-out=generated.tf
# it also writes an import block and a pbs_sync_job resource for each.
list "pbs_sync_job" "push" {
  provider         = pbs
  include_resource = true

  config {
    sync_direction = "push"
  }
}
