# terraform query lists the verify jobs; with -generate-config-out=generated.tf
# it also writes an import block and a pbs_verify_job resource for each.
list "pbs_verify_job" "all" {
  provider         = pbs
  include_resource = true
}
