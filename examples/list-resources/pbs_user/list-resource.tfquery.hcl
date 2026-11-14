# terraform query lists the users; with -generate-config-out=generated.tf it
# also writes an import block and a pbs_user resource for each.
list "pbs_user" "pbs" {
  provider         = pbs
  include_resource = true

  config {
    realm = "pbs"
  }
}
