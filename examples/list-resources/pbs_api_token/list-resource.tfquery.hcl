# terraform query lists the API tokens; with -generate-config-out=generated.tf
# it also writes an import block and a pbs_api_token resource for each,
# without the token's secret, which PBS never shows again.
list "pbs_api_token" "pve" {
  provider         = pbs
  include_resource = true

  config {
    userid = "pve@pbs"
  }
}
