# terraform query lists the OpenID Connect realms; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_realm_openid resource for each. The realms keep the client keys PBS has.
list "pbs_realm_openid" "all" {
  provider         = pbs
  include_resource = true
}
