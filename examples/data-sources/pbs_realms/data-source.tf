data "pbs_realms" "all" {}

# The realm the sign-in form preselects, if any.
output "default_realm" {
  value = one([for r in data.pbs_realms.all.realms : r.realm if r.default])
}

# The OpenID Connect realms.
output "openid_realms" {
  value = [for r in data.pbs_realms.all.realms : r.realm if r.type == "openid"]
}
