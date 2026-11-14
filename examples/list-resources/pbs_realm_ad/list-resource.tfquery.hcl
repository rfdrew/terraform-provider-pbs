# terraform query lists the Active Directory realms; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_realm_ad resource for each. The realms keep the bind passwords PBS has.
list "pbs_realm_ad" "all" {
  provider         = pbs
  include_resource = true
}
