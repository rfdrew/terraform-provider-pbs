# terraform query lists the LDAP realms; with -generate-config-out=generated.tf
# it also writes an import block and a pbs_realm_ldap resource for each. The
# realms keep the bind passwords PBS has.
list "pbs_realm_ldap" "all" {
  provider         = pbs
  include_resource = true
}
