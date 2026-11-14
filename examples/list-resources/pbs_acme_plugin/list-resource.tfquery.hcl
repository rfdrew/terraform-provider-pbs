# terraform query lists the ACME plugins, the built-in standalone one
# included; with -generate-config-out=generated.tf it also writes an import
# block and a pbs_acme_plugin resource for each. The settings of a DNS
# plugin are sensitive and left out: fill in data before planning.
list "pbs_acme_plugin" "all" {
  provider         = pbs
  include_resource = true
}
