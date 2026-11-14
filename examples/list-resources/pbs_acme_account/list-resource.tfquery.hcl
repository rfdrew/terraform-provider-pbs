# terraform query lists the ACME accounts; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_acme_account resource for each. Fill in contact where the CA keeps no
# addresses, as Let's Encrypt does not.
list "pbs_acme_account" "all" {
  provider         = pbs
  include_resource = true
}
