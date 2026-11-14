# terraform query lists the remotes; with -generate-config-out=generated.tf it
# also writes an import block and a pbs_remote resource for each, with
# password_wo null: an imported remote keeps the password PBS has.
list "pbs_remote" "all" {
  provider         = pbs
  include_resource = true
}
