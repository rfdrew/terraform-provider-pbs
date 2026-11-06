data "pbs_acme_accounts" "all" {}

# The accounts and the CA each is registered at.
output "acme_accounts" {
  value = { for a in data.pbs_acme_accounts.all.accounts : a.name => a.directory }
}
