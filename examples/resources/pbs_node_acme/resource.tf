# The node orders its certificate with the account of the pbs_acme_account
# example, for two names validated through Cloudflare, by the plugin of the
# pbs_acme_plugin example — both assumed in the same configuration.
resource "pbs_node_acme" "this" {
  account = pbs_acme_account.letsencrypt.name

  domains = [
    { domain = "pbs.example.net", plugin = pbs_acme_plugin.cloudflare.id },
    { domain = "backup.example.net", plugin = pbs_acme_plugin.cloudflare.id },
  ]
}
