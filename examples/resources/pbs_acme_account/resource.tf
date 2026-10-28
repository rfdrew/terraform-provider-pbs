# An account at Let's Encrypt, agreeing to its current terms of service.
# Try things out against Let's Encrypt's staging directory first, whose rate
# limits are far higher: a new directory registers a new account.
data "pbs_acme_tos" "letsencrypt" {}

# Use a real address in contact: Let's Encrypt refuses the example domains.
resource "pbs_acme_account" "letsencrypt" {
  name    = "default"
  contact = "pbs-admins@example.net"
  tos_url = data.pbs_acme_tos.letsencrypt.url

  # directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
}
