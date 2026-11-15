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

# An account at ZeroSSL, which requires External Account Binding: the CA
# gives you a key identifier and an HMAC key, which PBS sends once, when it
# registers the account.
data "pbs_acme_tos" "zerossl" {
  directory = "https://acme.zerossl.com/v2/DV90"
}

resource "pbs_acme_account" "zerossl" {
  name      = "zerossl"
  contact   = "pbs-admins@example.net"
  directory = data.pbs_acme_tos.zerossl.directory
  tos_url   = data.pbs_acme_tos.zerossl.url

  # The HMAC key is write-only: it never reaches the plan or state. A new
  # eab_kid or eab_hmac_key_wo_version registers a new account; once the
  # account is registered, the key may be left out, with its version.
  eab_kid                 = var.zerossl_eab_kid
  eab_hmac_key_wo         = var.zerossl_eab_hmac_key
  eab_hmac_key_wo_version = 1
}

variable "zerossl_eab_kid" {
  description = "Key identifier of the External Account Binding ZeroSSL gave."
  type        = string
}

variable "zerossl_eab_hmac_key" {
  description = "HMAC key of the External Account Binding ZeroSSL gave."
  type        = string
  sensitive   = true
  ephemeral   = true
}
