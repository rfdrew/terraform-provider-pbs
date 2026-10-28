# The terms of service of Let's Encrypt's production directory, and of its
# staging directory.
data "pbs_acme_tos" "letsencrypt" {}

data "pbs_acme_tos" "letsencrypt_staging" {
  directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
}

output "letsencrypt_tos" {
  value = data.pbs_acme_tos.letsencrypt.url
}
