data "pbs_acme_directories" "known" {}

data "pbs_acme_tos" "staging" {
  directory = data.pbs_acme_directories.known.directories[1].url
}

# Register at Let's Encrypt's staging directory, the second PBS knows, to try
# things out. Use a real address in contact: Let's Encrypt refuses the example
# domains.
resource "pbs_acme_account" "staging" {
  name      = "staging"
  contact   = "pbs-admins@example.net"
  directory = data.pbs_acme_directories.known.directories[1].url
  tos_url   = data.pbs_acme_tos.staging.url
}
