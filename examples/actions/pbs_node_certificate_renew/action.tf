terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# ACME settings as in the pbs_node_acme example, with its account and
# plugin. When they change — another account, say, of Let's Encrypt's
# production directory rather than its staging one — renew the certificate
# at once, rather than when PBS's daily update finds it due. Or invoke the
# action yourself, to see that renewal works:
# terraform apply -invoke=action.pbs_node_certificate_renew.now
#
# Do not trigger it so on a node with a pbs_node_certificate whose triggers
# follow the domains, as in its example: a change of domains has that
# resource order a certificate already, and the action would order a second
# one, which counts against the CA's rate limits too.
resource "pbs_node_acme" "this" {
  account = pbs_acme_account.letsencrypt.name

  domains = [
    { domain = "pbs.example.net", plugin = pbs_acme_plugin.cloudflare.id },
  ]

  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.pbs_node_certificate_renew.now]
    }
  }
}

action "pbs_node_certificate_renew" "now" {
  config {
    # Renew even though the certificate is not due yet.
    force   = true
    timeout = "15m"
  }
}
