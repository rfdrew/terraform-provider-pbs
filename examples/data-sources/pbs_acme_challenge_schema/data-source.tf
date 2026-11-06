data "pbs_acme_challenge_schema" "dns" {}

variable "dns_api" {
  description = "acme.sh DNS API of the plugin, such as cf for Cloudflare."
  type        = string
  default     = "cf"
}

variable "dns_settings" {
  description = "Settings of the DNS API, such as CF_Token."
  type        = map(string)
  sensitive   = true
}

locals {
  dns_fields = try(data.pbs_acme_challenge_schema.dns.apis[var.dns_api].fields, {})
}

# A DNS plugin whose API and settings are checked against what PBS documents
# for the API: a typo in a setting's name fails the plan instead of the next
# certificate order. APIs that document no settings accept any.
resource "pbs_acme_plugin" "dns" {
  id   = "dns"
  api  = var.dns_api
  data = var.dns_settings

  lifecycle {
    precondition {
      condition     = contains(keys(data.pbs_acme_challenge_schema.dns.apis), var.dns_api)
      error_message = "PBS has no DNS API ${var.dns_api}."
    }
    precondition {
      condition     = length(local.dns_fields) == 0 || alltrue([for key in keys(var.dns_settings) : contains(keys(local.dns_fields), key)])
      error_message = "dns_settings has a setting the DNS API ${var.dns_api} does not document: see the keys of its fields."
    }
  }
}

# The settings Cloudflare's API documents, with their descriptions.
output "cloudflare_settings" {
  value = {
    for key, field in data.pbs_acme_challenge_schema.dns.apis["cf"].fields : key => field.description
  }
}
