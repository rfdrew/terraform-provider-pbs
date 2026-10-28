# DNS-01 validation through Cloudflare, with an API token whose only
# permission is Zone → DNS → Edit on the zone the domains are in.
resource "pbs_acme_plugin" "cloudflare" {
  id  = "cloudflare"
  api = "cf"
  data = {
    CF_Token   = var.cloudflare_api_token
    CF_Zone_ID = var.cloudflare_zone_id
  }
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token with Zone → DNS → Edit on the zone."
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "ID of the Cloudflare zone, from the zone's overview page."
  type        = string
}
