variable "pbs_subscription_key" {
  type      = string
  sensitive = true
}

# PBS checks the key with Proxmox's shop, through the node's proxy if it
# has one.
resource "pbs_subscription" "this" {
  key = var.pbs_subscription_key

  depends_on = [pbs_node_config.this]

  lifecycle {
    postcondition {
      condition     = self.status == "active"
      error_message = "The PBS subscription is ${self.status}: ${coalesce(self.message, "no message")}."
    }
  }
}

# With a subscription, use the enterprise repository instead of
# no-subscription.
resource "pbs_apt_standard_repository" "enterprise" {
  handle     = "enterprise"
  depends_on = [pbs_subscription.this]
}
