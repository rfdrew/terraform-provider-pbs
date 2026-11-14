terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

resource "pbs_node_config" "this" {
  http_proxy = "http://proxy.example.com:3128"

  # Gotify notifications go through the node's proxy: check that they still
  # arrive whenever the node's settings change.
  lifecycle {
    action_trigger {
      events  = [after_update]
      actions = [action.pbs_notification_test.phone]
    }
  }
}

resource "pbs_notification_endpoint_gotify" "phone" {
  name             = "phone"
  server           = "https://gotify.example.com"
  token_wo         = var.gotify_token
  token_wo_version = 1
}

# Or send a test notification yourself:
# terraform apply -invoke=action.pbs_notification_test.phone
action "pbs_notification_test" "phone" {
  config {
    name = pbs_notification_endpoint_gotify.phone.name
  }
}

variable "gotify_token" {
  description = "Token of the Gotify application PBS sends to."
  type        = string
  sensitive   = true
  ephemeral   = true
}
