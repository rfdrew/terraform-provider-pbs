# Post every notification to a chat service's incoming webhook as JSON. The
# URL, the header values and the body are Handlebars templates;
# {{ escape ... }} makes a value safe inside a JSON string.
resource "pbs_notification_endpoint_webhook" "chat" {
  name   = "chat"
  url    = "https://chat.example.com/hooks/{{ secrets.hook_id }}"
  method = "post"
  header = [
    { name = "Content-Type", value = "application/json" },
    { name = "Authorization", value = "Bearer {{ secrets.token }}" },
  ]
  body = jsonencode({
    text = "[{{ severity }}] {{ escape title }}\n\n{{ escape message }}"
  })

  # The secrets' values are write-only: they never reach the plan or state,
  # and PBS never returns them. PBS receives a value when the secret is
  # created and whenever its value_wo_version changes; to rotate the token,
  # increment its version alone, and the hook ID keeps the value PBS has.
  secret = [
    { name = "hook_id", value_wo = var.chat_hook_id, value_wo_version = 1 },
    { name = "token", value_wo = var.chat_token, value_wo_version = 1 },
  ]

  send_test_on_apply = true
}

variable "chat_hook_id" {
  description = "ID of the chat's incoming webhook."
  type        = string
  sensitive   = true
  ephemeral   = true
}

variable "chat_token" {
  description = "Token the chat's webhook accepts."
  type        = string
  sensitive   = true
  ephemeral   = true
}

# Failed jobs of any kind go to the chat.
resource "pbs_notification_matcher" "errors_to_chat" {
  name           = "errors-to-chat"
  target         = [pbs_notification_endpoint_webhook.chat.name]
  match_severity = ["error"]
}
