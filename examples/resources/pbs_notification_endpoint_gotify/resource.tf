# Push notifications to a Gotify server, as messages of one of its
# applications, and route errors there.
resource "pbs_notification_endpoint_gotify" "phones" {
  name    = "gotify"
  server  = "https://gotify.example.com"
  comment = "The admins' phones"

  # The application token is write-only: it never reaches the plan or state,
  # and PBS receives it when the endpoint is created and whenever
  # token_wo_version changes.
  token_wo         = var.gotify_token
  token_wo_version = 1

  # PBS does not contact the server when it saves the endpoint; a test
  # message on every apply that creates or changes it does.
  send_test_on_apply = true
}

variable "gotify_token" {
  description = "Token of the Gotify application PBS sends as."
  type        = string
  sensitive   = true
  ephemeral   = true
}

resource "pbs_notification_matcher" "errors_to_phones" {
  name           = "errors-to-gotify"
  target         = [pbs_notification_endpoint_gotify.phones.name]
  match_severity = ["error"]
}
