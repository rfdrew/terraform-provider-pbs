# Mail through a relay that takes STARTTLS on port 587 and wants a sign-in.
# PBS does not contact the relay until it sends the first notification, and
# sends one here only through a matcher that targets the endpoint: see the
# pbs_notification_matcher example, which points the built-in default-matcher
# at it.
resource "pbs_notification_endpoint_smtp" "mail" {
  name         = "smtp"
  server       = "smtp.example.com"
  mode         = "starttls"
  port         = 587
  username     = "pbs@example.com"
  from_address = "pbs@example.com"
  author       = "Backup server"
  mailto       = ["backup-admins@example.com"]

  # The password is write-only: it never reaches the plan or state, and PBS
  # receives it when the endpoint is created and whenever
  # password_wo_version changes.
  password_wo         = var.smtp_password
  password_wo_version = 1
}

variable "smtp_password" {
  description = "Password of pbs@example.com on smtp.example.com."
  type        = string
  sensitive   = true
  ephemeral   = true
}
