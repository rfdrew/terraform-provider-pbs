# Mail handed to the host's mail transport agent, which delivers or relays it
# as it is configured to. A notification reaches the endpoint only through a
# matcher that targets it, such as in the pbs_notification_matcher example.
resource "pbs_notification_endpoint_sendmail" "admins" {
  name         = "backup-admins"
  mailto       = ["backup-admins@example.com"]
  mailto_user  = ["root@pam"]
  from_address = "pbs@example.com"
  author       = "Backup server"

  # A test mail on every apply that creates or changes the endpoint.
  send_test_on_apply = true
}

# The built-in mail-to-root, which default-matcher targets, imported to mail
# the backup admins as well. Destroying this resource does not delete it: PBS
# resets it to its built-in settings.
import {
  to = pbs_notification_endpoint_sendmail.mail_to_root
  id = "mail-to-root"
}

resource "pbs_notification_endpoint_sendmail" "mail_to_root" {
  name        = "mail-to-root"
  comment     = "Send mails to root@pam's email address"
  mailto_user = ["root@pam"]
  mailto      = ["backup-admins@example.com"]
}
