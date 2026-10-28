# Send every notification by SMTP. PBS's built-in default-matcher routes
# all notifications but those of successful prune jobs to mail-to-root, the
# host's sendmail. It always exists, so it is imported rather than created,
# and only its target changes: to the endpoint of the
# pbs_notification_endpoint_smtp example, assumed in the same configuration.
import {
  to = pbs_notification_matcher.default
  id = "default-matcher"
}

# Destroying this resource does not delete default-matcher: PBS resets it to
# its built-in settings, and notifications go to mail-to-root again.
resource "pbs_notification_matcher" "default" {
  name    = "default-matcher"
  comment = "Route everything but successful prune job notifications to SMTP"
  target  = [pbs_notification_endpoint_smtp.mail.name]

  # The built-in rules, kept as they are: they match the notifications of
  # prune jobs at severity info, the successful ones, and invert_match turns
  # that into everything else. Without the match_* attributes, the matcher
  # would match every notification, successful prunes included.
  mode           = "all"
  invert_match   = true
  match_field    = ["exact:type=prune"]
  match_severity = ["info"]
}

# A matcher of its own: failed sync jobs also go to root@pam's mail address,
# through the built-in sendmail endpoint mail-to-root.
resource "pbs_notification_matcher" "sync_errors" {
  name           = "sync-errors"
  target         = ["mail-to-root"]
  match_field    = ["exact:type=sync"]
  match_severity = ["error"]
}
