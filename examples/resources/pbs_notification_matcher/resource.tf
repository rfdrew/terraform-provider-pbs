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

# Rules that nest, from PBS 4.2.10: notifications of garbage collection,
# during working hours or when they are warnings or errors. This is the
# example of PBS's documentation, the kind of rule tree the matcher editor of
# the web interface builds; jsonencode writes it as PBS takes it.
resource "pbs_notification_matcher" "gc" {
  name   = "gc-alerts"
  target = [pbs_notification_endpoint_smtp.mail.name]
  expression = jsonencode({
    "all-of" = [
      { "any-of" = [
        { match = { type = "calendar", schedule = "mon..fri 09:00-17:00" } },
        { match = { type = "severity", severities = ["warning", "error"] } },
      ] },
      { match = { type = "field", field = "type", values = ["gc"] } },
    ]
  })
}
