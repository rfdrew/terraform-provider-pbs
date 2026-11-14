# terraform query lists the notification matchers, the built-in
# default-matcher among them; with -generate-config-out=generated.tf it also
# writes an import block and a pbs_notification_matcher resource for each.
# The rules of a matcher that PBS 4.2.10 and later hold as an expression, as
# the web interface stores them, are written as expression = jsonencode(...).
list "pbs_notification_matcher" "all" {
  provider         = pbs
  include_resource = true
}
