# terraform query lists the Gotify notification endpoints; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_notification_endpoint_gotify resource for each. Fill in token_wo and
# token_wo_version before planning: PBS never returns the token.
list "pbs_notification_endpoint_gotify" "all" {
  provider         = pbs
  include_resource = true
}
