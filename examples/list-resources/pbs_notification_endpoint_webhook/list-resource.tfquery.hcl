# terraform query lists the webhook notification endpoints; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_notification_endpoint_webhook resource for each. Fill in value_wo and
# value_wo_version of every secret before planning: PBS returns the secrets'
# names, never their values.
list "pbs_notification_endpoint_webhook" "all" {
  provider         = pbs
  include_resource = true
}
