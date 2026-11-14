# terraform query lists the SMTP notification endpoints; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_notification_endpoint_smtp resource for each. An endpoint with a
# username needs password_wo and password_wo_version filled in: PBS never
# returns the password.
list "pbs_notification_endpoint_smtp" "all" {
  provider         = pbs
  include_resource = true
}
