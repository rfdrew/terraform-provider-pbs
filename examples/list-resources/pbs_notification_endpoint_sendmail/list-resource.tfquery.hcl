# terraform query lists the sendmail notification endpoints, the built-in
# mail-to-root among them; with -generate-config-out=generated.tf it also
# writes an import block and a pbs_notification_endpoint_sendmail resource for
# each.
list "pbs_notification_endpoint_sendmail" "all" {
  provider         = pbs
  include_resource = true
}
