# Webhook endpoints are imported by name. PBS returns the names of the
# secrets but never their values, so every value_wo_version is empty after an
# import, and the next apply sends every secret's value_wo.
terraform import pbs_notification_endpoint_webhook.chat chat
