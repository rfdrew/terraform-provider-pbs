# Gotify endpoints are imported by name. PBS never returns the token, so
# token_wo_version is empty after an import, and the next apply sends
# token_wo, replacing the token PBS has.
terraform import pbs_notification_endpoint_gotify.phones gotify
