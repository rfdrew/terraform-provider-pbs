# SMTP endpoints are imported by name. PBS never returns the password, so
# password_wo_version is empty after an import, and a configuration that sets
# it sends password_wo in the next apply, replacing the password PBS has.
terraform import pbs_notification_endpoint_smtp.mail smtp
