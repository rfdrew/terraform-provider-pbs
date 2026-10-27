# Users are imported by user ID, as the pbs_users data source or the Access
# Control panel shows it. PBS never returns a password, so password_wo_version
# is empty after an import, and a configuration that sets it plans a password
# change: with an API token that is a plan-time error, and with a password it
# replaces the user's current password. Leave password_wo and
# password_wo_version out of an imported user unless that is intended.
terraform import pbs_user.pve pve@pbs
