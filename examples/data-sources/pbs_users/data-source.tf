# The users of PBS's own realm, leaving out root@pam and the other accounts
# of the host.
data "pbs_users" "local" {
  realm = "pbs"
}

output "local_users" {
  value = [for u in data.pbs_users.local.users : u.userid]
}

# Disabled users, as candidates for a clean-up. An expired user cannot sign
# in either; compare expire with a timestamp to find those.
output "disabled_users" {
  value = [for u in data.pbs_users.local.users : u.userid if !u.enable]
}
