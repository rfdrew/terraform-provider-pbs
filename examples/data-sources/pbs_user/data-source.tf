data "pbs_user" "pve" {
  userid = "pve@pbs"
}

# Warn when the user Proxmox VE backs up as can no longer sign in, or is set
# to stop being able to: its backups would start failing.
check "pve_user_can_sign_in" {
  assert {
    condition     = data.pbs_user.pve.enable && data.pbs_user.pve.expire == 0
    error_message = "The PBS user ${data.pbs_user.pve.userid} is disabled or has an expiry date."
  }
}

output "pve_user_contact" {
  value = coalesce(data.pbs_user.pve.email, "no email address")
}
