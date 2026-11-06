data "pbs_services" "this" {}

# The state of each service by its ID, such as
# { "proxmox-backup-proxy" = "running", "chrony" = "running", ... }; empty on
# PBS in a container without systemd.
output "service_states" {
  value = { for s in data.pbs_services.this.services : s.service => s.state }
}

# Warn when the clock is not kept in sync: certificates, sign-in tickets and
# TOTP codes depend on it. A node without systemd lists no services, and
# passes.
check "pbs_time_sync_is_running" {
  assert {
    condition = alltrue([
      for s in data.pbs_services.this.services : s.state == "running" if s.service == "chrony"
    ])
    error_message = "chrony is not running on the PBS node."
  }
}
