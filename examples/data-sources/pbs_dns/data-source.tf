data "pbs_dns" "this" {}

# The node's nameservers, in order, such as ["192.0.2.53", "192.0.2.54"].
output "pbs_nameservers" {
  value = compact([data.pbs_dns.this.dns1, data.pbs_dns.this.dns2, data.pbs_dns.this.dns3])
}

# Warn when the node depends on a single nameserver: without it, PBS resolves
# no name — not its remotes, S3 endpoints, ACME CA or APT mirrors.
check "pbs_has_a_second_nameserver" {
  assert {
    condition     = data.pbs_dns.this.dns2 != null
    error_message = "The PBS node has one nameserver only, ${coalesce(data.pbs_dns.this.dns1, "none")}."
  }
}
