data "pbs_network_interfaces" "this" {}

# The node's IPv4 addresses by interface, such as { vmbr0 = "192.0.2.10/24" }.
output "ipv4_addresses" {
  value = { for i in data.pbs_network_interfaces.this.interfaces : i.name => i.cidr if i.cidr != null }
}

# Physical NICs that are down, such as a backup link without a cable.
output "nics_down" {
  value = [for i in data.pbs_network_interfaces.this.interfaces : i.name if i.type == "eth" && !i.active]
}

# Warn while someone has changed the network configuration in PBS without
# applying it: PBS then lists the pending configuration, not the running one.
check "pbs_network_configuration_is_applied" {
  assert {
    condition     = data.pbs_network_interfaces.this.pending_changes == null
    error_message = "PBS has network changes not applied yet:\n${data.pbs_network_interfaces.this.pending_changes}"
  }
}
