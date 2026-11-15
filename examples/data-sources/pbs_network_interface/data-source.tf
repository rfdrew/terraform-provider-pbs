data "pbs_network_interface" "management" {
  name = "vmbr0"
}

# The node's management address, without its prefix length.
output "pbs_address" {
  value = try(split("/", data.pbs_network_interface.management.cidr)[0], null)
}

# Warn when the management bridge has lost its uplink.
check "pbs_management_bridge_has_ports" {
  assert {
    condition     = length(data.pbs_network_interface.management.bridge_ports) > 0
    error_message = "vmbr0 has no bridge ports."
  }
}
