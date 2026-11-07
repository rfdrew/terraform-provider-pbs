# VLAN interfaces from a map, applied once all of them are written: a change
# of any interface changes the triggers, and the apply runs after it.
locals {
  vlans = {
    backup  = { tag = 10, cidr = "198.51.100.10/24" }
    storage = { tag = 20, cidr = "203.0.113.10/24" }
  }
}

resource "pbs_network_interface" "vlan" {
  for_each = local.vlans

  name     = "vlan${each.value.tag}"
  type     = "vlan"
  vlan_id  = each.value.tag
  cidr     = each.value.cidr
  comments = each.key

  vlan_raw_device = "bond0"
}

resource "pbs_network_apply" "this" {
  triggers = {
    for name, iface in pbs_network_interface.vlan : name => jsonencode(iface)
  }
}

# The changes PBS has pending, as of the last refresh: null once applied.
output "pending_network_changes" {
  value = pbs_network_apply.this.pending_changes
}
