# Creating interfaces needs root@pam, signed in with a password: PBS refuses
# to create one for anyone else, API tokens included. A root@pam with
# two-factor authentication cannot sign in through the provider: create the
# interfaces on the node then, and import them.
provider "pbs" {
  endpoint = "https://pbs.example.com:8007"
  username = "root@pam"
  password = var.pbs_root_password
}

# The node's two NICs, bonded with LACP, carry a VLAN-aware bridge for the
# backup network and, on VLAN 20 of that bridge, a storage network. The
# node is reached through another interface, which this leaves alone.
resource "pbs_network_interface" "bond0" {
  name                  = "bond0"
  type                  = "bond"
  slaves                = ["eno1", "eno2"]
  bond_mode             = "802.3ad"
  bond_xmit_hash_policy = "layer3+4"
  mtu                   = 9000
  comments              = "LACP to the core switches"
}

resource "pbs_network_interface" "vmbr1" {
  name              = "vmbr1"
  type              = "bridge"
  bridge_ports      = [pbs_network_interface.bond0.name]
  bridge_vlan_aware = true
  cidr              = "198.51.100.10/24"
  cidr6             = "2001:db8:100::10/64"
  mtu               = 9000
  comments          = "Backup network"
}

resource "pbs_network_interface" "storage" {
  name = "${pbs_network_interface.vmbr1.name}.20"
  type = "vlan"
  cidr = "203.0.113.10/24"
}

# A physical interface is taken over, not created: here a spare NIC gets a
# comment and stays down.
resource "pbs_network_interface" "eno3" {
  name      = "eno3"
  type      = "eth"
  autostart = false
  comments  = "Spare, not cabled"
}

# Nothing above takes effect until the pending changes are applied, after
# every interface is written.
resource "pbs_network_apply" "this" {
  triggers = {
    bond0   = jsonencode(pbs_network_interface.bond0)
    vmbr1   = jsonencode(pbs_network_interface.vmbr1)
    storage = jsonencode(pbs_network_interface.storage)
    eno3    = jsonencode(pbs_network_interface.eno3)
  }
}
