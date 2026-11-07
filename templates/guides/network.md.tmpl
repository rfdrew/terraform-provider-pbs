---
page_title: "Managing the network of a PBS node"
subcategory: ""
description: |-
  How pbs_network_interface and pbs_network_apply change a node's network interfaces without cutting the node off: what PBS does with a change, how to wire the two resources, the order of the steps when an interface the node is reached through changes, and how to recover when it goes wrong.
---

# Managing the network of a PBS node

`pbs_network_interface` manages the bridges, bonds, VLAN interfaces and
physical interfaces of a Proxmox Backup Server node, and `pbs_network_apply`
makes their changes take effect. Both talk to the node over the network they
change, and a wrong setting on the interface Terraform reaches PBS through
leaves the node unreachable — for Terraform and for you. This guide says what
PBS does with a change, how to wire the two resources, and how to change an
interface the node is reached through without losing it.

## What PBS does with a change

* **Every change is pending at first.** PBS writes it to
  `/etc/network/interfaces.new`. Nothing changes on the node until the network
  is reloaded — `pbs_network_apply`, Apply Configuration in the web interface,
  or `proxmox-backup-manager network reload` — or, from PBS 4.0.8, the node
  boots. While changes are pending, PBS reports the pending configuration, and
  so do the resources; `proxmox-backup-manager network changes` and the apply
  resource's `pending_changes` show the difference.
* **Applying applies everything that is pending**, whoever wrote it: changes
  made in the web interface too. PBS moves the pending file over
  `/etc/network/interfaces` and runs `ifreload -a` (ifupdown2), which
  configures the interfaces with an `auto` line — `autostart = true`, the
  resource's default — and brings each of them in line with the whole file:
  edits made to `/etc/network/interfaces` directly are applied, and addresses
  added outside it, by hand or by another tool, are removed. Every apply of
  `pbs_network_apply` does that, also when nothing is pending.
* **There is no rollback.** Once PBS has moved the file, the previous
  configuration is gone. When `ifreload` fails, the node may run part of the
  new configuration; when the change cuts the node off, it stays cut off.
* **Only root@pam may create an interface.** PBS refuses everyone else —
  API tokens, even root@pam's, and any other user — whatever the ACL. Changing,
  deleting and taking over existing interfaces, and applying, need
  `Sys.Modify` on `/system/network/interfaces`, which a token may have.
* **PBS checks the whole pending configuration at every write**, and Terraform
  writes one interface at a time — ports and slaves before the bridges and
  bonds that use them. Some changes therefore take two applies (see below).

## Before you start

* **Have the node's console at hand** — IPMI, iDRAC or iLO, the console of the
  virtual machine PBS runs in, or a keyboard and screen. If a change cuts the
  node off, the console is the only way back.
* **Keep a copy of the running configuration** on the node, for the console:

  ```shell
  cp /etc/network/interfaces /root/interfaces.before-terraform
  ```

* **Check that nothing unexpected is pending or running.**
  `proxmox-backup-manager network changes` shows what is pending — the first
  apply applies it; revert what you do not want with
  `proxmox-backup-manager network revert`. Compare `ip -br addr` with
  `/etc/network/interfaces`: what the node runs but the file lacks goes at the
  first apply.
* **Check that the node has ifupdown2**, which applies the changes:
  `dpkg -s ifupdown2`. PBS only recommends the package, so an installation from
  the PBS ISO has it, but one made without recommended packages may not;
  `pbs_network_apply` says so when it is missing.
* **Sign in as root@pam** in the provider when the configuration creates
  interfaces. The password goes into the provider's `password`, or
  `PBS_PASSWORD`, preferably from a secret store:

  ```terraform
  provider "pbs" {
    endpoint = "https://pbs.example.com:8007"
    username = "root@pam"
    password = var.pbs_root_password
  }
  ```

  The provider cannot complete a second factor, so a root@pam with two-factor
  authentication cannot create interfaces through it. Create them on the node
  then — in the web interface, or with `proxmox-backup-manager network create`
  — and import them: changing, deleting and applying work with an API token.

## Wiring the two resources

`pbs_network_apply` applies when it is created and whenever its `triggers`
change. Give it a trigger for every interface, so that any change of an
interface changes the triggers, and the apply runs after the interfaces are
written:

```terraform
resource "pbs_network_interface" "vlan" {
  for_each = local.vlans

  name            = "vlan${each.value.tag}"
  type            = "vlan"
  vlan_id         = each.value.tag
  vlan_raw_device = "bond0"
  cidr            = each.value.cidr
}

resource "pbs_network_apply" "this" {
  triggers = {
    for name, iface in pbs_network_interface.vlan : name => jsonencode(iface)
  }
}
```

`jsonencode()` of the whole resource changes whenever the interface does,
which plans an apply, and the reference makes Terraform write the interface
before it applies; an interface left unchanged leaves the triggers as they
are, and nothing is applied.

The apply resource also notices changes that are pending when Terraform
plans it — made in the web interface, or left by a run that failed halfway —
and plans to apply them, with a warning that shows them. To keep them from
being applied, revert them first: Revert in the web interface, or
`proxmox-backup-manager network revert`.

Removing an interface together with its trigger deletes it from the pending
configuration and then applies.

## Bringing existing interfaces under Terraform

Start from what the node has, with a plan that changes nothing:

1. List the interfaces with the data source `pbs_network_interfaces`, or in
   the web interface.
2. Write a resource for each interface to manage, with the settings it has,
   and import it:

   ```terraform
   import {
     to = pbs_network_interface.vmbr0
     id = "localhost/vmbr0"
   }
   ```

3. Run `terraform plan` until it shows only the imports. A physical
   interface (`type = "eth"`) can also be taken over without an import, but
   then the configuration replaces what the interface has: the plan refuses
   to remove its addresses and gateways unless the configuration sets
   `method` (or `method6`) explicitly — `manual`, or `static` with another
   address —, and warns about the comments and MTU it removes and about
   `autostart`, which defaults to `true`.
4. Add `pbs_network_apply` last, once the plan is otherwise empty. Creating it
   reloads the network once, even when nothing is pending.

Lines PBS does not interpret, such as `bridge-stp off` or `post-up` commands,
stay as they are; `options` and `options6` show them.

## Stopping to manage an interface

Removing a `pbs_network_interface` from the configuration, or destroying it,
deletes a bridge, bond or VLAN interface from the pending configuration, and
resets a physical interface: method `manual`, no addresses, gateway, MTU,
comments or autostart — PBS 4.1.7 and later keep an IPv6 method `dhcp` or
`auto`. The plan warns when that removes addresses. When the interface's
trigger goes in the same change, `pbs_network_apply` applies it at once — for
the interface the node is reached through, that cuts it off.

To stop managing an interface and leave it as it is, remove it from the state
instead of destroying it:

```terraform
removed {
  from = pbs_network_interface.vmbr0

  lifecycle {
    destroy = false
  }
}
```

or `terraform state rm pbs_network_interface.vmbr0`. `terraform destroy`
destroys `pbs_network_apply` first, which applies nothing: the interfaces'
deletions then stay pending until the next reload, or boot. Revert them with
`proxmox-backup-manager network revert` if they are not wanted.

## Changing the interface the node is reached through

A change of the address, gateway, MTU, ports or bond of the interface
Terraform reaches PBS through takes effect while Terraform waits for the
apply to finish. Do it in steps that keep a way in at every point:

1. **Add before you remove.** Give the node the new address on another
   interface, or as a second interface — a VLAN interface, say — apply, and
   check that the web interface answers there.
2. **Move Terraform over.** Point the provider's `endpoint` at the new
   address, and run `terraform plan`: it must show no changes.
3. **Remove the old address**, and apply.

While the reload runs, `pbs_network_apply` waits up to two minutes for a node
that stops answering — a bond or a bridge may take half a minute to forward
again. A node that stays silent makes the apply fail with "lost contact": the
change may have cut it off, or it may answer again later. Once it answers,
run `terraform plan`: `pending_changes` shows whether anything is still
pending. If it does not answer at all, check it from its console, then point
`endpoint` at the address the node now has, and run `terraform apply` again.

**Move a gateway in one apply.** PBS allows one IPv4 and one IPv6 gateway in
the whole configuration, and checks the pending configuration, so a gateway
moves in one apply — as long as Terraform removes it from the old interface
before it adds it to the new one:

```terraform
resource "pbs_network_interface" "vmbr0" {
  name         = "vmbr0"
  type         = "bridge"
  bridge_ports = ["eno1"]
  cidr         = "192.0.2.10/24"
  # gateway removed here…
}

resource "pbs_network_interface" "vmbr1" {
  name         = "vmbr1"
  type         = "bridge"
  bridge_ports = ["eno2"]
  cidr         = "198.51.100.10/24"
  gateway      = "198.51.100.1" # …and set here

  depends_on = [pbs_network_interface.vmbr0]
}
```

One reload then switches the default route. Never apply a configuration in
which neither interface has the gateway: the node loses its default route,
and nothing outside its own networks — Terraform included — reaches it until
the next apply. When both interfaces are instances of one `for_each`, which
`depends_on` cannot order, write the removal first with
`terraform apply -target=<the old interface>`, which leaves the apply
resource alone, then run `terraform apply`.

## Changes that take two applies

Terraform writes ports and slaves before the bridges and bonds that use them,
and PBS refuses a write that leaves the pending configuration inconsistent.
For these changes, write the first step alone with
`terraform apply -target=<the bridge>` — which leaves `pbs_network_apply`
alone, so the node never runs the state in between —, then make the rest of
the change and run `terraform apply`, which writes it and applies both:

* **Raising the MTU of a bridge and its ports.** PBS refuses a port whose MTU
  is larger than its bridge's — counting a bridge without an MTU as 1500 —, so
  raise the bridge's MTU first, then the ports'. Lowering works in one apply.
* **Moving a NIC from a bridge into a new bond under it.** A NIC belongs to
  one bridge or bond only, and a bridge's ports must exist: take the NIC out of
  the bridge's `bridge_ports` first, then add the bond and make it the
  bridge's port.
* **Removing a bond together with the bridge port it is.** Take it out of
  `bridge_ports` first, then remove its resource.

## Recovering from the console

When the node is unreachable after an apply:

```shell
# What the node runs now, and what the reload reported. The task ID is in
# Terraform's error; `proxmox-backup-manager task list --all` lists the
# reload as a srvreload task with the ID networking.
ip -br addr
proxmox-backup-manager task log 'UPID:...'

# Back to the copy made before:
cp /root/interfaces.before-terraform /etc/network/interfaces
ifreload -a
```

Then bring Terraform's state in line: `terraform plan` shows the interfaces
as the node has them again, and the next apply makes the changes anew —
fix them in the configuration first.

## Limits

* **IPv4 DHCP:** PBS's API turns the IPv4 method `dhcp` into `manual`
  whenever it changes an interface. So a change of a bridge, bond or VLAN
  interface whose configuration sets `method = "dhcp"` replaces it: the
  interface is deleted from the pending configuration and created anew,
  which needs root@pam, drops its `options`, and fails while a bridge uses it
  as a port or a bond as a slave. When the configuration leaves `method` out
  of an interface that uses DHCP, the plan refuses to change it. A physical
  interface cannot keep DHCP under Terraform.
* **IPv6 `dhcp` and `auto`** need PBS 4.1.7 (and `auto` 4.2.7): older
  releases turn them into `manual` on any change, and those before 4.2.7
  cannot read a configuration with `auto` at all.
* **One resource per interface.** `localhost` and the node's host name name
  the same node; two resources for one interface undo each other's changes.
