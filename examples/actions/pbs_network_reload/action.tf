terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# Apply the network changes pending on the node now — made in the web
# interface, or left by an earlier run —, without a pbs_network_apply
# resource:
# terraform apply -invoke=action.pbs_network_reload.now
#
# In configurations that manage interfaces, prefer pbs_network_apply, and do
# not trigger this action from pbs_network_interface resources: each would
# reload the node with the changes of the interfaces written so far.
action "pbs_network_reload" "now" {
  config {
    timeout = "10m"
  }
}
