# terraform query lists the node's bridges; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_network_interface resource for each.
list "pbs_network_interface" "bridges" {
  provider         = pbs
  include_resource = true

  config {
    type = "bridge"
  }
}
