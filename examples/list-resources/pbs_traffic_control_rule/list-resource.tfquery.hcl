# terraform query lists the traffic control rules; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_traffic_control_rule resource for each.
list "pbs_traffic_control_rule" "all" {
  provider         = pbs
  include_resource = true
}
