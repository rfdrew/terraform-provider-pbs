# terraform query lists the InfluxDB UDP metric servers; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_metric_server_influxdb_udp resource for each.
list "pbs_metric_server_influxdb_udp" "all" {
  provider         = pbs
  include_resource = true
}
