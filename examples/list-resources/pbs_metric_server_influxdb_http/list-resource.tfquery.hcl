# terraform query lists the InfluxDB HTTP metric servers; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_metric_server_influxdb_http resource for each. The servers keep the
# tokens PBS has.
list "pbs_metric_server_influxdb_http" "all" {
  provider         = pbs
  include_resource = true
}
