data "pbs_metric_servers" "all" {}

# Where PBS sends its metrics, by name: the URL of an HTTP server, the
# host:port of a UDP one.
output "metric_targets" {
  value = {
    for s in data.pbs_metric_servers.all.servers : s.name => coalesce(s.url, s.host) if s.enable
  }
}
