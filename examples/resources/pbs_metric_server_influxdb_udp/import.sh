# InfluxDB UDP metric servers are imported by name, as Configuration → Metric
# Server in the web interface, or the pbs_metric_servers data source, shows
# it.
terraform import pbs_metric_server_influxdb_udp.telegraf telegraf
