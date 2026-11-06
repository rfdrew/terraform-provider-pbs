# InfluxDB HTTP metric servers are imported by name, as Configuration →
# Metric Server in the web interface, or the pbs_metric_servers data source,
# shows it. PBS never returns the token, so token_wo_version is empty after an
# import: a configuration that sets it sends token_wo in the next apply,
# replacing the token PBS has, and PBS first checks an enabled server with
# that token. Leave token_wo and token_wo_version out to keep the token PBS
# has.
terraform import pbs_metric_server_influxdb_http.influxdb influxdb
