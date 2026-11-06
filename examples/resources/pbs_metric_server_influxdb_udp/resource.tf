# Send PBS's metrics as line protocol to the UDP listener of InfluxDB 1.x —
# or of Telegraf's socket_listener input, in front of InfluxDB 2 or 3. PBS
# needs only to resolve the name before it saves the server; whether
# anything listens shows only in InfluxDB.
resource "pbs_metric_server_influxdb_udp" "telegraf" {
  name    = "telegraf"
  host    = "telegraf.example.com:8089"
  comment = "Telegraf socket_listener"
}

# A listener on a network with jumbo frames takes larger datagrams.
resource "pbs_metric_server_influxdb_udp" "lab" {
  name = "influxdb-lab"
  host = "[2001:db8::10]:8089"
  mtu  = 9000
}
