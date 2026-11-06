# Send PBS's metrics to InfluxDB 2, into the bucket pbs of the organization
# ops, with a token that may write there. PBS checks the server — GET
# https://influxdb.example.com:8086/health — before it saves it, from its own
# host.
resource "pbs_metric_server_influxdb_http" "influxdb" {
  name         = "influxdb"
  url          = "https://influxdb.example.com:8086"
  organization = "ops"
  bucket       = "pbs"
  comment      = "Grafana dashboards"

  # The token is write-only: it never reaches the plan or state, and PBS
  # receives it when the server is created and whenever token_wo_version
  # changes.
  token_wo         = var.influxdb_token
  token_wo_version = 1
}

variable "influxdb_token" {
  description = "InfluxDB API token with write access to the bucket pbs."
  type        = string
  sensitive   = true
  ephemeral   = true
}

# InfluxDB 1.8 behind a reverse proxy that serves it below /influxdb: its
# write API for InfluxDB 2 clients takes the database and retention policy as
# the bucket, and the user and password as the token. The proxy's certificate
# comes from an internal CA, which must be in the PBS host's trust store
# (/usr/local/share/ca-certificates, then update-ca-certificates): with
# verify_tls = false, PBS would send the password to whatever answers there.
resource "pbs_metric_server_influxdb_http" "legacy" {
  name             = "influxdb-legacy"
  url              = "https://metrics.example.com/influxdb"
  bucket           = "pbs/autogen"
  token_wo         = "pbs:${var.influxdb_legacy_password}"
  token_wo_version = 1
}

variable "influxdb_legacy_password" {
  description = "Password of the InfluxDB 1.8 user pbs."
  type        = string
  sensitive   = true
  ephemeral   = true
}
