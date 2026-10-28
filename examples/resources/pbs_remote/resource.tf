# The offsite PBS, as a remote of the PBS that holds the backups, so that a
# pbs_sync_job can push to it. On the offsite server, an API token,
# sync@pbs!primary here, signs the pushes in; it needs DatastoreBackup on the
# offsite datastore, for the token and its user both.
resource "pbs_remote" "offsite" {
  name    = "offsite"
  host    = "pbs-offsite.example.com"
  auth_id = "sync@pbs!primary"
  comment = "Offsite copy"

  # The offsite server's self-signed certificate, as its dashboard or
  # pbs_fingerprint there shows it. Leave it out for a certificate of a
  # public CA.
  fingerprint = "2f:f2:f7:e9:8b:a5:62:fe:bb:6d:63:40:33:8b:4a:97:e6:d4:80:5d:f9:96:b9:63:ee:4c:08:31:c2:d0:00:5c"

  # The token's secret is write-only: it never reaches the plan or state, and
  # PBS receives it when the remote is created and whenever
  # password_wo_version changes.
  password_wo         = var.offsite_token_secret
  password_wo_version = 1
}

variable "offsite_token_secret" {
  description = "Secret of the API token sync@pbs!primary on the offsite PBS."
  type        = string
  sensitive   = true
  ephemeral   = true
}
