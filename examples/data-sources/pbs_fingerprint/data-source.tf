data "pbs_fingerprint" "this" {}

# Register the PBS as a storage in Proxmox VE, pinned to its certificate,
# with the bpg/proxmox provider.
resource "proxmox_storage_pbs" "backup" {
  id          = "pbs"
  server      = "pbs.example.com"
  datastore   = "main"
  username    = "pve@pbs!cluster1"
  password    = var.pbs_token_secret
  fingerprint = data.pbs_fingerprint.this.fingerprint
}

variable "pbs_token_secret" {
  type      = string
  sensitive = true
}

# Warn a month before the certificate runs out.
check "pbs_certificate_is_valid" {
  assert {
    condition     = timecmp(data.pbs_fingerprint.this.not_after, timeadd(plantimestamp(), "720h")) > 0
    error_message = "The PBS certificate expires on ${data.pbs_fingerprint.this.not_after}."
  }
}
