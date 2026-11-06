data "pbs_node_certificates" "this" {}

locals {
  # The certificate the web interface and API serve; PBS has no other.
  pbs_certificate = one([for c in data.pbs_node_certificates.this.certificates : c if c.filename == "proxy.pem"])
}

# The certificate and its chain, for clients that verify PBS against a CA
# file rather than by its fingerprint.
output "pbs_certificate_pem" {
  value = local.pbs_certificate.pem
}

# Warn a month before the certificate runs out, and while PBS still serves
# the self-signed certificate it generated.
check "pbs_certificate" {
  assert {
    condition     = timecmp(local.pbs_certificate.not_after, timeadd(plantimestamp(), "720h")) > 0
    error_message = "The PBS certificate expires on ${local.pbs_certificate.not_after}."
  }
  assert {
    condition     = local.pbs_certificate.issuer != local.pbs_certificate.subject
    error_message = "PBS still serves a self-signed certificate for ${join(", ", local.pbs_certificate.san)}."
  }
}
