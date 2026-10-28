# Order the certificate for the domains of the pbs_node_acme example, and a
# new one whenever they change. PBS renews it on its own.
resource "pbs_node_certificate" "this" {
  source = "acme"

  triggers = {
    domains = join(",", sort(pbs_node_acme.this.domains[*].domain))
  }
}

# Once PBS serves a certificate of a public CA, trust it by the CA: the
# provider without tls_cert_fingerprint, its endpoint one of the domains.
provider "pbs" {
  endpoint = "https://pbs.example.net:8007"
}

# PBS renews once a third of the certificate's lifetime is left: 30 days
# before a 90-day certificate expires, 15 before a 45-day one. Ten days
# before, the renewal has failed.
check "pbs_certificate_is_renewed" {
  assert {
    condition     = timecmp(pbs_node_certificate.this.not_after, timeadd(plantimestamp(), "240h")) > 0
    error_message = "The PBS certificate expires on ${pbs_node_certificate.this.not_after}; check the renewal task in PBS."
  }
}
