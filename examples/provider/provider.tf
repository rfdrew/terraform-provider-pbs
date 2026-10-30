terraform {
  required_providers {
    pbs = {
      source  = "rfdrew/pbs"
      version = "~> 0.3"
    }
  }
}

# Credentials are best supplied through the environment so they stay out of
# the configuration: PBS_ENDPOINT, PBS_API_TOKEN and PBS_TLS_FINGERPRINT.
provider "pbs" {
  endpoint  = "https://pbs.example.com:8007"
  api_token = var.pbs_api_token

  # PBS generated its own certificate at installation; its dashboard shows the
  # fingerprint under "Show Fingerprint".
  tls_cert_fingerprint = "2f:f2:f7:e9:8b:a5:62:fe:bb:6d:63:40:33:8b:4a:97:e6:d4:80:5d:f9:96:b9:63:ee:4c:08:31:c2:d0:00:5c"
}

variable "pbs_api_token" {
  description = "PBS API token, as PBS shows it when the token is created: <user>@<realm>!<token name>:<secret>."
  type        = string
  sensitive   = true
}
