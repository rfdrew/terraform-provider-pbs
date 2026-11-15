terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# The proxy reads its cipher lists when it starts, reloads or loads a new
# certificate: reload it whenever they change, so that they take effect at
# once. The action first checks that OpenSSL takes the @ commands and
# operators of ciphers_tls_1_2 — its @SECLEVEL must be one digit from 0 to 5 —
# and that the proxy's certificate meets the security level the list sets,
# and refuses otherwise. PBS has OpenSSL check the rest of the list, such as
# whether its names match any cipher, when pbs_node_config stores it; a list
# written into node.cfg on the host gets no such check.
resource "pbs_node_config" "this" {
  ciphers_tls_1_2 = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
  ciphers_tls_1_3 = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
}

# Follows the cipher lists only, so that a change of another setting, such
# as the node's notes, does not reload the proxy.
resource "terraform_data" "proxy_ciphers" {
  input = [pbs_node_config.this.ciphers_tls_1_2, pbs_node_config.this.ciphers_tls_1_3]

  lifecycle {
    action_trigger {
      events  = [after_create, after_update]
      actions = [action.pbs_service_reload.proxy]
    }
  }
}

action "pbs_service_reload" "proxy" {
  config {
    service = "proxmox-backup-proxy"
  }
}

# Or reload a service yourself:
# terraform apply -invoke=action.pbs_service_reload.postfix
action "pbs_service_reload" "postfix" {
  config {
    service = "postfix"
  }
}
