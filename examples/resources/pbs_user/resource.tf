# A user of PBS's own realm, for a Proxmox VE cluster. It has no privileges
# until pbs_acl grants them, and PVE signs in with an API token of it, which
# needs ACL entries of its own.
resource "pbs_user" "pve" {
  userid  = "pve@pbs"
  comment = "PVE cluster"
}

# A person who signs in to the web interface. The password is write-only: it
# never reaches the plan or state, and PBS receives it when the user is
# created and whenever password_wo_version changes. Changing it later needs a
# provider that signs in with a username and password, not an API token.
resource "pbs_user" "alice" {
  userid    = "alice@pbs"
  firstname = "Alice"
  lastname  = "Example"
  email     = "alice@example.com"

  password_wo         = var.alice_password
  password_wo_version = 1
}

# An account of the host, through the pam realm: it signs in with the host's
# password, and PBS keeps only its settings. It expires at the end of 2026.
resource "pbs_user" "operator" {
  userid = "operator@pam"
  expire = 1798761600
}

variable "alice_password" {
  description = "Initial password of alice@pbs, 8 to 64 characters."
  type        = string
  sensitive   = true
  ephemeral   = true
}
