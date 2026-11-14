terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

resource "pbs_realm_ldap" "corp" {
  realm     = "corp"
  server1   = "ldap.example.com"
  mode      = "ldaps"
  verify    = true
  base_dn   = "ou=people,dc=example,dc=com"
  user_attr = "uid"
  filter    = "(memberOf=cn=backup-users,ou=groups,dc=example,dc=com)"

  bind_dn             = "uid=pbs,ou=services,dc=example,dc=com"
  password_wo         = var.bind_password
  password_wo_version = 1

  sync_attributes = {
    email     = "mail"
    firstname = "givenName"
    lastname  = "sn"
  }

  # Sync the users as soon as the realm exists, and whenever its settings
  # change.
  lifecycle {
    action_trigger {
      events  = [after_create, after_update]
      actions = [action.pbs_realm_sync.corp]
    }
  }
}

# Creates the users of the directory's group backup-users, disabled until an
# administrator enables them, and updates the names and email addresses of
# the users it has. It deletes nothing: with "entry", a change of base_dn,
# filter, user_classes or user_attr would delete, in the same apply, every
# user of the realm the new search no longer finds, with their API tokens.
action "pbs_realm_sync" "corp" {
  config {
    realm           = pbs_realm_ldap.corp.realm
    enable_new      = false
    remove_vanished = [] # removes nothing, whatever sync_defaults says
  }
}

# Also deletes the users of the realm that left the group, with their API
# tokens and ACL entries. Nothing triggers it: preview what it would delete
# with dry_run = true, then run it with
# terraform apply -invoke=action.pbs_realm_sync.corp_prune
action "pbs_realm_sync" "corp_prune" {
  config {
    realm           = pbs_realm_ldap.corp.realm
    enable_new      = false
    remove_vanished = ["entry", "acl"]
  }
}

variable "bind_password" {
  description = "Password of uid=pbs,ou=services,dc=example,dc=com."
  type        = string
  sensitive   = true
  ephemeral   = true
}
