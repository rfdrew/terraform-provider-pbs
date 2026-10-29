# Sign-in with FreeIPA accounts, as <uid>@ipa, such as alice@ipa: PBS looks
# the entry up below base_dn and checks the password by binding as it. PBS
# connects to the directory whenever the realm is created or changed — even
# just its comment — from the PBS host, not from where Terraform runs, and
# saves nothing when it cannot connect, bind as bind_dn and read base_dn: the
# apply fails with the reason.
resource "pbs_realm_ldap" "ipa" {
  realm   = "ipa"
  server1 = "ipa1.example.com"
  server2 = "ipa2.example.com"
  comment = "FreeIPA"

  # LDAP over TLS, on port 636, with the servers' certificates checked against
  # FreeIPA's own certificate authority. capath is a file on the PBS host,
  # which PBS reads on every connection: /etc/ipa/ca.crt on a host enrolled in
  # FreeIPA, or a copy of it. Changing or removing capath later replaces the
  # realm: PBS sets it only when it creates one.
  mode   = "ldaps"
  verify = true
  capath = "/etc/ipa/ca.crt"

  # A system account that may read the users. Its password is write-only: it
  # never reaches the plan or state, and PBS receives it when the realm is
  # created, which needs it, and whenever password_wo_version changes.
  # Increment the version after changing the password in FreeIPA: PBS binds on
  # every change, and fails while it has the old one.
  bind_dn             = "uid=pbs,cn=sysaccounts,cn=etc,dc=example,dc=com"
  password_wo         = var.ipa_bind_password
  password_wo_version = 1

  base_dn   = "cn=users,cn=accounts,dc=example,dc=com"
  user_attr = "uid"

  # Only users that exist in PBS can sign in. A sync creates them from the
  # directory — proxmox-backup-manager ldap sync ipa on the PBS host, or Sync
  # under Access Control > Realms in the web interface: here the members of
  # the group pbs, with their email addresses and names. It also deletes the
  # users of the realm it no longer finds, with their API tokens and ACL
  # entries — users Terraform manages included, which the next apply creates
  # again.
  filter = "(memberOf=cn=pbs,cn=groups,cn=accounts,dc=example,dc=com)"
  sync_attributes = {
    email     = "mail"
    firstname = "givenName"
    lastname  = "sn"
  }
  sync_defaults = {
    enable_new      = true
    remove_vanished = ["acl", "entry"]
  }
}

# A user of the realm, with read access to the datastores' contents, who can
# sign in before any sync. A sync sets the email address and names of every
# user it finds to the directory's, this one's too, so they match FreeIPA here.
resource "pbs_user" "alice" {
  userid    = "alice@${pbs_realm_ldap.ipa.realm}"
  email     = "alice@example.com"
  firstname = "Alice"
  lastname  = "Smith"
}

resource "pbs_acl" "alice" {
  path    = "/datastore"
  auth_id = pbs_user.alice.userid
  role    = "DatastoreReader"
}

variable "ipa_bind_password" {
  description = "Password of the PBS system account in FreeIPA."
  type        = string
  sensitive   = true
  ephemeral   = true
}
