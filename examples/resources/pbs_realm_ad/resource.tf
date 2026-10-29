# Sign-in with Active Directory accounts, as <sAMAccountName>@ad, such as
# alice@ad: PBS looks the account up by sAMAccountName and checks the password
# by binding as it. PBS connects to a domain controller whenever the realm is
# created or changed — even just its comment — from the PBS host, not from
# where Terraform runs, and saves nothing when it cannot connect, bind as
# bind_dn and read base_dn: the apply fails with the reason.
resource "pbs_realm_ad" "ad" {
  realm   = "ad"
  server1 = "dc1.example.com"
  server2 = "dc2.example.com"
  comment = "Active Directory example.com"

  # LDAP over TLS, on port 636, with the domain controllers' certificates
  # checked against the system's certificate authorities, to which the
  # domain's own CA was added on the PBS host (update-ca-certificates); capath
  # names a CA certificate otherwise. mode = "ldap+starttls" uses port 389
  # instead.
  mode   = "ldaps"
  verify = true

  # The account PBS looks users up as, in UPN form; a distinguished name, such
  # as cn=pbs,cn=Users,dc=example,dc=com, works as well. Its password is
  # write-only: it never reaches the plan or state, and PBS receives it when
  # the realm is created, which needs it, and whenever password_wo_version
  # changes. Increment the version after changing the password in Active
  # Directory: PBS binds on every change, and fails while it has the old one.
  bind_dn             = "pbs@example.com"
  password_wo         = var.ad_bind_password
  password_wo_version = 1

  # No base_dn: PBS asks the domain controller for the domain's naming
  # context, dc=example,dc=com, when it creates the realm, and keeps it. Set
  # it to look users up below one organizational unit only.

  # Only users that exist in PBS can sign in: pbs_user creates them, or a sync
  # does — proxmox-backup-manager ad sync ad on the PBS host, or Sync under
  # Access Control > Realms in the web interface. The filter limits a sync to
  # the members of one group: otherwise it takes every entry that is a person
  # or user, computer accounts included. Without sync_attributes, it creates
  # users without email address or names, and leaves those of existing users
  # alone.
  filter = "(memberOf=cn=PBS Users,ou=Groups,dc=example,dc=com)"

  # The sign-in form preselects the realm. Only one realm is the default: set
  # it on one realm only.
  default = true
}

# A user of the realm, the domain account alice, who may manage the
# datastores.
resource "pbs_user" "alice" {
  userid = "alice@${pbs_realm_ad.ad.realm}"
  email  = "alice@example.com"
}

resource "pbs_acl" "alice" {
  path    = "/datastore"
  auth_id = pbs_user.alice.userid
  role    = "DatastoreAdmin"
}

variable "ad_bind_password" {
  description = "Password of the PBS service account in Active Directory."
  type        = string
  sensitive   = true
  ephemeral   = true
}
