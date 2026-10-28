# Sign-in through Authentik. In Authentik, PBS is an OAuth2/OpenID provider
# with an application whose slug, here "pbs", ends the issuer URL; its
# redirect URI is the address of PBS's web interface, such as
# https://pbs.example.com:8007. PBS contacts Authentik only when someone signs
# in, so a wrong issuer or key shows then, not on apply.
resource "pbs_realm_openid" "authentik" {
  realm      = "authentik"
  issuer_url = "https://authentik.example.com/application/o/pbs/"
  client_id  = "pbs"
  comment    = "Authentik"

  # The client secret is write-only: it never reaches the plan or state, and
  # PBS receives it when the realm is created and whenever
  # client_key_wo_version changes. client_key would keep it in state instead,
  # where a change made outside Terraform shows.
  client_key_wo         = var.authentik_client_secret
  client_key_wo_version = 1

  # Users are <Authentik username>@authentik. Changing the claim later
  # replaces the realm.
  username_claim = "preferred_username"

  # Users that do not exist yet are created at their first sign-in, without
  # privileges; the sign-in form preselects the realm.
  autocreate = true
  default    = true
}

# A user of the realm, with read access to the datastores' contents. Created
# beforehand, it can sign in with autocreate = false too.
resource "pbs_user" "alice" {
  userid = "alice@${pbs_realm_openid.authentik.realm}"
  email  = "alice@example.com"
}

resource "pbs_acl" "alice" {
  path    = "/datastore"
  auth_id = pbs_user.alice.userid
  role    = "DatastoreReader"
}

variable "authentik_client_secret" {
  description = "Client secret of the PBS provider in Authentik."
  type        = string
  sensitive   = true
  ephemeral   = true
}
