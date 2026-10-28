# OpenID realms are imported by name. An import reads no client key: with
# client_key in the configuration, or client_key_wo and its version, the next
# apply sends the configured key to PBS; with neither, PBS keeps its key, until
# a new realm or username_claim replaces the realm without it.
terraform import pbs_realm_openid.authentik authentik
