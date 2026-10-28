data "pbs_remote" "offsite" {
  name = "offsite"
}

# Warn when the remote trusts the offsite server by a fingerprint that is no
# longer the one of its certificate, read there with a second provider
# configuration, aliased offsite.
data "pbs_fingerprint" "offsite" {
  provider = pbs.offsite
}

check "offsite_fingerprint_is_current" {
  assert {
    condition     = data.pbs_remote.offsite.fingerprint == null || data.pbs_remote.offsite.fingerprint == data.pbs_fingerprint.offsite.fingerprint
    error_message = "Remote offsite pins ${data.pbs_remote.offsite.fingerprint}, but the offsite PBS serves ${data.pbs_fingerprint.offsite.fingerprint}."
  }
}
