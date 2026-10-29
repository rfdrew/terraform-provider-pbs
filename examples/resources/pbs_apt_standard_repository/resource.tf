# The no-subscription repository, for a host without a subscription. PBS
# adds its entry to /etc/apt/sources.list.d/proxmox.sources, or enables the
# entry the host has.
resource "pbs_apt_standard_repository" "no_subscription" {
  handle = "no-subscription"
}

# The test repository, kept off until it is needed. PBS adds its entry
# enabled; the pbs_apt_repository, which refers to where the standard
# repository says the entry is, disables it right after, in the same apply.
resource "pbs_apt_standard_repository" "test" {
  handle = "test"
}

resource "pbs_apt_repository" "test" {
  file_path = pbs_apt_standard_repository.test.file_path
  index     = pbs_apt_standard_repository.test.index
  enabled   = false
}
