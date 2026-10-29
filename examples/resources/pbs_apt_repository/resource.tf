# A host without a subscription: the enterprise repository, which PBS
# installs enabled, is turned off, and the no-subscription repository is
# added in its place.
resource "pbs_apt_repository" "enterprise" {
  file_path = "/etc/apt/sources.list.d/pbs-enterprise.sources"
  index     = 0
  enabled   = false
}

resource "pbs_apt_standard_repository" "no_subscription" {
  handle = "no-subscription"
}

# Rather than written down, the place of a standard repository's entry can
# be looked up, here for the test repository, should the host have one.
data "pbs_apt_repositories" "this" {}

locals {
  test = one([
    for r in data.pbs_apt_repositories.this.standard_repositories : r
    if r.handle == "test" && r.file_path != null
  ])
}

resource "pbs_apt_repository" "test" {
  count = local.test == null ? 0 : 1

  file_path = local.test.file_path
  index     = local.test.index
  enabled   = false
}
