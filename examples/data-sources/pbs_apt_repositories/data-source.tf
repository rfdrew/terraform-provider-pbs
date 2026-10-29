data "pbs_apt_repositories" "this" {}

# The standard repositories the host has enabled, such as ["enterprise"] on
# a fresh installation.
output "enabled_standard_repositories" {
  value = [for r in data.pbs_apt_repositories.this.standard_repositories : r.handle if r.enabled]
}

# Where the enterprise repository's entry is, for a pbs_apt_repository that
# disables it; null when the host has none.
output "enterprise_entry" {
  value = one([
    for r in data.pbs_apt_repositories.this.standard_repositories :
    { file_path = r.file_path, index = r.index } if r.handle == "enterprise" && r.file_path != null
  ])
}

# Files PBS cannot parse, which it leaves out of the list.
output "broken_source_files" {
  value = data.pbs_apt_repositories.this.errors
}
