data "pbs_version" "this" {}

# Stop early when the server is older than a feature needs.
check "pbs_is_recent" {
  assert {
    condition     = data.pbs_version.this.major > 4 || (data.pbs_version.this.major == 4 && data.pbs_version.this.minor >= 2)
    error_message = "This configuration needs PBS 4.2 or newer; the server runs ${data.pbs_version.this.version}."
  }
}
