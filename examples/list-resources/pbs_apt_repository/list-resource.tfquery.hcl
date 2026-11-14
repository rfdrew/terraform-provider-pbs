# terraform query lists every entry of the node's APT source files; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_apt_repository resource for each.
list "pbs_apt_repository" "all" {
  provider         = pbs
  include_resource = true

  config {
    node = "localhost"
  }
}
