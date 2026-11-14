# terraform query lists the roles granted on datastore store1, one result
# for each role of each user or API token; with
# -generate-config-out=generated.tf it also writes an import block and a
# pbs_acl resource for each.
list "pbs_acl" "store1" {
  provider         = pbs
  include_resource = true

  config {
    path = "/datastore/store1"
  }
}

# Every role of the API token pve@pbs!cluster1, on any path.
list "pbs_acl" "cluster1" {
  provider = pbs

  config {
    auth_id = "pve@pbs!cluster1"
  }
}
