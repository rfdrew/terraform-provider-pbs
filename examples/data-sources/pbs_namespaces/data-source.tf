# Every namespace of the datastore store1.
data "pbs_namespaces" "store1" {
  store = "store1"
}

# A verify job for each namespace at the top level — cluster1 and so on —
# that verifies it and the namespaces below it. A job ID has at most 32
# characters, and a namespace's name as many, so the ID is derived from a
# hash of the name, and the comment names the namespace.
data "pbs_namespaces" "top" {
  store     = "store1"
  max_depth = 1
}

resource "pbs_verify_job" "per_namespace" {
  for_each = toset(data.pbs_namespaces.top.namespaces)

  id       = "verify-${substr(sha1(each.key), 0, 12)}"
  store    = "store1"
  ns       = each.key
  schedule = "sat 03:00"
  comment  = "Verifies namespace ${each.key}"
}

# The namespaces below cluster1, such as cluster1/hosts.
data "pbs_namespaces" "cluster1" {
  store  = "store1"
  parent = "cluster1"
}
