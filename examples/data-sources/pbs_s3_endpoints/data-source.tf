data "pbs_s3_endpoints" "all" {}

# Which object store each endpoint points at.
output "s3_endpoints" {
  value = { for e in data.pbs_s3_endpoints.all.endpoints : e.id => e.endpoint }
}
