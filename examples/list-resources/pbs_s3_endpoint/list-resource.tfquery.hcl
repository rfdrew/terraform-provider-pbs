# terraform query lists the S3 endpoints; with -generate-config-out=generated.tf
# it also writes an import block and a pbs_s3_endpoint resource for each. Fill
# in access_key before planning: it is sensitive, so the results leave it out.
list "pbs_s3_endpoint" "all" {
  provider         = pbs
  include_resource = true
}
