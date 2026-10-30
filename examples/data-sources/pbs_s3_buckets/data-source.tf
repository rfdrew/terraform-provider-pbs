# PBS connects to the object store to list its buckets, so reading this
# checks the endpoint: it fails when the address, the keys or the fingerprint
# are wrong, and when the region is wrong only where the object store checks
# it — not with {{region}} in the endpoint, as at AWS, where PBS asks the
# region set, which lists the buckets of every region. Listing needs PBS
# 4.0.8 or newer. The access key must be allowed to list the buckets
# of its account, which a key limited to one bucket may not be; the
# datastores do not need that. In a check block, a failure is a warning, not
# an error. Referring to the id of pbs_s3_endpoint.aws, of the
# pbs_s3_endpoint example, reads it after the endpoint is created or changed.
check "s3_bucket_is_reachable" {
  data "pbs_s3_buckets" "aws" {
    s3_endpoint = pbs_s3_endpoint.aws.id
  }

  assert {
    condition     = contains(data.pbs_s3_buckets.aws.buckets[*].name, "pbs-backups")
    error_message = "The access key of S3 endpoint aws sees no bucket pbs-backups."
  }
}
