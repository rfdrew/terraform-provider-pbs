data "pbs_s3_endpoint" "aws" {
  id = "aws"
}

# Backups to S3 are to leave bandwidth for the rest; warn when someone
# removed the endpoint's upload limit.
check "s3_uploads_are_limited" {
  assert {
    condition     = data.pbs_s3_endpoint.aws.rate_out != null
    error_message = "S3 endpoint aws has no rate_out: backups to S3 may take the whole uplink."
  }
}
