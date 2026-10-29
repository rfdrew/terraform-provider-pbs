# S3 endpoints are imported by ID. PBS never returns the secret key, so
# secret_key_wo_version is empty after an import: leave secret_key_wo and
# secret_key_wo_version out to keep the secret key PBS has, as a
# configuration that sets them sends secret_key_wo in the next apply.
terraform import pbs_s3_endpoint.aws aws
