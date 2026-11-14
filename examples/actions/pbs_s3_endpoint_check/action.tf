terraform {
  # Actions need Terraform 1.14.1 or later; Terraform 1.13 would ignore them.
  required_version = ">= 1.14.1"
}

# The MinIO endpoint of the pbs_s3_endpoint example, assumed in the same
# configuration. PBS contacts nothing when it saves an endpoint: the check
# shows, after every change of the endpoint, that PBS reaches the bucket and
# that the access key may write, read and delete objects under the prefix of
# the datastore that will use it. Or check it yourself:
# terraform apply -invoke=action.pbs_s3_endpoint_check.minio
resource "terraform_data" "minio_settings" {
  input = pbs_s3_endpoint.minio

  lifecycle {
    action_trigger {
      events  = [after_create, after_update]
      actions = [action.pbs_s3_endpoint_check.minio]
    }
  }
}

action "pbs_s3_endpoint_check" "minio" {
  config {
    s3_endpoint  = pbs_s3_endpoint.minio.id
    bucket       = "pbs-backups"
    store_prefix = "minio1"
  }
}
