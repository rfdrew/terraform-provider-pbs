# Amazon S3 in eu-central-1, for datastores on S3. PBS puts a datastore's
# bucket into the host name, in place of {{bucket}}, and the region in place
# of {{region}}, so one endpoint serves every bucket the access key reaches.
# The buckets and the access key are created at AWS: PBS creates neither, and
# contacts nothing when it saves the endpoint.
resource "pbs_s3_endpoint" "aws" {
  id         = "aws"
  endpoint   = "{{bucket}}.s3.{{region}}.amazonaws.com"
  region     = "eu-central-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"

  # The secret key is write-only: it never reaches the plan or state, and
  # PBS receives it when the endpoint is created and whenever
  # secret_key_wo_version changes.
  secret_key_wo         = var.aws_secret_access_key
  secret_key_wo_version = 1

  # All datastores on the endpoint together upload at most 50 MB per second,
  # leaving bandwidth for the rest (PBS 4.1+). Traffic control rules do not
  # limit what PBS sends to S3.
  rate_out = "50MB"
}

# MinIO in the local network, with a self-signed certificate on port 9000.
# Like Ceph RGW, it takes the bucket in the path of a request rather than in
# the host name.
resource "pbs_s3_endpoint" "minio" {
  id         = "minio"
  endpoint   = "minio.example.com"
  port       = 9000
  path_style = true
  access_key = "pbs"

  # The certificate's SHA-256 fingerprint, as
  # `openssl x509 -noout -fingerprint -sha256 -in public.crt` shows it. Leave
  # it out for a certificate of a public CA.
  fingerprint = "7c:47:fd:cb:f4:62:f9:0e:93:ad:74:5f:39:fe:c4:d2:f7:4f:d9:6e:1d:af:f8:ae:ae:9a:ad:ff:95:19:62:50"

  secret_key_wo         = var.minio_secret_key
  secret_key_wo_version = 1
}

variable "aws_secret_access_key" {
  description = "Secret access key of AKIAIOSFODNN7EXAMPLE at AWS."
  type        = string
  sensitive   = true
  ephemeral   = true
}

variable "minio_secret_key" {
  description = "Secret key of the access key pbs on minio.example.com."
  type        = string
  sensitive   = true
  ephemeral   = true
}
