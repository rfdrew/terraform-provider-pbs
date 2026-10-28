data "pbs_verify_job" "store1" {
  id = "verify-store1"
}

output "store1_verification" {
  value = "${data.pbs_verify_job.store1.store}: ${coalesce(data.pbs_verify_job.store1.schedule, "by hand only")}"
}
