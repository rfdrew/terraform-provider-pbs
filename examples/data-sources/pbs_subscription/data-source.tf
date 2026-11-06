data "pbs_subscription" "this" {}

check "pbs_subscription_is_active" {
  assert {
    condition     = data.pbs_subscription.this.status == "active"
    error_message = "The PBS subscription is ${data.pbs_subscription.this.status}."
  }
}
