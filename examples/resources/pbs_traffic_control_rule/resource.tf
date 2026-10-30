# On working days from 8:00 to 18:00, server time, the clients in the office
# network share 100 MB per second for what they send PBS, such as backups,
# and 50 MB per second for what PBS sends them, such as restores, so that
# backups leave bandwidth for the office. At other times the rule does not
# apply, and nothing is limited. Only connections clients open to PBS are
# limited: sync jobs and S3 endpoints have rate limits of their own.
resource "pbs_traffic_control_rule" "office" {
  name      = "office"
  network   = ["192.0.2.0/24", "2001:db8:1::/48"]
  timeframe = ["mon..fri 8:00-18:00"]
  rate_in   = "100MB"
  rate_out  = "50MB"
  comment   = "Office hours"
}

# PBS applies one rule to a connection, the best match, and a rule with users
# beats one without. So another PBS that pulls from this one as offsite@pbs
# gets 20 MB per second from any network, office included, at any time
# (PBS 4.1+). After a quiet period, up to 200 MB pass at once.
resource "pbs_traffic_control_rule" "offsite_pulls" {
  name      = "offsite-pulls"
  network   = ["0.0.0.0/0", "::/0"]
  users     = ["offsite@pbs"]
  rate_out  = "20MB"
  burst_out = "200MB"
  comment   = "Pulls of pbs-offsite.example.com"
}
