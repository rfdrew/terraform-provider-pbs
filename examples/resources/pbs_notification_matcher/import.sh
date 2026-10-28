# Matchers are imported by name. The built-in default-matcher can only be
# imported, as PBS always has it; destroying it resets it to its built-in
# settings instead of deleting it.
terraform import pbs_notification_matcher.default default-matcher
