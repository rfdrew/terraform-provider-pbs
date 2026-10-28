# Plugins are imported by ID. The built-in standalone plugin, which answers
# HTTP-01 challenges on port 80, can only be imported, as PBS always has it;
# destroying it leaves it as it is.
terraform import pbs_acme_plugin.cloudflare cloudflare
