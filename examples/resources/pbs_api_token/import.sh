# API tokens are imported by token ID, <user ID>!<token name>. PBS never shows
# a token's secret again, so an imported token has no value until regenerate
# changes, which replaces the secret.
terraform import pbs_api_token.pve 'pve@pbs!cluster1'
