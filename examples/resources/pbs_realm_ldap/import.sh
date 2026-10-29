# LDAP realms are imported by name. PBS never returns the bind password, so an
# import reads none, and PBS keeps the one it has: with password_wo and
# password_wo_version in the configuration, the next apply sends password_wo;
# without them, a plan that replaces a realm with a bind_dn — for a new realm
# name, or a new or removed capath — fails, as PBS needs the password to
# create it.
terraform import pbs_realm_ldap.ipa ipa
