package provider

import (
	"net/http"
	"testing"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

func TestACMEDataSourceSchemasAreValid(t *testing.T) {
	requireValidDataSourceSchema(t, NewACMEDirectoriesDataSource())
	requireValidDataSourceSchema(t, NewACMEChallengeSchemaDataSource())
	requireValidDataSourceSchema(t, NewACMEAccountsDataSource())
}

// The directories are those built into PBS, in its order: the default one,
// Let's Encrypt's production directory, first.
func TestACMEDirectoriesDataSource(t *testing.T) {
	h, fake, _ := newACMEHarness(t)
	config := h.dataSourceValue(t, "pbs_acme_directories", map[string]any{})

	state := h.readDataSource(t, "pbs_acme_directories", config)
	if lengthAt(t, state, "directories") != 2 ||
		stringAt(t, state, "directories", 0, "name") != "Let's Encrypt V2" ||
		stringAt(t, state, "directories", 0, "url") != pbsclient.DefaultACMEDirectory ||
		stringAt(t, state, "directories", 1, "name") != "Let's Encrypt V2 Staging" ||
		stringAt(t, state, "directories", 1, "url") != pbsclient.ACMEStagingDirectory {
		t.Fatalf("pbs_acme_directories = %s", state)
	}
	if fake.count("GET /config/acme/directories") != 1 {
		t.Errorf("routes = %v, want the directories read once", fake.routes())
	}

	fake.reply("GET /config/acme/directories", http.StatusInternalServerError, "internal error")
	resp := h.readDataSourceResponse(t, "pbs_acme_directories", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS ACME directories")
	requireProtocolErrorContaining(t, resp.Diagnostics, "internal error")
}

// The challenge schema is a map of the APIs by the id a plugin's api names,
// with what the schema file documents of each and null for what it leaves
// out.
func TestACMEChallengeSchemaDataSource(t *testing.T) {
	h, fake, _ := newACMEHarness(t)
	config := h.dataSourceValue(t, "pbs_acme_challenge_schema", map[string]any{})

	state := h.readDataSource(t, "pbs_acme_challenge_schema", config)
	if lengthAt(t, state, "apis") != 4 {
		t.Fatalf("pbs_acme_challenge_schema = %s, want four APIs", state)
	}

	// Cloudflare's fields have a type and a description, and no display
	// name, default or optional, which reads as false.
	cf := valueAt(t, state, "apis", "cf")
	if stringAt(t, cf, "name") != "Cloudflare Managed DNS" || stringAt(t, cf, "type") != "dns" ||
		stringAt(t, cf, "description") != "Either provide global account key and email, or CF API token and Account ID." ||
		lengthAt(t, cf, "fields") != 5 {
		t.Fatalf("cf = %s", cf)
	}
	for _, key := range []string{"CF_Account_ID", "CF_Email", "CF_Key", "CF_Token", "CF_Zone_ID"} {
		field := valueAt(t, cf, "fields", key)
		if stringAt(t, field, "type") != "string" || stringAt(t, field, "description") == "" || boolAt(t, field, "optional") ||
			!isNullAt(t, field, "label") || !isNullAt(t, field, "default") {
			t.Errorf("cf %s = %s", key, field)
		}
	}
	if got := stringAt(t, cf, "fields", "CF_Token", "description"); got != "The new Cloudflare API Token" {
		t.Errorf("CF_Token description = %q", got)
	}

	// Hetzner Cloud's API has no description, and optional fields with
	// defaults: the integer one as text.
	hetzner := valueAt(t, state, "apis", "hetznercloud")
	if stringAt(t, hetzner, "name") != "Hetzner Cloud" || !isNullAt(t, hetzner, "description") || lengthAt(t, hetzner, "fields") != 2 {
		t.Fatalf("hetznercloud = %s", hetzner)
	}
	if ttl := valueAt(t, hetzner, "fields", "HETZNER_TTL"); stringAt(t, ttl, "type") != "integer" || stringAt(t, ttl, "default") != "120" ||
		!boolAt(t, ttl, "optional") || stringAt(t, ttl, "description") != "TTL of the TXT records, in seconds" || !isNullAt(t, ttl, "label") {
		t.Errorf("HETZNER_TTL = %s", ttl)
	}
	if api := valueAt(t, hetzner, "fields", "HETZNER_API"); stringAt(t, api, "type") != "string" ||
		stringAt(t, api, "default") != "https://api.hetzner.cloud/v1" || !boolAt(t, api, "optional") {
		t.Errorf("HETZNER_API = %s", api)
	}

	// AWS's fields have display names.
	aws := valueAt(t, state, "apis", "aws")
	if stringAt(t, aws, "name") != "Amazon Route53 (AWS)" || lengthAt(t, aws, "fields") != 2 ||
		stringAt(t, aws, "fields", "AWS_ACCESS_KEY_ID", "label") != "ACCESS_KEY_ID" ||
		stringAt(t, aws, "fields", "AWS_ACCESS_KEY_ID", "description") != "The AWS access-key ID" ||
		stringAt(t, aws, "fields", "AWS_SECRET_ACCESS_KEY", "label") != "SECRET_ACCESS_KEY" {
		t.Errorf("aws = %s", aws)
	}

	// Most APIs document nothing: their name is their id, which PBS gives
	// in their stead, and their fields are empty, not null.
	hosting := valueAt(t, state, "apis", "1984hosting")
	if stringAt(t, hosting, "name") != "1984hosting" || stringAt(t, hosting, "type") != "dns" ||
		!isNullAt(t, hosting, "description") || isNullAt(t, hosting, "fields") || lengthAt(t, hosting, "fields") != 0 {
		t.Errorf("1984hosting = %s", hosting)
	}

	// Without libproxmox-acme-plugins PBS has no schema file: the error says
	// which package installs it.
	fake.reply("GET /config/acme/challenge-schema", http.StatusBadRequest,
		"unable to open file '/usr/share/proxmox-acme/dns-challenge-schema.json' - No such file or directory (os error 2)")
	resp := h.readDataSourceResponse(t, "pbs_acme_challenge_schema", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read the PBS ACME challenge schema")
	requireProtocolErrorContaining(t, resp.Diagnostics, "libproxmox-acme-plugins")
	requireProtocolErrorContaining(t, resp.Diagnostics, "No such file or directory")
}

// The schema file is written by hand: values of an unexpected kind are read
// leniently, as Perl and JavaScript read them, rather than failing the data
// source.
func TestACMEChallengeSchemaDataSourceReadsLeniently(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	acme.mu.Lock()
	acme.challengeSchema = `[
		{"id": "unnamed", "type": "dns", "schema": {"description": 42, "fields": {
			"FLAG": {"optional": "1", "default": true},
			"ZERO": {"optional": 0, "default": 0, "type": "integer"},
			"BLANK": {"optional": "0", "default": "", "name": "", "description": ["not", "text"]},
			"BROKEN": "not an object"
		}}},
		{"id": "blankname", "name": "", "type": "dns", "schema": {"fields": []}},
		{"id": "noschema", "name": "No Schema", "type": "dns"}
	]`
	acme.mu.Unlock()

	state := h.readDataSource(t, "pbs_acme_challenge_schema", h.dataSourceValue(t, "pbs_acme_challenge_schema", map[string]any{}))
	if lengthAt(t, state, "apis") != 3 {
		t.Fatalf("pbs_acme_challenge_schema = %s, want three APIs", state)
	}

	// A name that is missing or empty is the id; a description that is no
	// text is none.
	unnamed := valueAt(t, state, "apis", "unnamed")
	if stringAt(t, unnamed, "name") != "unnamed" || !isNullAt(t, unnamed, "description") || lengthAt(t, unnamed, "fields") != 4 {
		t.Fatalf("unnamed = %s", unnamed)
	}
	if flag := valueAt(t, unnamed, "fields", "FLAG"); !boolAt(t, flag, "optional") || stringAt(t, flag, "default") != "true" ||
		!isNullAt(t, flag, "type") || !isNullAt(t, flag, "label") || !isNullAt(t, flag, "description") {
		t.Errorf("FLAG = %s", flag)
	}
	if zero := valueAt(t, unnamed, "fields", "ZERO"); boolAt(t, zero, "optional") || stringAt(t, zero, "default") != "0" ||
		stringAt(t, zero, "type") != "integer" {
		t.Errorf("ZERO = %s", zero)
	}
	for _, key := range []string{"BLANK", "BROKEN"} {
		field := valueAt(t, unnamed, "fields", key)
		if boolAt(t, field, "optional") {
			t.Errorf("%s = %s, want it not optional", key, field)
		}
		for _, name := range []string{"label", "type", "description", "default"} {
			if !isNullAt(t, field, name) {
				t.Errorf("%s %s = %s, want null", key, name, valueAt(t, field, name))
			}
		}
	}

	// Fields that are no object, and a schema that is missing, are no
	// fields.
	if blank := valueAt(t, state, "apis", "blankname"); stringAt(t, blank, "name") != "blankname" || lengthAt(t, blank, "fields") != 0 {
		t.Errorf("blankname = %s", blank)
	}
	if none := valueAt(t, state, "apis", "noschema"); stringAt(t, none, "name") != "No Schema" ||
		!isNullAt(t, none, "description") || lengthAt(t, none, "fields") != 0 {
		t.Errorf("noschema = %s", none)
	}
}

// The accounts are sorted by name, with what PBS recorded of each, and
// null for the contacts and terms of service it has none of.
func TestACMEAccountsDataSource(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	config := h.dataSourceValue(t, "pbs_acme_accounts", map[string]any{})

	if empty := h.readDataSource(t, "pbs_acme_accounts", config); lengthAt(t, empty, "accounts") != 0 {
		t.Fatalf("pbs_acme_accounts = %s, want no accounts", empty)
	}

	acme.addAccount("le", fakeProperties{"directory": pbsclient.DefaultACMEDirectory, "location": "https://acme-v02.api.letsencrypt.org/acme/acct/1",
		"status": "valid", "contact": []string{"mailto:ops@example.org", "mailto:admin@example.org"}, "tos": fakeToS[pbsclient.DefaultACMEDirectory]})
	// Let's Encrypt has returned no contacts since June 2025, and an account
	// registered without agreeing to terms of service has none.
	acme.addAccount("default", fakeProperties{"directory": pbsclient.ACMEStagingDirectory,
		"location": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/2", "status": "valid"})
	acme.addAccount("pebble", fakeProperties{"directory": "https://pebble.test:14000/dir", "location": "https://pebble.test:14000/my-account/3",
		"status": "revoked", "contact": []string{"mailto:pki@example.org"}, "tos": fakeToS["https://pebble.test:14000/dir"]})

	list := h.readDataSource(t, "pbs_acme_accounts", config)
	if lengthAt(t, list, "accounts") != 3 || stringAt(t, list, "accounts", 0, "name") != "default" ||
		stringAt(t, list, "accounts", 1, "name") != "le" || stringAt(t, list, "accounts", 2, "name") != "pebble" {
		t.Fatalf("pbs_acme_accounts = %s, want default, le and pebble", list)
	}
	if stringAt(t, list, "accounts", 0, "directory") != pbsclient.ACMEStagingDirectory ||
		stringAt(t, list, "accounts", 0, "location") != "https://acme-staging-v02.api.letsencrypt.org/acme/acct/2" ||
		stringAt(t, list, "accounts", 0, "status") != "valid" ||
		!isNullAt(t, list, "accounts", 0, "contact") || !isNullAt(t, list, "accounts", 0, "tos_url") {
		t.Errorf("default = %s", valueAt(t, list, "accounts", 0))
	}
	// The contacts are the addresses, in the CA's order, as contact of
	// pbs_acme_account takes them.
	if stringAt(t, list, "accounts", 1, "directory") != pbsclient.DefaultACMEDirectory ||
		stringAt(t, list, "accounts", 1, "location") != "https://acme-v02.api.letsencrypt.org/acme/acct/1" ||
		stringAt(t, list, "accounts", 1, "status") != "valid" ||
		stringAt(t, list, "accounts", 1, "contact") != "ops@example.org,admin@example.org" ||
		stringAt(t, list, "accounts", 1, "tos_url") != fakeToS[pbsclient.DefaultACMEDirectory] {
		t.Errorf("le = %s", valueAt(t, list, "accounts", 1))
	}
	if stringAt(t, list, "accounts", 2, "directory") != "https://pebble.test:14000/dir" ||
		stringAt(t, list, "accounts", 2, "status") != "revoked" ||
		stringAt(t, list, "accounts", 2, "contact") != "pki@example.org" ||
		stringAt(t, list, "accounts", 2, "tos_url") != "data:text/plain,Do%20what%20thou%20wilt" {
		t.Errorf("pebble = %s", valueAt(t, list, "accounts", 2))
	}
	if fake.count("GET /config/acme/account") != 2 || fake.count("GET /config/acme/account/le") != 1 {
		t.Errorf("routes = %v, want the list read twice and each account once", fake.routes())
	}

	// The list and the accounts need Sys.Modify on /system/certificates.
	fake.reply("GET /config/acme/account", http.StatusForbidden, "permission check failed")
	resp := h.readDataSourceResponse(t, "pbs_acme_accounts", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to list PBS ACME accounts")
	requireProtocolErrorContaining(t, resp.Diagnostics, "Sys.Modify on /system/certificates")
}

// An account deactivated or deleted after PBS listed it is left out; an
// account PBS fails to read for another reason fails the data source.
func TestACMEAccountsDataSourceAccountsThatFailToRead(t *testing.T) {
	h, fake, acme := newACMEHarness(t)
	config := h.dataSourceValue(t, "pbs_acme_accounts", map[string]any{})
	for _, name := range []string{"a", "b", "c"} {
		acme.addAccount(name, fakeProperties{"directory": pbsclient.DefaultACMEDirectory, "location": "https://ca.test/acme/acct/" + name, "status": "valid"})
	}
	fake.handle("GET /config/acme/account", func(w http.ResponseWriter, req *http.Request) {
		acme.listAccounts(w, req)
		// Another client deactivates b before the provider reads it.
		acme.mu.Lock()
		delete(acme.accounts, "b")
		acme.mu.Unlock()
	})

	list := h.readDataSource(t, "pbs_acme_accounts", config)
	if lengthAt(t, list, "accounts") != 2 || stringAt(t, list, "accounts", 0, "name") != "a" || stringAt(t, list, "accounts", 1, "name") != "c" {
		t.Fatalf("pbs_acme_accounts = %s, want a and c", list)
	}
	if fake.count("GET /config/acme/account/b") != 1 {
		t.Errorf("routes = %v, want b read once", fake.routes())
	}

	fake.reply("GET /config/acme/account/c", http.StatusBadRequest,
		"failed to parse acme account file - EOF while parsing a value at line 1 column 0")
	resp := h.readDataSourceResponse(t, "pbs_acme_accounts", config)
	requireProtocolErrorContaining(t, resp.Diagnostics, "Unable to read PBS ACME account")
	requireProtocolErrorContaining(t, resp.Diagnostics, "EOF while parsing a value")
}

// An account pbs_acme_account registers shows in the list as PBS recorded
// it, and is gone from it once destroying deactivated it.
func TestACMEAccountsDataSourceListsRegisteredAccounts(t *testing.T) {
	h, _, acme := newACMEHarness(t)
	const tos = "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf"
	config := h.dataSourceValue(t, "pbs_acme_accounts", map[string]any{})

	le := h.create(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"tos_url": tos, "contact": "admin@example.org, ops@example.org"}))
	// A CA that returns no contacts leaves the data source none, while the
	// resource keeps those configured.
	acme.caForgets = true
	staging := h.create(t, "pbs_acme_account", accountConfig(t, h, map[string]any{"name": "staging", "directory": pbsclient.ACMEStagingDirectory}))

	list := h.readDataSource(t, "pbs_acme_accounts", config)
	if lengthAt(t, list, "accounts") != 2 || stringAt(t, list, "accounts", 0, "name") != "le" || stringAt(t, list, "accounts", 1, "name") != "staging" {
		t.Fatalf("pbs_acme_accounts = %s, want le and staging", list)
	}
	if stringAt(t, list, "accounts", 0, "directory") != stringAt(t, le.state, "directory") ||
		stringAt(t, list, "accounts", 0, "location") != stringAt(t, le.state, "location") ||
		stringAt(t, list, "accounts", 0, "status") != "valid" ||
		stringAt(t, list, "accounts", 0, "contact") != "admin@example.org,ops@example.org" ||
		stringAt(t, list, "accounts", 0, "tos_url") != tos {
		t.Errorf("le = %s, resource state %s", valueAt(t, list, "accounts", 0), le.state)
	}
	if stringAt(t, list, "accounts", 1, "directory") != pbsclient.ACMEStagingDirectory ||
		stringAt(t, list, "accounts", 1, "location") != stringAt(t, staging.state, "location") ||
		!isNullAt(t, list, "accounts", 1, "contact") || stringAt(t, staging.state, "contact") != "ops@example.org" ||
		!isNullAt(t, list, "accounts", 1, "tos_url") {
		t.Errorf("staging = %s, resource state %s", valueAt(t, list, "accounts", 1), staging.state)
	}

	h.destroy(t, le)
	list = h.readDataSource(t, "pbs_acme_accounts", config)
	if lengthAt(t, list, "accounts") != 1 || stringAt(t, list, "accounts", 0, "name") != "staging" {
		t.Fatalf("pbs_acme_accounts = %s after le was deactivated, want staging alone", list)
	}
}
