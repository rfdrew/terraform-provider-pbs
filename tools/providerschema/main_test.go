package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/rfdrew/terraform-provider-pbs/internal/provider"
)

// The document must be one tfplugindocs accepts: terraform-json validates the
// format version when it decodes it.
func TestProviderSchemasDecodeWithTerraformJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "schema.json")
	if err := run(context.Background(), out, "pbs"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	var decoded tfjson.ProviderSchemas
	if err := decoded.UnmarshalJSON(raw); err != nil {
		t.Fatalf("terraform-json rejected the document: %v", err)
	}
	schema, ok := decoded.Schemas["pbs"]
	if !ok {
		t.Fatalf("no provider under the key pbs: %v", decoded.Schemas)
	}
	if got := len(schema.ConfigSchema.Block.Attributes); got != 10 {
		t.Errorf("provider block has %d attributes, want 10", got)
	}
	password := schema.ConfigSchema.Block.Attributes["password"]
	if password == nil || !password.Sensitive || !password.Optional || password.DescriptionKind != tfjson.SchemaDescriptionKindMarkdown {
		t.Errorf("password = %+v, want an optional sensitive attribute with a Markdown description", password)
	}
	if schema.ConfigSchema.Block.DescriptionKind != tfjson.SchemaDescriptionKindMarkdown ||
		!strings.Contains(schema.ConfigSchema.Block.Description, "Proxmox Backup Server") {
		t.Errorf("provider description = %q (%s)", schema.ConfigSchema.Block.Description, schema.ConfigSchema.Block.DescriptionKind)
	}
}

func TestTheProviderIsKeyedByItsAddressByDefault(t *testing.T) {
	schemas, err := providerSchemas(context.Background(), provider.Address)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := schemas.Schemas["registry.terraform.io/rfdrew/pbs"]; !ok || schemas.FormatVersion != "1.0" {
		t.Fatalf("schemas = %+v", schemas)
	}
}

// Every construct the framework can serve is converted the way Terraform
// prints it.
func TestConvertProviderSchema(t *testing.T) {
	markdown := tfprotov6.StringKindMarkdown
	resp := &tfprotov6.GetProviderSchemaResponse{
		Provider: &tfprotov6.Schema{Block: &tfprotov6.SchemaBlock{
			Description:     "The provider.",
			DescriptionKind: markdown,
			Attributes: []*tfprotov6.SchemaAttribute{
				{Name: "url", Type: tftypes.String, Optional: true, Description: "Root URL.", DescriptionKind: markdown},
			},
		}},
		ResourceSchemas: map[string]*tfprotov6.Schema{
			"pbs_thing": {Version: 1, Block: &tfprotov6.SchemaBlock{
				Attributes: []*tfprotov6.SchemaAttribute{
					{Name: "id", Type: tftypes.String, Computed: true},
					{Name: "tags", Type: tftypes.Set{ElementType: tftypes.String}, Optional: true},
					{Name: "headers", Type: tftypes.Map{ElementType: tftypes.String}, Optional: true, Sensitive: true},
					{Name: "loose", Type: tftypes.Object{
						AttributeTypes:     map[string]tftypes.Type{"a": tftypes.Number},
						OptionalAttributes: map[string]struct{}{"a": {}},
					}, Optional: true},
					{Name: "retention", Optional: true, NestedType: &tfprotov6.SchemaObject{
						Nesting: tfprotov6.SchemaObjectNestingModeSingle,
						Attributes: []*tfprotov6.SchemaAttribute{
							{Name: "keep_latest", Type: tftypes.Number, Optional: true, Description: "Keep.", DescriptionKind: markdown},
						},
					}},
					{Name: "times", Optional: true, NestedType: &tfprotov6.SchemaObject{
						Nesting:    tfprotov6.SchemaObjectNestingModeSet,
						Attributes: []*tfprotov6.SchemaAttribute{{Name: "hour", Type: tftypes.Number, Required: true}},
					}},
					{Name: "secret_wo", Type: tftypes.String, Optional: true, Sensitive: true, WriteOnly: true},
					{Name: "old", Type: tftypes.Bool, Optional: true, Deprecated: true},
				},
				BlockTypes: []*tfprotov6.SchemaNestedBlock{{
					TypeName: "rule",
					Nesting:  tfprotov6.SchemaNestedBlockNestingModeList,
					MaxItems: 2,
					Block: &tfprotov6.SchemaBlock{Attributes: []*tfprotov6.SchemaAttribute{
						{Name: "value", Type: tftypes.String, Required: true},
					}},
				}},
			}},
		},
		DataSourceSchemas: map[string]*tfprotov6.Schema{
			"pbs_things": {Block: &tfprotov6.SchemaBlock{Attributes: []*tfprotov6.SchemaAttribute{
				{Name: "names", Type: tftypes.List{ElementType: tftypes.String}, Computed: true},
			}}},
		},
		ListResourceSchemas: map[string]*tfprotov6.Schema{
			"pbs_thing": {Block: &tfprotov6.SchemaBlock{}},
		},
		ActionSchemas: map[string]*tfprotov6.ActionSchema{
			"pbs_poke": {Schema: &tfprotov6.Schema{Block: &tfprotov6.SchemaBlock{Attributes: []*tfprotov6.SchemaAttribute{
				{Name: "target", Type: tftypes.String, Required: true},
			}}}},
		},
	}
	identities := map[string]*tfprotov6.ResourceIdentitySchema{
		"pbs_thing": {IdentityAttributes: []*tfprotov6.ResourceIdentitySchemaAttribute{
			{Name: "target", Type: tftypes.String, RequiredForImport: true, Description: "Target."},
		}},
	}

	converted, err := convertProviderSchema(resp, identities)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(converted)
	if err != nil {
		t.Fatal(err)
	}

	const want = `{
	  "provider": {"version": 0, "block": {
	    "attributes": {"url": {"type": "string", "description": "Root URL.", "description_kind": "markdown", "optional": true}},
	    "description": "The provider.", "description_kind": "markdown"}},
	  "resource_schemas": {"pbs_thing": {"version": 1, "block": {
	    "attributes": {
	      "id": {"type": "string", "description_kind": "plain", "computed": true},
	      "tags": {"type": ["set", "string"], "description_kind": "plain", "optional": true},
	      "headers": {"type": ["map", "string"], "description_kind": "plain", "optional": true, "sensitive": true},
	      "loose": {"type": ["object", {"a": "number"}, ["a"]], "description_kind": "plain", "optional": true},
	      "retention": {"nested_type": {"nesting_mode": "single", "attributes": {
	        "keep_latest": {"type": "number", "description": "Keep.", "description_kind": "markdown", "optional": true}}},
	        "description_kind": "plain", "optional": true},
	      "times": {"nested_type": {"nesting_mode": "set", "attributes": {
	        "hour": {"type": "number", "description_kind": "plain", "required": true}}},
	        "description_kind": "plain", "optional": true},
	      "secret_wo": {"type": "string", "description_kind": "plain", "optional": true, "sensitive": true, "write_only": true},
	      "old": {"type": "bool", "description_kind": "plain", "deprecated": true, "optional": true}
	    },
	    "block_types": {"rule": {"nesting_mode": "list", "max_items": 2, "block": {
	      "attributes": {"value": {"type": "string", "description_kind": "plain", "required": true}},
	      "description_kind": "plain"}}},
	    "description_kind": "plain"}}},
	  "data_source_schemas": {"pbs_things": {"version": 0, "block": {
	    "attributes": {"names": {"type": ["list", "string"], "description_kind": "plain", "computed": true}},
	    "description_kind": "plain"}}},
	  "action_schemas": {"pbs_poke": {"block": {
	    "attributes": {"target": {"type": "string", "description_kind": "plain", "required": true}},
	    "description_kind": "plain"}}},
	  "list_resource_schemas": {"pbs_thing": {"version": 0, "block": {"description_kind": "plain"}}},
	  "resource_identity_schemas": {"pbs_thing": {"version": 0, "attributes": {
	    "target": {"type": "string", "description": "Target.", "required_for_import": true}}}}
	}`

	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		pretty, _ := json.MarshalIndent(gotValue, "", "  ")
		t.Fatalf("converted schema:\n%s", pretty)
	}
}

func TestConvertProviderSchemaRefusesWhatItCannotConvert(t *testing.T) {
	resp := &tfprotov6.GetProviderSchemaResponse{
		Provider:  &tfprotov6.Schema{Block: &tfprotov6.SchemaBlock{}},
		Functions: map[string]*tfprotov6.Function{"parse_target": {}},
	}
	if _, err := convertProviderSchema(resp, nil); err == nil || !strings.Contains(err.Error(), "parse_target") {
		t.Fatalf("convertProviderSchema() error = %v, want a refusal naming the function", err)
	}

	untyped := &tfprotov6.GetProviderSchemaResponse{Provider: &tfprotov6.Schema{Block: &tfprotov6.SchemaBlock{
		Attributes: []*tfprotov6.SchemaAttribute{{Name: "broken", Optional: true}},
	}}}
	if _, err := convertProviderSchema(untyped, nil); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("convertProviderSchema() error = %v, want one naming the untyped attribute", err)
	}
}
