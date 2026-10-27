// Command providerschema writes the provider's schema as `terraform providers
// schema -json` would print it, without Terraform and without running the
// provider as a plugin.
//
// tfplugindocs normally builds the provider, installs it into a scratch
// Terraform working directory and asks Terraform for the schema. Where that is
// impossible — no network to download Terraform, or a sandbox that does not
// let Terraform start plugins — `make docs-offline` runs this command instead
// and hands the file to `tfplugindocs generate --providers-schema`. The schema
// comes from the same protocol server Terraform talks to, converted the way
// Terraform converts it (internal/command/jsonprovider in Terraform): every
// attribute and block carries its description kind, nested attributes carry
// nested_type instead of type, and resource identities are listed under
// resource_identity_schemas.
//
// Usage:
//
//	go run ./tools/providerschema [-o schema.json] [-key registry.terraform.io/rfdrew/pbs]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/zclconf/go-cty/cty"

	"github.com/rfdrew/terraform-provider-pbs/internal/provider"
)

// formatVersion is the version of the JSON format Terraform 1.x writes.
const formatVersion = "1.0"

func main() {
	out := flag.String("o", "", "file to write the schema to; standard output when empty")
	key := flag.String("key", provider.Address, "key of the provider in provider_schemas. tfplugindocs looks a schema "+
		"file up by the provider's short name, or under registry.terraform.io/hashicorp/<name>, so pass the short "+
		"name when the file is for tfplugindocs")
	flag.Parse()

	if err := run(context.Background(), *out, *key); err != nil {
		fmt.Fprintln(os.Stderr, "providerschema:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, out, key string) error {
	schemas, err := providerSchemas(ctx, key)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(schemas, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the schema: %w", err)
	}
	encoded = append(encoded, '\n')
	if out == "" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	return os.WriteFile(out, encoded, 0o644)
}

// providerSchemas asks the provider's protocol server for its schemas and
// converts them.
func providerSchemas(ctx context.Context, key string) (*tfjson.ProviderSchemas, error) {
	server, err := providerserver.NewProtocol6WithError(provider.New("dev")())()
	if err != nil {
		return nil, fmt.Errorf("starting the provider server: %w", err)
	}

	schemaResp, err := server.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetProviderSchema: %w", err)
	}
	if err := diagnosticsError("GetProviderSchema", schemaResp.Diagnostics); err != nil {
		return nil, err
	}
	identityResp, err := server.GetResourceIdentitySchemas(ctx, &tfprotov6.GetResourceIdentitySchemasRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetResourceIdentitySchemas: %w", err)
	}
	if err := diagnosticsError("GetResourceIdentitySchemas", identityResp.Diagnostics); err != nil {
		return nil, err
	}

	schema, err := convertProviderSchema(schemaResp, identityResp.IdentitySchemas)
	if err != nil {
		return nil, err
	}
	return &tfjson.ProviderSchemas{
		FormatVersion: formatVersion,
		Schemas:       map[string]*tfjson.ProviderSchema{key: schema},
	}, nil
}

// diagnosticsError turns error diagnostics into an error.
func diagnosticsError(call string, diags []*tfprotov6.Diagnostic) error {
	var messages []string
	for _, d := range diags {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			messages = append(messages, d.Summary+": "+d.Detail)
		}
	}
	if len(messages) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %s", call, strings.Join(messages, "; "))
}

// convertProviderSchema converts everything a framework provider can serve.
// Functions and state stores are refused rather than silently left out of
// the documentation: this provider has none, and supporting them is work for
// when it does.
func convertProviderSchema(resp *tfprotov6.GetProviderSchemaResponse, identities map[string]*tfprotov6.ResourceIdentitySchema) (*tfjson.ProviderSchema, error) {
	if len(resp.Functions) > 0 {
		return nil, fmt.Errorf("the provider declares functions (%s), which this command does not convert yet", strings.Join(sortedKeys(resp.Functions), ", "))
	}
	if len(resp.StateStoreSchemas) > 0 {
		return nil, fmt.Errorf("the provider declares state stores (%s), which this command does not convert yet", strings.Join(sortedKeys(resp.StateStoreSchemas), ", "))
	}

	out := &tfjson.ProviderSchema{}
	var err error
	if out.ConfigSchema, err = convertSchema(resp.Provider); err != nil {
		return nil, fmt.Errorf("provider: %w", err)
	}
	if out.ResourceSchemas, err = convertSchemas(resp.ResourceSchemas); err != nil {
		return nil, err
	}
	if out.DataSourceSchemas, err = convertSchemas(resp.DataSourceSchemas); err != nil {
		return nil, err
	}
	if out.EphemeralResourceSchemas, err = convertSchemas(resp.EphemeralResourceSchemas); err != nil {
		return nil, err
	}
	if out.ListResourceSchemas, err = convertSchemas(resp.ListResourceSchemas); err != nil {
		return nil, err
	}
	for name, action := range resp.ActionSchemas {
		if out.ActionSchemas == nil {
			out.ActionSchemas = map[string]*tfjson.ActionSchema{}
		}
		converted, err := convertSchema(action.Schema)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out.ActionSchemas[name] = &tfjson.ActionSchema{Block: converted.Block}
	}
	for name, identity := range identities {
		if out.ResourceIdentitySchemas == nil {
			out.ResourceIdentitySchemas = map[string]*tfjson.IdentitySchema{}
		}
		converted, err := convertIdentity(identity)
		if err != nil {
			return nil, fmt.Errorf("%s identity: %w", name, err)
		}
		out.ResourceIdentitySchemas[name] = converted
	}
	return out, nil
}

func convertSchemas(schemas map[string]*tfprotov6.Schema) (map[string]*tfjson.Schema, error) {
	if len(schemas) == 0 {
		return nil, nil
	}
	out := make(map[string]*tfjson.Schema, len(schemas))
	for name, s := range schemas {
		converted, err := convertSchema(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = converted
	}
	return out, nil
}

func convertSchema(s *tfprotov6.Schema) (*tfjson.Schema, error) {
	if s == nil {
		return nil, errors.New("no schema")
	}
	block, err := convertBlock(s.Block)
	if err != nil {
		return nil, err
	}
	return &tfjson.Schema{Version: uint64(s.Version), Block: block}, nil
}

func convertBlock(b *tfprotov6.SchemaBlock) (*tfjson.SchemaBlock, error) {
	if b == nil {
		return &tfjson.SchemaBlock{DescriptionKind: tfjson.SchemaDescriptionKindPlain}, nil
	}
	out := &tfjson.SchemaBlock{
		Description:     b.Description,
		DescriptionKind: descriptionKind(b.DescriptionKind),
		Deprecated:      b.Deprecated,
	}
	if len(b.Attributes) > 0 {
		out.Attributes = make(map[string]*tfjson.SchemaAttribute, len(b.Attributes))
		for _, a := range b.Attributes {
			converted, err := convertAttribute(a)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", a.Name, err)
			}
			out.Attributes[a.Name] = converted
		}
	}
	if len(b.BlockTypes) > 0 {
		out.NestedBlocks = make(map[string]*tfjson.SchemaBlockType, len(b.BlockTypes))
		for _, nested := range b.BlockTypes {
			block, err := convertBlock(nested.Block)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", nested.TypeName, err)
			}
			mode, err := blockNestingMode(nested.Nesting)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", nested.TypeName, err)
			}
			out.NestedBlocks[nested.TypeName] = &tfjson.SchemaBlockType{
				NestingMode: mode,
				Block:       block,
				MinItems:    uint64(nested.MinItems),
				MaxItems:    uint64(nested.MaxItems),
			}
		}
	}
	return out, nil
}

func convertAttribute(a *tfprotov6.SchemaAttribute) (*tfjson.SchemaAttribute, error) {
	out := &tfjson.SchemaAttribute{
		Description:     a.Description,
		DescriptionKind: descriptionKind(a.DescriptionKind),
		Deprecated:      a.Deprecated,
		Required:        a.Required,
		Optional:        a.Optional,
		Computed:        a.Computed,
		Sensitive:       a.Sensitive,
		WriteOnly:       a.WriteOnly,
	}
	if a.NestedType != nil {
		nested, err := convertObject(a.NestedType)
		if err != nil {
			return nil, err
		}
		out.AttributeNestedType = nested
		return out, nil
	}
	typ, err := ctyType(a.Type)
	if err != nil {
		return nil, err
	}
	out.AttributeType = typ
	return out, nil
}

func convertObject(o *tfprotov6.SchemaObject) (*tfjson.SchemaNestedAttributeType, error) {
	mode, err := objectNestingMode(o.Nesting)
	if err != nil {
		return nil, err
	}
	out := &tfjson.SchemaNestedAttributeType{
		NestingMode: mode,
		Attributes:  make(map[string]*tfjson.SchemaAttribute, len(o.Attributes)),
	}
	for _, a := range o.Attributes {
		converted, err := convertAttribute(a)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Name, err)
		}
		out.Attributes[a.Name] = converted
	}
	return out, nil
}

func convertIdentity(s *tfprotov6.ResourceIdentitySchema) (*tfjson.IdentitySchema, error) {
	out := &tfjson.IdentitySchema{
		Version:    uint64(s.Version),
		Attributes: make(map[string]*tfjson.IdentityAttribute, len(s.IdentityAttributes)),
	}
	for _, a := range s.IdentityAttributes {
		typ, err := ctyType(a.Type)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Name, err)
		}
		out.Attributes[a.Name] = &tfjson.IdentityAttribute{
			IdentityType:      typ,
			Description:       a.Description,
			RequiredForImport: a.RequiredForImport,
			OptionalForImport: a.OptionalForImport,
		}
	}
	return out, nil
}

// ctyType converts a protocol type into the cty type Terraform uses. Both
// serialise to the same JSON type notation, so that is the bridge.
func ctyType(t tftypes.Type) (cty.Type, error) {
	if t == nil {
		return cty.NilType, errors.New("attribute has neither a type nor a nested type")
	}
	encoded, err := json.Marshal(t)
	if err != nil {
		return cty.NilType, fmt.Errorf("encoding type %s: %w", t, err)
	}
	var typ cty.Type
	if err := typ.UnmarshalJSON(encoded); err != nil {
		return cty.NilType, fmt.Errorf("decoding type %s: %w", encoded, err)
	}
	return typ, nil
}

// descriptionKind is the description_kind Terraform writes: "markdown" for
// Markdown, and "plain" for everything else, even an empty description.
func descriptionKind(kind tfprotov6.StringKind) tfjson.SchemaDescriptionKind {
	if kind == tfprotov6.StringKindMarkdown {
		return tfjson.SchemaDescriptionKindMarkdown
	}
	return tfjson.SchemaDescriptionKindPlain
}

func blockNestingMode(mode tfprotov6.SchemaNestedBlockNestingMode) (tfjson.SchemaNestingMode, error) {
	switch mode {
	case tfprotov6.SchemaNestedBlockNestingModeSingle:
		return tfjson.SchemaNestingModeSingle, nil
	case tfprotov6.SchemaNestedBlockNestingModeGroup:
		return tfjson.SchemaNestingModeGroup, nil
	case tfprotov6.SchemaNestedBlockNestingModeList:
		return tfjson.SchemaNestingModeList, nil
	case tfprotov6.SchemaNestedBlockNestingModeSet:
		return tfjson.SchemaNestingModeSet, nil
	case tfprotov6.SchemaNestedBlockNestingModeMap:
		return tfjson.SchemaNestingModeMap, nil
	}
	return "", fmt.Errorf("unknown block nesting mode %v", mode)
}

func objectNestingMode(mode tfprotov6.SchemaObjectNestingMode) (tfjson.SchemaNestingMode, error) {
	switch mode {
	case tfprotov6.SchemaObjectNestingModeSingle:
		return tfjson.SchemaNestingModeSingle, nil
	case tfprotov6.SchemaObjectNestingModeList:
		return tfjson.SchemaNestingModeList, nil
	case tfprotov6.SchemaObjectNestingModeSet:
		return tfjson.SchemaNestingModeSet, nil
	case tfprotov6.SchemaObjectNestingModeMap:
		return tfjson.SchemaNestingModeMap, nil
	}
	return "", fmt.Errorf("unknown nested attribute nesting mode %v", mode)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
