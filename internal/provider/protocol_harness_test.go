package provider

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// The protocol harness, taken from terraform-provider-kopia's and cut down to
// what the provider's tests use. It drives resources and data sources through
// the framework's protocol server, the one Terraform talks to, so that
// validators, defaults, plan modifiers, write-only handling and identity
// bookkeeping run as they do under Terraform. Nothing opens a socket: the
// provider is configured with the fake PBS as its transport.
//
//	h := newProtocolHarness(t, fake)                 // signs in with the fake's API token
//	h := newProtocolHarness(t, fake, withPasswordSignIn())
//	inst := h.create(t, "pbs_user", config)          // validate, plan and apply, as `terraform apply` does
//	inst = h.update(t, inst, config)                 // plan and apply a change
//	inst = h.refresh(t, inst)                        // ReadResource; inst.state is null when it was removed
//	h.destroy(t, inst)
//	inst = h.importByID(t, "pbs_user", "alice@pbs")  // ImportResourceState, then ReadResource
//	inst = h.importByIdentity(t, "pbs_user", map[string]any{"userid": "alice@pbs"})
//	state := h.readDataSource(t, "pbs_users", config)
//
// Those calls fail the test on an error diagnostic. For the diagnostics
// themselves, or to look at a plan, use the single steps, which return the
// raw protocol responses: h.validateResource, h.plan(t, typeName, prior,
// config) (prior nil for a create, config null for a destroy), h.apply,
// h.importResource and h.readDataSourceResponse. Check them with
// requireNoProtocolErrors, requireProtocolErrorContaining and
// requireProtocolWarningContaining, and decode with h.decodeResource and
// h.identityValue. Configurations are built with h.resourceValue and
// h.dataSourceValue from plain Go values, as tfValue accepts them; read values
// back with valueAt, stringAt, int64At, boolAt, isNullAt and isUnknownAt.

// resourceSchema returns r's schema, failing the test on a schema error.
func resourceSchema(t *testing.T, r resource.Resource) resourceschema.Schema {
	t.Helper()
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	requireNoErrors(t, resp.Diagnostics)
	return resp.Schema
}

// requireValidResourceSchema fails the test when r's schema breaks one of the
// framework's rules, which the framework would otherwise only report when
// Terraform first asks for the schema.
func requireValidResourceSchema(t *testing.T, r resource.Resource) {
	t.Helper()
	requireNoErrors(t, resourceSchema(t, r).ValidateImplementation(context.Background()))
}

// --- reading values -------------------------------------------------------------

// valueAt walks v: a string step selects an object attribute or a map
// element, an int step a list element. It fails the test when a step does not
// exist or crosses a null or unknown value.
func valueAt(t *testing.T, v tftypes.Value, steps ...any) tftypes.Value {
	t.Helper()
	current := v
	for i, step := range steps {
		if !current.IsKnown() || current.IsNull() {
			t.Fatalf("%v: cannot step into a null or unknown value at step %d", steps, i)
		}
		switch step := step.(type) {
		case string:
			var attrs map[string]tftypes.Value
			if err := current.As(&attrs); err != nil {
				t.Fatalf("%v: step %d (%q): %v", steps, i, step, err)
			}
			next, ok := attrs[step]
			if !ok {
				t.Fatalf("%v: step %d: no attribute or key %q in %s", steps, i, step, current)
			}
			current = next
		case int:
			var elements []tftypes.Value
			if err := current.As(&elements); err != nil {
				t.Fatalf("%v: step %d ([%d]): %v", steps, i, step, err)
			}
			if step < 0 || step >= len(elements) {
				t.Fatalf("%v: step %d: index %d out of range, %d elements", steps, i, step, len(elements))
			}
			current = elements[step]
		default:
			t.Fatalf("%v: step %d is a %T, want a string or an int", steps, i, step)
		}
	}
	return current
}

// isNullAt reports whether the value at steps is null.
func isNullAt(t *testing.T, v tftypes.Value, steps ...any) bool {
	t.Helper()
	return valueAt(t, v, steps...).IsNull()
}

// isUnknownAt reports whether the value at steps is unknown.
func isUnknownAt(t *testing.T, v tftypes.Value, steps ...any) bool {
	t.Helper()
	return !valueAt(t, v, steps...).IsKnown()
}

// knownAt returns the value at steps, failing the test when it is null or
// unknown.
func knownAt(t *testing.T, v tftypes.Value, steps ...any) tftypes.Value {
	t.Helper()
	value := valueAt(t, v, steps...)
	if !value.IsKnown() || value.IsNull() {
		t.Fatalf("%v is %s, want a known value", steps, value)
	}
	return value
}

func stringAt(t *testing.T, v tftypes.Value, steps ...any) string {
	t.Helper()
	var s string
	if err := knownAt(t, v, steps...).As(&s); err != nil {
		t.Fatalf("%v: %v", steps, err)
	}
	return s
}

func boolAt(t *testing.T, v tftypes.Value, steps ...any) bool {
	t.Helper()
	var b bool
	if err := knownAt(t, v, steps...).As(&b); err != nil {
		t.Fatalf("%v: %v", steps, err)
	}
	return b
}

func int64At(t *testing.T, v tftypes.Value, steps ...any) int64 {
	t.Helper()
	n := new(big.Float)
	if err := knownAt(t, v, steps...).As(&n); err != nil {
		t.Fatalf("%v: %v", steps, err)
	}
	i, accuracy := n.Int64()
	if accuracy != big.Exact {
		t.Fatalf("%v = %s, want an integer", steps, n)
	}
	return i
}

// lengthAt returns the number of elements of the list, set or map at steps.
func lengthAt(t *testing.T, v tftypes.Value, steps ...any) int {
	t.Helper()
	value := knownAt(t, v, steps...)
	var elements []tftypes.Value
	if err := value.As(&elements); err == nil {
		return len(elements)
	}
	var m map[string]tftypes.Value
	if err := value.As(&m); err != nil {
		t.Fatalf("%v: %v", steps, err)
	}
	return len(m)
}

// --- the protocol server -------------------------------------------------------

// protocolHarness is a configured protocol server plus the schemas it serves.
type protocolHarness struct {
	server     tfprotov6.ProviderServer
	schemas    *tfprotov6.GetProviderSchemaResponse
	identities map[string]*tfprotov6.ResourceIdentitySchema
}

// resourceInstance is what Terraform keeps of a resource between operations:
// its state, identity and private data.
type resourceInstance struct {
	typeName string
	state    tftypes.Value
	identity *tfprotov6.ResourceIdentityData
	private  []byte
}

// harnessOptions are what newProtocolHarness configures.
type harnessOptions struct {
	passwordSignIn bool
}

type harnessOption func(*harnessOptions)

// withPasswordSignIn configures the provider with the fake's username and
// password instead of its API token.
func withPasswordSignIn() harnessOption {
	return func(o *harnessOptions) { o.passwordSignIn = true }
}

// newProtocolHarness starts the provider's protocol server with the fake as
// its transport and configures it, as Terraform 1.14 would.
func newProtocolHarness(t *testing.T, fake *fakePBS, opts ...harnessOption) *protocolHarness {
	t.Helper()
	var options harnessOptions
	for _, opt := range opts {
		opt(&options)
	}
	ctx := context.Background()
	clearPBSEnv(t)
	server, err := providerserver.NewProtocol6WithError(&pbsProvider{version: "test", transport: fake})()
	if err != nil {
		t.Fatal(err)
	}

	schemas, err := server.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	requireNoProtocolErrors(t, schemas.Diagnostics)
	identities, err := server.GetResourceIdentitySchemas(ctx, &tfprotov6.GetResourceIdentitySchemasRequest{})
	if err != nil {
		t.Fatal(err)
	}
	requireNoProtocolErrors(t, identities.Diagnostics)

	providerConfig := map[string]any{"endpoint": "https://pbs.test:8007", "api_token": fakeAPIToken}
	if options.passwordSignIn {
		providerConfig = map[string]any{"endpoint": "https://pbs.test:8007", "username": fake.username, "password": fake.password}
	}
	config := dynamicValue(t, tfValue(t, schemas.Provider.ValueType(), providerConfig))
	resp, err := server.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{TerraformVersion: "1.14.0", Config: config})
	if err != nil {
		t.Fatal(err)
	}
	requireNoProtocolErrors(t, resp.Diagnostics)

	return &protocolHarness{server: server, schemas: schemas, identities: identities.IdentitySchemas}
}

func (h *protocolHarness) resourceSchema(t *testing.T, typeName string) *tfprotov6.Schema {
	t.Helper()
	s, ok := h.schemas.ResourceSchemas[typeName]
	if !ok {
		t.Fatalf("no resource %s is registered; registered: %s", typeName, strings.Join(harnessSortedKeys(h.schemas.ResourceSchemas), ", "))
	}
	return s
}

func (h *protocolHarness) dataSourceSchema(t *testing.T, typeName string) *tfprotov6.Schema {
	t.Helper()
	s, ok := h.schemas.DataSourceSchemas[typeName]
	if !ok {
		t.Fatalf("no data source %s is registered; registered: %s", typeName, strings.Join(harnessSortedKeys(h.schemas.DataSourceSchemas), ", "))
	}
	return s
}

func (h *protocolHarness) resourceType(t *testing.T, typeName string) tftypes.Type {
	t.Helper()
	return h.resourceSchema(t, typeName).ValueType()
}

func (h *protocolHarness) identityType(t *testing.T, typeName string) tftypes.Type {
	t.Helper()
	s, ok := h.identities[typeName]
	if !ok {
		t.Fatalf("resource %s declares no identity", typeName)
	}
	return s.ValueType()
}

// resourceValue and dataSourceValue build objects of the served schemas.
func (h *protocolHarness) resourceValue(t *testing.T, typeName string, attrs map[string]any) tftypes.Value {
	t.Helper()
	return tfValue(t, h.resourceType(t, typeName), attrs)
}

func (h *protocolHarness) dataSourceValue(t *testing.T, typeName string, attrs map[string]any) tftypes.Value {
	t.Helper()
	return tfValue(t, h.dataSourceSchema(t, typeName).ValueType(), attrs)
}

// identityValue decodes an identity of typeName; the null object when there
// is none.
func (h *protocolHarness) identityValue(t *testing.T, typeName string, identity *tfprotov6.ResourceIdentityData) tftypes.Value {
	t.Helper()
	typ := h.identityType(t, typeName)
	if identity == nil || identity.IdentityData == nil {
		return tftypes.NewValue(typ, nil)
	}
	return decodeDynamicValue(t, identity.IdentityData, typ)
}

// decodeResource decodes a protocol value of a served resource schema.
func (h *protocolHarness) decodeResource(t *testing.T, typeName string, dv *tfprotov6.DynamicValue) tftypes.Value {
	t.Helper()
	return decodeDynamicValue(t, dv, h.resourceType(t, typeName))
}

func dynamicValue(t *testing.T, v tftypes.Value) *tfprotov6.DynamicValue {
	t.Helper()
	dv, err := tfprotov6.NewDynamicValue(v.Type(), v)
	if err != nil {
		t.Fatal(err)
	}
	return &dv
}

func decodeDynamicValue(t *testing.T, dv *tfprotov6.DynamicValue, typ tftypes.Type) tftypes.Value {
	t.Helper()
	if dv == nil {
		t.Fatal("no value")
	}
	v, err := dv.Unmarshal(typ)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// validateResource runs ValidateResourceConfig — attribute validators, then
// ConfigValidators and ValidateConfig — for a Terraform that supports
// write-only attributes.
func (h *protocolHarness) validateResource(t *testing.T, typeName string, config tftypes.Value) []*tfprotov6.Diagnostic {
	t.Helper()
	resp, err := h.server.ValidateResourceConfig(context.Background(), &tfprotov6.ValidateResourceConfigRequest{
		TypeName:           typeName,
		Config:             dynamicValue(t, config),
		ClientCapabilities: &tfprotov6.ValidateResourceConfigClientCapabilities{WriteOnlyAttributesAllowed: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Diagnostics
}

// plan runs PlanResourceChange from prior (nil for a create) to config (a
// null value for a destroy), with the proposed new state Terraform core
// would send.
func (h *protocolHarness) plan(t *testing.T, typeName string, prior *resourceInstance, config tftypes.Value) *tfprotov6.PlanResourceChangeResponse {
	t.Helper()
	typ := h.resourceType(t, typeName)
	priorState := tftypes.NewValue(typ, nil)
	var priorIdentity *tfprotov6.ResourceIdentityData
	var priorPrivate []byte
	if prior != nil {
		priorState, priorIdentity, priorPrivate = prior.state, prior.identity, prior.private
	}
	proposed := tftypes.NewValue(typ, nil)
	if !config.IsNull() {
		proposed = proposedNewState(t, h.resourceSchema(t, typeName).Block, priorState, config)
	}
	resp, err := h.server.PlanResourceChange(context.Background(), &tfprotov6.PlanResourceChangeRequest{
		TypeName:         typeName,
		PriorState:       dynamicValue(t, priorState),
		ProposedNewState: dynamicValue(t, proposed),
		Config:           dynamicValue(t, config),
		PriorPrivate:     priorPrivate,
		PriorIdentity:    priorIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// apply runs ApplyResourceChange for a plan h.plan made.
func (h *protocolHarness) apply(t *testing.T, typeName string, prior *resourceInstance, config tftypes.Value, planned *tfprotov6.PlanResourceChangeResponse) *tfprotov6.ApplyResourceChangeResponse {
	t.Helper()
	priorState := tftypes.NewValue(h.resourceType(t, typeName), nil)
	if prior != nil {
		priorState = prior.state
	}
	resp, err := h.server.ApplyResourceChange(context.Background(), &tfprotov6.ApplyResourceChangeRequest{
		TypeName:        typeName,
		PriorState:      dynamicValue(t, priorState),
		PlannedState:    planned.PlannedState,
		Config:          dynamicValue(t, config),
		PlannedPrivate:  planned.PlannedPrivate,
		PlannedIdentity: planned.PlannedIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// planAndApply validates config, plans and applies, failing the test on any
// error, and returns what Terraform would store.
func (h *protocolHarness) planAndApply(t *testing.T, typeName string, prior *resourceInstance, config tftypes.Value) *resourceInstance {
	t.Helper()
	if !config.IsNull() {
		requireNoProtocolErrors(t, h.validateResource(t, typeName, config))
	}
	planned := h.plan(t, typeName, prior, config)
	requireNoProtocolErrors(t, planned.Diagnostics)
	applied := h.apply(t, typeName, prior, config, planned)
	requireNoProtocolErrors(t, applied.Diagnostics)
	return &resourceInstance{
		typeName: typeName,
		state:    h.decodeResource(t, typeName, applied.NewState),
		identity: applied.NewIdentity,
		private:  applied.Private,
	}
}

// create applies config to a new resource, as `terraform apply` does.
func (h *protocolHarness) create(t *testing.T, typeName string, config tftypes.Value) *resourceInstance {
	t.Helper()
	return h.planAndApply(t, typeName, nil, config)
}

// update applies config to an existing resource.
func (h *protocolHarness) update(t *testing.T, inst *resourceInstance, config tftypes.Value) *resourceInstance {
	t.Helper()
	return h.planAndApply(t, inst.typeName, inst, config)
}

// destroy plans and applies the resource's destruction.
func (h *protocolHarness) destroy(t *testing.T, inst *resourceInstance) {
	t.Helper()
	h.planAndApply(t, inst.typeName, inst, tftypes.NewValue(h.resourceType(t, inst.typeName), nil))
}

// read runs ReadResource on inst.
func (h *protocolHarness) read(t *testing.T, inst *resourceInstance) *tfprotov6.ReadResourceResponse {
	t.Helper()
	resp, err := h.server.ReadResource(context.Background(), &tfprotov6.ReadResourceRequest{
		TypeName:        inst.typeName,
		CurrentState:    dynamicValue(t, inst.state),
		Private:         inst.private,
		CurrentIdentity: inst.identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// refresh reads inst, failing the test on an error. The returned state is
// null when the resource removed itself.
func (h *protocolHarness) refresh(t *testing.T, inst *resourceInstance) *resourceInstance {
	t.Helper()
	resp := h.read(t, inst)
	requireNoProtocolErrors(t, resp.Diagnostics)
	return &resourceInstance{
		typeName: inst.typeName,
		state:    h.decodeResource(t, inst.typeName, resp.NewState),
		identity: resp.NewIdentity,
		private:  resp.Private,
	}
}

// importResource runs ImportResourceState with an import id or, when id is
// "", with identity.
func (h *protocolHarness) importResource(t *testing.T, typeName, id string, identity *tfprotov6.ResourceIdentityData) *tfprotov6.ImportResourceStateResponse {
	t.Helper()
	resp, err := h.server.ImportResourceState(context.Background(), &tfprotov6.ImportResourceStateRequest{
		TypeName: typeName,
		ID:       id,
		Identity: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// importByID imports a resource by import id and reads it, as Terraform does,
// failing the test on an error.
func (h *protocolHarness) importByID(t *testing.T, typeName, id string) *resourceInstance {
	t.Helper()
	return h.finishImport(t, typeName, h.importResource(t, typeName, id, nil))
}

// importByIdentity imports a resource by identity and reads it.
func (h *protocolHarness) importByIdentity(t *testing.T, typeName string, identity map[string]any) *resourceInstance {
	t.Helper()
	data := &tfprotov6.ResourceIdentityData{IdentityData: dynamicValue(t, tfValue(t, h.identityType(t, typeName), identity))}
	return h.finishImport(t, typeName, h.importResource(t, typeName, "", data))
}

func (h *protocolHarness) finishImport(t *testing.T, typeName string, resp *tfprotov6.ImportResourceStateResponse) *resourceInstance {
	t.Helper()
	requireNoProtocolErrors(t, resp.Diagnostics)
	if len(resp.ImportedResources) != 1 {
		t.Fatalf("import returned %d resources, want 1", len(resp.ImportedResources))
	}
	imported := resp.ImportedResources[0]
	return h.refresh(t, &resourceInstance{
		typeName: typeName,
		state:    h.decodeResource(t, typeName, imported.State),
		identity: imported.Identity,
		private:  imported.Private,
	})
}

// readDataSourceResponse runs ReadDataSource with config.
func (h *protocolHarness) readDataSourceResponse(t *testing.T, typeName string, config tftypes.Value) *tfprotov6.ReadDataSourceResponse {
	t.Helper()
	resp, err := h.server.ReadDataSource(context.Background(), &tfprotov6.ReadDataSourceRequest{
		TypeName: typeName,
		Config:   dynamicValue(t, config),
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// readDataSource validates config and reads the data source, failing the test
// on an error, and returns its state.
func (h *protocolHarness) readDataSource(t *testing.T, typeName string, config tftypes.Value) tftypes.Value {
	t.Helper()
	validated, err := h.server.ValidateDataResourceConfig(context.Background(), &tfprotov6.ValidateDataResourceConfigRequest{
		TypeName: typeName,
		Config:   dynamicValue(t, config),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireNoProtocolErrors(t, validated.Diagnostics)
	resp := h.readDataSourceResponse(t, typeName, config)
	requireNoProtocolErrors(t, resp.Diagnostics)
	return decodeDynamicValue(t, resp.State, h.dataSourceSchema(t, typeName).ValueType())
}

// proposedNewState builds the proposed new state Terraform core sends with
// PlanResourceChange (internal/plans/objchange in Terraform): the configured
// value of every attribute, except that a computed attribute the
// configuration leaves null keeps its prior value, and a write-only attribute
// is always null. Single nested attributes are walked the same way; the
// provider's schemas have no other nesting and no blocks, which this does not
// handle.
func proposedNewState(t *testing.T, block *tfprotov6.SchemaBlock, prior, config tftypes.Value) tftypes.Value {
	t.Helper()
	if !config.IsKnown() || config.IsNull() {
		return config
	}
	if len(block.BlockTypes) > 0 {
		t.Fatal("proposedNewState does not handle blocks")
	}
	return proposedAttributes(t, block.Attributes, prior, config)
}

// proposedAttributes is proposedNewState for the attributes of one object.
func proposedAttributes(t *testing.T, attributes []*tfprotov6.SchemaAttribute, prior, config tftypes.Value) tftypes.Value {
	t.Helper()
	priorAttrs := harnessObjectAttributes(t, prior)
	configAttrs := harnessObjectAttributes(t, config)
	proposed := make(map[string]tftypes.Value, len(attributes))
	for _, attr := range attributes {
		configV := configAttrs[attr.Name]
		priorV, ok := priorAttrs[attr.Name]
		if !ok {
			priorV = tftypes.NewValue(configV.Type(), nil)
		}
		configured := configV.IsKnown() && !configV.IsNull()
		switch {
		case attr.WriteOnly:
			proposed[attr.Name] = tftypes.NewValue(configV.Type(), nil)
		case attr.NestedType != nil && configured:
			if attr.NestedType.Nesting != tfprotov6.SchemaObjectNestingModeSingle {
				t.Fatalf("proposedNewState handles single nested attributes only (%s)", attr.Name)
			}
			proposed[attr.Name] = proposedAttributes(t, attr.NestedType.Attributes, priorV, configV)
		case !attr.Computed || configured:
			proposed[attr.Name] = configV
		default:
			proposed[attr.Name] = priorV
		}
	}
	return tftypes.NewValue(config.Type(), proposed)
}

// harnessObjectAttributes returns an object's attributes; none for null.
func harnessObjectAttributes(t *testing.T, v tftypes.Value) map[string]tftypes.Value {
	t.Helper()
	if v.IsNull() || !v.IsKnown() {
		return map[string]tftypes.Value{}
	}
	var attrs map[string]tftypes.Value
	if err := v.As(&attrs); err != nil {
		t.Fatal(err)
	}
	return attrs
}

func requireNoProtocolErrors(t *testing.T, diags []*tfprotov6.Diagnostic) {
	t.Helper()
	for _, d := range diags {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("unexpected error: %s: %s", d.Summary, d.Detail)
		}
	}
}

func requireProtocolErrorContaining(t *testing.T, diags []*tfprotov6.Diagnostic, want string) {
	t.Helper()
	requireProtocolDiagnostic(t, diags, tfprotov6.DiagnosticSeverityError, want)
}

func requireProtocolWarningContaining(t *testing.T, diags []*tfprotov6.Diagnostic, want string) {
	t.Helper()
	requireProtocolDiagnostic(t, diags, tfprotov6.DiagnosticSeverityWarning, want)
}

func requireProtocolDiagnostic(t *testing.T, diags []*tfprotov6.Diagnostic, severity tfprotov6.DiagnosticSeverity, want string) {
	t.Helper()
	for _, d := range diags {
		if d.Severity == severity && (strings.Contains(d.Summary, want) || strings.Contains(d.Detail, want)) {
			return
		}
	}
	var got []string
	for _, d := range diags {
		got = append(got, fmt.Sprintf("%s: %s: %s", d.Severity, d.Summary, d.Detail))
	}
	t.Fatalf("expected a %s containing %q, got %v", severity, want, got)
}
