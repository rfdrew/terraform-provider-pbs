package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// --- actions --------------------------------------------------------------------

func (h *protocolHarness) actionSchema(t *testing.T, typeName string) *tfprotov6.Schema {
	t.Helper()
	s, ok := h.schemas.ActionSchemas[typeName]
	if !ok {
		t.Fatalf("no action %s is registered; registered: %s", typeName, strings.Join(harnessSortedKeys(h.schemas.ActionSchemas), ", "))
	}
	return s.Schema
}

// actionValue builds a configuration of an action.
func (h *protocolHarness) actionValue(t *testing.T, typeName string, attrs map[string]any) tftypes.Value {
	t.Helper()
	return tfValue(t, h.actionSchema(t, typeName).ValueType(), attrs)
}

// actionServer is the server's action RPCs.
func (h *protocolHarness) actionServer(t *testing.T) tfprotov6.ActionServer {
	t.Helper()
	server, ok := h.server.(tfprotov6.ActionServer)
	if !ok {
		t.Fatal("the provider server does not serve actions")
	}
	return server
}

// validateAction runs ValidateActionConfig.
func (h *protocolHarness) validateAction(t *testing.T, typeName string, config tftypes.Value) []*tfprotov6.Diagnostic {
	t.Helper()
	resp, err := h.actionServer(t).ValidateActionConfig(context.Background(), &tfprotov6.ValidateActionConfigRequest{
		ActionType: typeName,
		Config:     dynamicValue(t, config),
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Diagnostics
}

// planAction runs PlanAction, as Terraform does while planning an
// invocation.
func (h *protocolHarness) planAction(t *testing.T, typeName string, config tftypes.Value) []*tfprotov6.Diagnostic {
	t.Helper()
	resp, err := h.actionServer(t).PlanAction(context.Background(), &tfprotov6.PlanActionRequest{
		ActionType:         typeName,
		Config:             dynamicValue(t, config),
		ClientCapabilities: &tfprotov6.PlanActionClientCapabilities{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Diagnostics
}

// actionInvocation is what Terraform hears from an invoked action: its
// progress messages, in order, until ctx ended, and the diagnostics it
// completed with — also when it completed after ctx ended, which Terraform
// would drop.
type actionInvocation struct {
	progress    []string
	diagnostics []*tfprotov6.Diagnostic
	completed   bool
	// stopped tells that ctx ended before the action completed.
	stopped bool
}

// actionStopGrace is how long an action may take to complete once ctx has
// ended.
const actionStopGrace = 10 * time.Second

// invokeActionWith runs InvokeAction with ctx and collects its events. It
// reads them as tf6server does: once ctx has ended, the next event is the
// last one read, and the action's next progress message would then block
// its goroutine for good, as the framework sends progress on an unbuffered
// channel. So the test fails when that event is a progress message, and
// when the action has not completed within actionStopGrace of ctx ending.
func (h *protocolHarness) invokeActionWith(ctx context.Context, t *testing.T, typeName string, config tftypes.Value) actionInvocation {
	t.Helper()
	stream, err := h.actionServer(t).InvokeAction(ctx, &tfprotov6.InvokeActionRequest{
		ActionType:         typeName,
		Config:             dynamicValue(t, config),
		ClientCapabilities: &tfprotov6.InvokeActionClientCapabilities{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got actionInvocation
	var lateProgress []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range stream.Events {
			stopped := ctx.Err() != nil
			switch e := event.Type.(type) {
			case tfprotov6.ProgressInvokeActionEventType:
				if stopped {
					lateProgress = append(lateProgress, e.Message)
				} else {
					got.progress = append(got.progress, e.Message)
				}
			case tfprotov6.CompletedInvokeActionEventType:
				got.diagnostics = append(got.diagnostics, e.Diagnostics...)
				got.completed = true
			}
			if stopped {
				got.stopped = true
				break
			}
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		select {
		case <-done:
		case <-time.After(actionStopGrace):
			t.Fatalf("action %s did not complete within %s of Terraform stopping it", typeName, actionStopGrace)
		}
	}
	if len(lateProgress) > 0 {
		t.Fatalf("action %s sent progress after Terraform stopped it: %q", typeName, lateProgress)
	}
	return got
}

// invokeAction validates, plans and invokes an action with the
// configuration attrs, as `terraform apply` does, failing the test when
// validation or planning fails or the action never completes.
func (h *protocolHarness) invokeAction(t *testing.T, typeName string, attrs map[string]any) actionInvocation {
	t.Helper()
	config := h.actionValue(t, typeName, attrs)
	requireNoProtocolErrors(t, h.validateAction(t, typeName, config))
	requireNoProtocolErrors(t, h.planAction(t, typeName, config))
	got := h.invokeActionWith(context.Background(), t, typeName, config)
	if !got.completed {
		t.Fatalf("action %s did not complete; progress: %q", typeName, got.progress)
	}
	return got
}

// requireProgressContaining fails the test unless a progress message
// contains want.
func requireProgressContaining(t *testing.T, got actionInvocation, want string) {
	t.Helper()
	for _, message := range got.progress {
		if strings.Contains(message, want) {
			return
		}
	}
	t.Fatalf("no progress message contains %q; progress: %q", want, got.progress)
}

// --- list resources -------------------------------------------------------------

func (h *protocolHarness) listSchema(t *testing.T, typeName string) *tfprotov6.Schema {
	t.Helper()
	s, ok := h.schemas.ListResourceSchemas[typeName]
	if !ok {
		t.Fatalf("no list resource %s is registered; registered: %s", typeName, strings.Join(harnessSortedKeys(h.schemas.ListResourceSchemas), ", "))
	}
	return s
}

// listServer is the server's list RPCs.
func (h *protocolHarness) listServer(t *testing.T) tfprotov6.ListResourceServer {
	t.Helper()
	server, ok := h.server.(tfprotov6.ListResourceServer)
	if !ok {
		t.Fatal("the provider server does not serve list resources")
	}
	return server
}

// listedResult is one result of a list resource, decoded.
type listedResult struct {
	displayName string
	// identity is the result's identity; resource its state, null when the
	// list did not include resources.
	identity    tftypes.Value
	resource    tftypes.Value
	diagnostics []*tfprotov6.Diagnostic
}

// listRequest says how to list.
type listRequest struct {
	config          map[string]any
	includeResource bool
	limit           int64
}

// listResources validates the list block's configuration and lists, as
// `terraform query` does, and returns every result; results without an
// identity carry diagnostics only.
func (h *protocolHarness) listResources(t *testing.T, typeName string, req listRequest) []listedResult {
	t.Helper()
	if req.config == nil {
		req.config = map[string]any{}
	}
	if req.limit == 0 {
		req.limit = 100
	}
	config := tfValue(t, h.listSchema(t, typeName).ValueType(), req.config)
	validated, err := h.listServer(t).ValidateListResourceConfig(context.Background(), &tfprotov6.ValidateListResourceConfigRequest{
		TypeName: typeName,
		Config:   dynamicValue(t, config),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireNoProtocolErrors(t, validated.Diagnostics)

	stream, err := h.listServer(t).ListResource(context.Background(), &tfprotov6.ListResourceRequest{
		TypeName:        typeName,
		Config:          dynamicValue(t, config),
		IncludeResource: req.includeResource,
		Limit:           req.limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	var results []listedResult
	for result := range stream.Results {
		listed := listedResult{
			displayName: result.DisplayName,
			identity:    h.identityValue(t, typeName, result.Identity),
			resource:    tftypes.NewValue(h.resourceType(t, typeName), nil),
			diagnostics: result.Diagnostics,
		}
		if result.Resource != nil {
			listed.resource = h.decodeResource(t, typeName, result.Resource)
		}
		results = append(results, listed)
	}
	return results
}

// listedObjects lists and returns the results with an identity, failing the
// test on an error diagnostic.
func (h *protocolHarness) listedObjects(t *testing.T, typeName string, req listRequest) []listedResult {
	t.Helper()
	var objects []listedResult
	for _, result := range h.listResources(t, typeName, req) {
		requireNoProtocolErrors(t, result.diagnostics)
		if !result.identity.IsNull() {
			objects = append(objects, result)
		}
	}
	return objects
}

// listedIdentities returns the identity attribute of the given name of
// each result, in order.
func listedIdentities(t *testing.T, results []listedResult, attribute string) []string {
	t.Helper()
	var values []string
	for _, result := range results {
		values = append(values, stringAt(t, result.identity, attribute))
	}
	return values
}

// generateConfig returns the configuration Terraform generates from a state,
// as `terraform query -generate-config-out` does with a listed resource.
// Framework 1.19 does not announce its GenerateResourceConfig to Terraform,
// so Terraform 1.14 extracts the configuration with its own legacy rules,
// which that RPC transcribes and stands in for here, and then writes it as
// HCL (internal/genconfig/generate_config.go), which changes two kinds of
// top-level attributes on the way: a sensitive one is written as null, and
// a string holding a JSON object or array as jsonencode() of it, which
// evaluates to the document compacted, keys sorted and <, > and & escaped.
func (h *protocolHarness) generateConfig(t *testing.T, typeName string, state tftypes.Value) tftypes.Value {
	t.Helper()
	resp, err := h.server.GenerateResourceConfig(context.Background(), &tfprotov6.GenerateResourceConfigRequest{
		TypeName: typeName,
		State:    dynamicValue(t, state),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireNoProtocolErrors(t, resp.Diagnostics)
	config := h.decodeResource(t, typeName, resp.Config)
	attrs := harnessObjectAttributes(t, config.Copy())
	for _, attr := range h.resourceSchema(t, typeName).Block.Attributes {
		value, ok := attrs[attr.Name]
		if !ok || value.IsNull() || !value.IsKnown() {
			continue
		}
		if attr.Sensitive {
			attrs[attr.Name] = tftypes.NewValue(value.Type(), nil)
			continue
		}
		var text string
		if !value.Type().Is(tftypes.String) || value.As(&text) != nil {
			continue
		}
		if encoded, ok := jsonencodedLikeTerraform(text); ok {
			attrs[attr.Name] = tftypes.NewValue(tftypes.String, encoded)
		}
	}
	return tftypes.NewValue(config.Type(), attrs)
}

// jsonencodedLikeTerraform returns what jsonencode() of the HCL Terraform
// writes for a string holding a JSON object or array evaluates to.
func jsonencodedLikeTerraform(text string) (string, bool) {
	raw := []byte(text)
	if !json.Valid(raw) {
		return "", false
	}
	typ, err := ctyjson.ImpliedType(raw)
	if err != nil || !typ.IsObjectType() && !typ.IsTupleType() {
		return "", false
	}
	value, err := ctyjson.Unmarshal(raw, typ)
	if err != nil {
		return "", false
	}
	encoded, err := ctyjson.Marshal(value, typ)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

// importListed imports a listed object by its identity and reads it, as
// `terraform plan` does with the import block -generate-config-out writes.
func (h *protocolHarness) importListed(t *testing.T, typeName string, result listedResult) *resourceInstance {
	t.Helper()
	identity := &tfprotov6.ResourceIdentityData{IdentityData: dynamicValue(t, result.identity)}
	return h.finishImport(t, typeName, h.importResource(t, typeName, "", identity))
}

// generatedPlan is what `terraform plan` does with what
// `terraform query -generate-config-out` wrote for a listed object: the
// configuration generated from the result, its validation, the import of
// the object and the plan from there to the configuration.
type generatedPlan struct {
	config      tftypes.Value
	validation  []*tfprotov6.Diagnostic
	imported    *resourceInstance
	plan        *tfprotov6.PlanResourceChangeResponse
	plannedSame bool
}

func (h *protocolHarness) planGenerated(t *testing.T, typeName string, result listedResult) generatedPlan {
	t.Helper()
	got := generatedPlan{config: h.generateConfig(t, typeName, result.resource)}
	got.validation = h.validateResource(t, typeName, got.config)
	got.imported = h.importListed(t, typeName, result)
	got.plan = h.plan(t, typeName, got.imported, got.config)
	if got.plan.PlannedState != nil {
		got.plannedSame = h.decodeResource(t, typeName, got.plan.PlannedState).Equal(got.imported.state)
	}
	return got
}

// requireListedLikeImport checks a listed object against importing it: the
// same identity, the same state but for sensitive values, which a list
// leaves null, and a generated configuration that validates and plans no
// change.
func (h *protocolHarness) requireListedLikeImport(t *testing.T, typeName string, result listedResult) {
	t.Helper()
	if result.resource.IsNull() {
		t.Fatalf("%s: the result %q includes no resource", typeName, result.displayName)
	}
	generated := h.planGenerated(t, typeName, result)
	if got := h.identityValue(t, typeName, generated.imported.identity); !got.Equal(result.identity) {
		t.Fatalf("%s: listed identity %s, imported %s", typeName, result.identity, got)
	}
	wantState := withoutSensitive(t, h.resourceSchema(t, typeName).Block, generated.imported.state)
	if !result.resource.Equal(wantState) {
		t.Fatalf("%s: listed state differs from the imported one\nlisted:   %s\nimported: %s", typeName, result.resource, wantState)
	}
	requireNoProtocolErrors(t, generated.validation)
	requireNoProtocolErrors(t, generated.plan.Diagnostics)
	if len(generated.plan.RequiresReplace) > 0 {
		t.Fatalf("%s: the generated configuration replaces the object: %v", typeName, generated.plan.RequiresReplace)
	}
	if !generated.plannedSame {
		t.Fatalf("%s: the generated configuration plans a change\nconfig:   %s\nimported: %s\nplanned:  %s", typeName,
			generated.config, generated.imported.state, h.decodeResource(t, typeName, generated.plan.PlannedState))
	}
}

// withoutSensitive returns v with every sensitive attribute of block null,
// as list results carry them.
func withoutSensitive(t *testing.T, block *tfprotov6.SchemaBlock, v tftypes.Value) tftypes.Value {
	t.Helper()
	if v.IsNull() || !v.IsKnown() {
		return v
	}
	// As returns the value's own map: a copy keeps the caller's value as it
	// is.
	attrs := harnessObjectAttributes(t, v.Copy())
	for _, attr := range block.Attributes {
		value, ok := attrs[attr.Name]
		if !ok || value.IsNull() {
			continue
		}
		switch {
		case attr.Sensitive:
			attrs[attr.Name] = tftypes.NewValue(value.Type(), nil)
		case attr.NestedType != nil:
			attrs[attr.Name] = withoutSensitiveNested(t, attr.NestedType, value)
		}
	}
	return tftypes.NewValue(v.Type(), attrs)
}

func withoutSensitiveNested(t *testing.T, nested *tfprotov6.SchemaObject, v tftypes.Value) tftypes.Value {
	t.Helper()
	object := func(o tftypes.Value) tftypes.Value {
		return withoutSensitive(t, &tfprotov6.SchemaBlock{Attributes: nested.Attributes}, o)
	}
	v = v.Copy()
	switch nested.Nesting {
	case tfprotov6.SchemaObjectNestingModeSingle:
		return object(v)
	case tfprotov6.SchemaObjectNestingModeMap:
		var elements map[string]tftypes.Value
		if err := v.As(&elements); err != nil {
			t.Fatal(err)
		}
		for k, e := range elements {
			elements[k] = object(e)
		}
		return tftypes.NewValue(v.Type(), elements)
	default:
		var elements []tftypes.Value
		if err := v.As(&elements); err != nil {
			t.Fatal(err)
		}
		for i, e := range elements {
			elements[i] = object(e)
		}
		return tftypes.NewValue(v.Type(), elements)
	}
}
