package component

// service_ontology_test.go verifies that WithOntologyReasoner wires the
// reasoner field, that nil is safe (no panic), and that RegisterComponent
// forwards a wire-form OntologyExtension to the reasoner.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// ---------------------------------------------------------------------------
// stubOntologyReasoner — minimal OntologyReasoner for unit tests
// ---------------------------------------------------------------------------

type stubOntologyReasoner struct {
	registered   map[string]sdkgraphrag.OntologyExtension
	unregistered []string
	registerErr  error
}

func newStubReasoner() *stubOntologyReasoner {
	return &stubOntologyReasoner{registered: make(map[string]sdkgraphrag.OntologyExtension)}
}

func (s *stubOntologyReasoner) RegisterExtension(name string, ext sdkgraphrag.OntologyExtension) error {
	if s.registerErr != nil {
		return s.registerErr
	}
	s.registered[name] = ext
	return nil
}

func (s *stubOntologyReasoner) UnregisterExtension(name string) error {
	s.unregistered = append(s.unregistered, name)
	delete(s.registered, name)
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// newTestServiceWithReasoner creates a ComponentServiceServer with the stub
// reasoner and the shared noopRegistry / noopWorkQueue from test helpers.
func newTestServiceWithReasoner(or OntologyReasoner) *ComponentServiceServer {
	svc := NewComponentServiceServer(
		&noopRegistry{},
		&noopWorkQueue{},
		nil, // logger — defaults to slog.Default()
		nil, // llmCompleter
		nil, // memStore
		nil, // findingSubmitter
		nil, // pluginAccess
		nil, // auditLog
	)
	svc.WithOntologyReasoner(or)
	return svc
}

// TestWithOntologyReasoner_Wired verifies that WithOntologyReasoner stores the
// reasoner and that it is accessible after construction.
func TestWithOntologyReasoner_Wired(t *testing.T) {
	t.Parallel()

	stub := newStubReasoner()
	svc := newTestServiceWithReasoner(stub)

	assert.Equal(t, stub, svc.ontologyReasoner,
		"ontologyReasoner field must equal the stub passed to WithOntologyReasoner")
}

// TestWithOntologyReasoner_NilIsSafe verifies that wiring nil does not panic
// and that RegisterComponent completes successfully.
func TestWithOntologyReasoner_NilIsSafe(t *testing.T) {
	t.Parallel()

	svc := newTestServiceWithReasoner(nil)

	ctx := auth.ContextWithTenantString(context.Background(), "tenant-abc")
	req := &componentpb.RegisterComponentRequest{Kind: "agent", Name: "test-agent"}

	resp, err := svc.RegisterComponent(ctx, req)
	require.NoError(t, err, "RegisterComponent with nil ontologyReasoner must not error")
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.InstanceId)
}

// TestRegisterComponent_NoOntologyExtension_Skips verifies that when the
// request carries no OntologyExtension payload, RegisterComponent does not
// touch the reasoner — soft skip, not a hard guard.
func TestRegisterComponent_NoOntologyExtension_Skips(t *testing.T) {
	t.Parallel()

	stub := newStubReasoner()
	svc := newTestServiceWithReasoner(stub)

	ctx := auth.ContextWithTenantString(context.Background(), "tenant-abc")
	req := &componentpb.RegisterComponentRequest{Kind: "tool", Name: "nmap"}

	resp, err := svc.RegisterComponent(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, stub.registered, "reasoner must not be called when ontology_extension is unset")
}

// TestRegisterComponent_OntologyExtension_Registers exercises the active wire
// path: when the request carries an OntologyExtension, the reasoner sees the
// parsed Go-form struct under the component's name.
func TestRegisterComponent_OntologyExtension_Registers(t *testing.T) {
	t.Parallel()

	stub := newStubReasoner()
	svc := newTestServiceWithReasoner(stub)

	ctx := auth.ContextWithTenantString(context.Background(), "tenant-abc")
	req := &componentpb.RegisterComponentRequest{
		Kind: "tool",
		Name: "nmap",
		OntologyExtension: &graphragpb.OntologyExtension{
			Prefixes: map[string]string{"mycorp": "https://mycorp.example/"},
			Hierarchies: []*graphragpb.HierarchyDef{
				{NodeType: "finding", Label: "mycorp:LeakedKey", SubClassOf: "mycorp:Sensitive"},
			},
			Equivalences: []*graphragpb.SameAsPair{
				{IriA: "mycorp:LeakedKey", IriB: "gibson:disclosure"},
			},
			Ifps: []*graphragpb.IFPDef{
				{NodeType: "my_artifact", Property: "content_hash"},
			},
		},
	}

	resp, err := svc.RegisterComponent(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Contains(t, stub.registered, "nmap",
		"reasoner must see the extension keyed by component name")
	got := stub.registered["nmap"]
	assert.Equal(t, map[string]string{"mycorp": "https://mycorp.example/"}, got.Prefixes)
	require.Len(t, got.Hierarchies, 1)
	assert.Equal(t, "mycorp:LeakedKey", got.Hierarchies[0].Label)
	require.Len(t, got.Equivalences, 1)
	assert.Equal(t, [2]string{"mycorp:LeakedKey", "gibson:disclosure"}, got.Equivalences[0])
	require.Len(t, got.IFPs, 1)
	assert.Equal(t, "content_hash", got.IFPs[0].Property)
}

// TestRegisterComponent_OntologyExtension_ReasonerErrorIsSoft verifies that a
// reasoner.RegisterExtension failure does NOT propagate to the RPC caller —
// missing ontology hierarchy is a soft degradation, the component still
// enrolls successfully.
func TestRegisterComponent_OntologyExtension_ReasonerErrorIsSoft(t *testing.T) {
	t.Parallel()

	stub := newStubReasoner()
	stub.registerErr = assert.AnError
	svc := newTestServiceWithReasoner(stub)

	ctx := auth.ContextWithTenantString(context.Background(), "tenant-abc")
	req := &componentpb.RegisterComponentRequest{
		Kind: "tool",
		Name: "nmap",
		OntologyExtension: &graphragpb.OntologyExtension{
			Prefixes: map[string]string{"x": "https://x.example/"},
		},
	}

	resp, err := svc.RegisterComponent(ctx, req)
	require.NoError(t, err, "reasoner error must not fail the enrollment RPC")
	require.NotNil(t, resp)
}
