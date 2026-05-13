package component

// service_ontology_test.go verifies that WithOntologyReasoner wires the
// reasoner field, that nil is safe (no panic), and that the field is
// accessible for the deferred RegisterExtension call site.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/auth"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
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

// TestWithOntologyReasoner_FieldReachable verifies that when an OntologyReasoner
// is wired, RegisterComponent proceeds without error (the deferred proto-field
// call site is exercised via the _ = s.ontologyReasoner guard in service.go).
func TestWithOntologyReasoner_FieldReachable(t *testing.T) {
	t.Parallel()

	stub := newStubReasoner()
	svc := newTestServiceWithReasoner(stub)

	ctx := auth.ContextWithTenantString(context.Background(), "tenant-abc")
	req := &componentpb.RegisterComponentRequest{Kind: "tool", Name: "nmap"}

	resp, err := svc.RegisterComponent(ctx, req)
	require.NoError(t, err, "RegisterComponent must succeed when ontologyReasoner is wired")
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.InstanceId)

	// No extensions should have been registered yet (proto field is deferred).
	assert.Empty(t, stub.registered, "no extensions should be registered until proto field lands")
}
