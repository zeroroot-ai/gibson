package component

// service_authz_test.go verifies that RegisterComponent writes FGA component
// ownership tuples on success and that a nil authorizer (noop/disabled mode)
// does not panic.
//
// The test uses a minimal mock authorizer that satisfies the authz.Authorizer
// interface so the component package can remain decoupled from the live FGA
// client.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// mockAuthorizer — minimal authz.Authorizer for unit tests
// ---------------------------------------------------------------------------

// mockAuthorizer records Write and Delete calls and optionally returns errors.
type mockAuthorizer struct {
	writtenTuples []authz.Tuple
	deletedTuples []authz.Tuple
	writeErr      error
	deleteErr     error
}

func (m *mockAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }
func (m *mockAuthorizer) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (m *mockAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writtenTuples = append(m.writtenTuples, tuples...)
	return nil
}
func (m *mockAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletedTuples = append(m.deletedTuples, tuples...)
	return nil
}
func (m *mockAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthorizer) StoreID() string { return "test-store" }
func (m *mockAuthorizer) ModelID() string { return "test-model" }
func (m *mockAuthorizer) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// newAuthzServer builds a ComponentServiceServer with the supplied authorizer
// and a noop registry/queue. Uses the shared noopRegistry and noopWorkQueue
// defined in service_harness_parity_test.go (same package).
func newAuthzServer(az authz.Authorizer) *ComponentServiceServer {
	svc := NewComponentServiceServer(
		&noopRegistry{},
		&noopWorkQueue{},
		testLogger(),
		nil, nil, nil, nil, nil,
	)
	if az != nil {
		svc.WithAuthorizer(az)
	}
	return svc
}

// minimalRegisterReq returns a RegisterComponentRequest with the minimum
// required fields filled in.
func minimalRegisterReq(kind, name string) *componentpb.RegisterComponentRequest {
	return &componentpb.RegisterComponentRequest{
		Kind:    kind,
		Name:    name,
		Version: "v1.0.0",
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRegisterComponent_WritesOwnershipTuple verifies that on a successful
// RegisterComponent call the server writes exactly one FGA ownership tuple:
//
//	tenant:<slug>  owner  component:<name>
func TestRegisterComponent_WritesOwnershipTuple(t *testing.T) {
	mock := &mockAuthorizer{}
	svc := newAuthzServer(mock)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	resp, err := svc.RegisterComponent(ctx, minimalRegisterReq("agent", "recon-agent"))

	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetInstanceId())

	require.Len(t, mock.writtenTuples, 1, "expected exactly one FGA tuple to be written")
	tuple := mock.writtenTuples[0]
	assert.Equal(t, "tenant:acme", tuple.User)
	assert.Equal(t, "owner", tuple.Relation)
	assert.Equal(t, "component:recon-agent", tuple.Object)
}

// TestRegisterComponent_NilAuthorizer_NoPanic verifies that when no authorizer
// is wired (noop / authz.enabled=false mode) RegisterComponent succeeds
// without panicking and without attempting any FGA calls.
func TestRegisterComponent_NilAuthorizer_NoPanic(t *testing.T) {
	svc := newAuthzServer(nil) // no authorizer

	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	assert.NotPanics(t, func() {
		resp, err := svc.RegisterComponent(ctx, minimalRegisterReq("tool", "nmap"))
		require.NoError(t, err)
		assert.NotEmpty(t, resp.GetInstanceId())
	})
}

// TestRegisterComponent_FGAWriteFailure_DoesNotFailRegistration verifies that
// when the FGA Write call returns an error the RegisterComponent RPC still
// succeeds (best-effort — log WARN and continue).
func TestRegisterComponent_FGAWriteFailure_DoesNotFailRegistration(t *testing.T) {
	mock := &mockAuthorizer{
		writeErr: errors.New("fga: connection refused"),
	}
	svc := newAuthzServer(mock)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	resp, err := svc.RegisterComponent(ctx, minimalRegisterReq("plugin", "gitlab"))

	// Registration must succeed even when FGA is unavailable.
	require.NoError(t, err, "registration must succeed even when FGA write fails")
	assert.NotEmpty(t, resp.GetInstanceId())
}

// TestRegisterComponent_SystemTenant_WritesOwnershipTuple verifies that the
// _system tenant also gets an ownership tuple written. System components are
// platform-shared but still need FGA tuples for computed relations to work.
func TestRegisterComponent_SystemTenant_WritesOwnershipTuple(t *testing.T) {
	mock := &mockAuthorizer{}
	svc := newAuthzServer(mock)

	// auth.ContextWithTenantString rejects "_system" (reserved); use WithTenant
	// with auth.SystemTenant directly.
	ctx := auth.WithTenant(context.Background(), auth.SystemTenant)
	resp, err := svc.RegisterComponent(ctx, minimalRegisterReq("tool", "httpx"))

	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetInstanceId())

	require.Len(t, mock.writtenTuples, 1)
	assert.Equal(t, "tenant:_system", mock.writtenTuples[0].User)
	assert.Equal(t, "owner", mock.writtenTuples[0].Relation)
	assert.Equal(t, "component:httpx", mock.writtenTuples[0].Object)
}
