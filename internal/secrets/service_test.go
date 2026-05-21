package secrets

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/sdk/auth"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
)

// --- fakes ---

// fakeServiceRegistry implements ServiceRegistry.
type fakeServiceRegistry struct {
	broker sdksecrets.Broker
	err    error
}

func (f *fakeServiceRegistry) For(_ context.Context, _ auth.TenantID) (sdksecrets.Broker, error) {
	return f.broker, f.err
}

// fakeCircuit implements ServiceCircuitBreaker, always allowing unless
// allowErr is set.
type fakeCircuit struct {
	allowErr     error
	successCalls int
	failureCalls int
}

func (f *fakeCircuit) Allow(_, _ string) error   { return f.allowErr }
func (f *fakeCircuit) RecordSuccess(_, _ string) { f.successCalls++ }
func (f *fakeCircuit) RecordFailure(_, _ string) { f.failureCalls++ }

// serviceFakeBroker is a configurable broker for service tests.
type serviceFakeBroker struct {
	getVal []byte
	getErr error
	putErr error
	delErr error
	lstVal []string
	lstErr error
}

var _ sdksecrets.Broker = (*serviceFakeBroker)(nil)

func (b *serviceFakeBroker) Get(_ context.Context, _ auth.TenantID, _ string) ([]byte, error) {
	return b.getVal, b.getErr
}
func (b *serviceFakeBroker) Put(_ context.Context, _ auth.TenantID, _ string, _ []byte) error {
	return b.putErr
}
func (b *serviceFakeBroker) Delete(_ context.Context, _ auth.TenantID, _ string) error {
	return b.delErr
}
func (b *serviceFakeBroker) List(_ context.Context, _ auth.TenantID, _ sdksecrets.Filter) ([]string, error) {
	return b.lstVal, b.lstErr
}
func (b *serviceFakeBroker) Health(_ context.Context) error { return nil }
func (b *serviceFakeBroker) Probe(_ context.Context) error  { return nil }
func (b *serviceFakeBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{CanPut: true, CanDelete: true, CanList: true, MaxValueBytes: 1 << 20}
}

// ctxWithTestTenant returns a context carrying the given tenant via
// auth.WithTenant (test helper from the SDK auth package).
func ctxWithTestTenant(tenant auth.TenantID) context.Context {
	return auth.WithTenant(context.Background(), tenant)
}

var svcTenant = auth.MustNewTenantID("acme-corp")

func buildService(
	broker sdksecrets.Broker,
	circuit ServiceCircuitBreaker,
	auditor ServiceAuditWriter,
) *Service {
	reg := &fakeServiceRegistry{broker: broker}
	svc, err := NewService(reg, circuit, auditor)
	if err != nil {
		panic("buildService: " + err.Error())
	}
	return svc
}

// --- Resolve ---

func TestService_Resolve_Success(t *testing.T) {
	want := []byte("super-secret")
	broker := &serviceFakeBroker{getVal: want}
	circuit := &fakeCircuit{}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	got, err := svc.Resolve(ctx, "cred:openai")
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, 1, circuit.successCalls)
	assert.Equal(t, 0, circuit.failureCalls)
	require.Len(t, aud.events, 1)
	assert.Equal(t, EffectAllow, aud.events[0].Effect)
	assert.Equal(t, ActionSecretRead, aud.events[0].Action)
}

func TestService_Resolve_NotFound(t *testing.T) {
	broker := &serviceFakeBroker{getErr: fmt.Errorf("not found: %w", sdksecrets.ErrNotFound)}
	circuit := &fakeCircuit{}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	_, err := svc.Resolve(ctx, "cred:missing")
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())

	assert.Equal(t, 1, circuit.failureCalls)
	require.Len(t, aud.events, 1)
	assert.Equal(t, EffectDeny, aud.events[0].Effect)
}

func TestService_Resolve_CircuitOpen(t *testing.T) {
	broker := &serviceFakeBroker{getVal: []byte("value")}
	circuit := &fakeCircuit{allowErr: fmt.Errorf("open: %w", sdksecrets.ErrUnavailable)}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	_, err := svc.Resolve(ctx, "cred:x")
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	require.Len(t, aud.events, 1)
	assert.Equal(t, "circuit_open", aud.events[0].DecisionReason)
}

func TestService_Resolve_NoTenantInContext(t *testing.T) {
	broker := &serviceFakeBroker{getVal: []byte("x")}
	circuit := &fakeCircuit{}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)

	_, err := svc.Resolve(context.Background(), "cred:x")
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

// --- Put ---

func TestService_Put_Success(t *testing.T) {
	broker := &serviceFakeBroker{}
	circuit := &fakeCircuit{}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	require.NoError(t, svc.Put(ctx, "cred:foo", []byte("val")))
	assert.Equal(t, 1, circuit.successCalls)
	require.Len(t, aud.events, 1)
	assert.Equal(t, EffectAllow, aud.events[0].Effect)
	assert.Equal(t, ActionSecretWrite, aud.events[0].Action)
}

func TestService_Put_Unavailable(t *testing.T) {
	broker := &serviceFakeBroker{putErr: fmt.Errorf("transient: %w", sdksecrets.ErrUnavailable)}
	circuit := &fakeCircuit{}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	err := svc.Put(ctx, "cred:foo", []byte("val"))
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Equal(t, 1, circuit.failureCalls)
}

// --- Delete ---

func TestService_Delete_Success(t *testing.T) {
	broker := &serviceFakeBroker{}
	circuit := &fakeCircuit{}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	require.NoError(t, svc.Delete(ctx, "cred:foo"))
	assert.Equal(t, 1, circuit.successCalls)
	require.Len(t, aud.events, 1)
	assert.Equal(t, ActionSecretDelete, aud.events[0].Action)
	assert.Equal(t, EffectAllow, aud.events[0].Effect)
}

// --- List ---

func TestService_List_Success(t *testing.T) {
	want := []string{"cred:foo", "cred:bar"}
	broker := &serviceFakeBroker{lstVal: want}
	circuit := &fakeCircuit{}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	got, err := svc.List(ctx, sdksecrets.Filter{})
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, 1, circuit.successCalls)
	require.Len(t, aud.events, 1)
	assert.Equal(t, ActionSecretList, aud.events[0].Action)
}

func TestService_List_CircuitOpen(t *testing.T) {
	broker := &serviceFakeBroker{}
	circuit := &fakeCircuit{allowErr: fmt.Errorf("open: %w", sdksecrets.ErrUnavailable)}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	_, err := svc.List(ctx, sdksecrets.Filter{})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())
}

// --- Error mapping ---

func TestToGRPCError_Mapping(t *testing.T) {
	tests := []struct {
		err      error
		wantCode codes.Code
	}{
		{fmt.Errorf("%w", sdksecrets.ErrNotFound), codes.NotFound},
		{fmt.Errorf("%w", sdksecrets.ErrPermissionDenied), codes.PermissionDenied},
		{fmt.Errorf("%w", sdksecrets.ErrUnavailable), codes.Unavailable},
		{fmt.Errorf("%w", sdksecrets.ErrInvalidArgument), codes.InvalidArgument},
		{fmt.Errorf("%w", sdksecrets.ErrUnsupported), codes.FailedPrecondition},
		{fmt.Errorf("%w", sdksecrets.ErrTooLarge), codes.InvalidArgument},
		{errors.New("unknown"), codes.Unavailable},
	}
	for _, tc := range tests {
		got := toGRPCError(tc.err, "op")
		st, ok := status.FromError(got)
		require.True(t, ok, "expected gRPC status error for %v", tc.err)
		assert.Equal(t, tc.wantCode, st.Code(), "wrong code for %v", tc.err)
	}
}

func TestToGRPCError_Nil(t *testing.T) {
	assert.NoError(t, toGRPCError(nil, "op"))
}

// TestService_ResourceURIContainsTenantAndName verifies the audit event has
// the correct resource URI format.
func TestService_ResourceURIContainsTenantAndName(t *testing.T) {
	broker := &serviceFakeBroker{getVal: []byte("v")}
	circuit := &fakeCircuit{}
	aud := &fakeAuditCapture{}

	svc := buildService(broker, circuit, aud)
	ctx := ctxWithTestTenant(svcTenant)

	_, err := svc.Resolve(ctx, "cred:db-password")
	require.NoError(t, err)

	require.Len(t, aud.events, 1)
	assert.Contains(t, aud.events[0].ResourceURI, svcTenant.String())
	assert.Contains(t, aud.events[0].ResourceURI, "cred:db-password")
}
