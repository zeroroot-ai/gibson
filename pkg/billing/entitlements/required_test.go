package entitlements

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	entitlementsv1 "github.com/zeroroot-ai/gibson/pkg/billing/entitlements/v1"
)

// ---------------------------------------------------------------------------
// Required() / IsRequired() / ErrEntitlementsRequired
// ---------------------------------------------------------------------------

func TestRequired_FalseWhenUnset(t *testing.T) {
	t.Setenv(RequiredKnob, "")
	if Required() {
		t.Fatal("Required() must be false when knob is unset")
	}
}

func TestRequired_TrueWhenSetTrue(t *testing.T) {
	for _, val := range []string{"true", "TRUE", "True", "  true  "} {
		t.Setenv(RequiredKnob, val)
		if !Required() {
			t.Fatalf("Required() must be true for %q", val)
		}
	}
}

func TestRequired_FalseForOtherValues(t *testing.T) {
	for _, val := range []string{"1", "yes", "on", "false", "0"} {
		t.Setenv(RequiredKnob, val)
		if Required() {
			t.Fatalf("Required() must be false for %q", val)
		}
	}
}

func TestIsRequired_IdentifiesSentinel(t *testing.T) {
	if !IsRequired(ErrEntitlementsRequired) {
		t.Fatal("IsRequired must return true for ErrEntitlementsRequired")
	}
}

func TestIsRequired_WrappedError(t *testing.T) {
	wrapped := fmt.Errorf("outer: %w", ErrEntitlementsRequired)
	if !IsRequired(wrapped) {
		t.Fatal("IsRequired must return true for a wrapped ErrEntitlementsRequired")
	}
}

func TestIsRequired_UnrelatedError(t *testing.T) {
	if IsRequired(errors.New("some other error")) {
		t.Fatal("IsRequired must return false for unrelated errors")
	}
}

func TestIsRequired_Nil(t *testing.T) {
	if IsRequired(nil) {
		t.Fatal("IsRequired must return false for nil")
	}
}

// ---------------------------------------------------------------------------
// BlockedProvider
// ---------------------------------------------------------------------------

func TestBlockedProvider_AlwaysReturnsErrEntitlementsRequired(t *testing.T) {
	p := NewBlockedProvider(nil)
	_, err := p.Limits(context.Background(), "acme")
	if !IsRequired(err) {
		t.Fatalf("BlockedProvider must return ErrEntitlementsRequired, got %v", err)
	}
}

func TestBlockedProvider_NonZeroError(t *testing.T) {
	p := NewBlockedProvider(nil)
	lim, err := p.Limits(context.Background(), "acme")
	if err == nil {
		t.Fatal("BlockedProvider must error")
	}
	_ = lim // Limits value is meaningless when err != nil; caller must not use it
}

// ---------------------------------------------------------------------------
// New() — SaaS mode (GIBSON_ENTITLEMENTS_REQUIRED=true)
// ---------------------------------------------------------------------------

// TestNew_SaaS_MissingEndpoint_ReturnsBlockedProvider verifies that when
// GIBSON_ENTITLEMENTS_REQUIRED=true and ENTITLEMENTS_ENDPOINT is absent, New
// returns a BlockedProvider (not ConfigProvider / unlimited).
// This is the boot guard for invariant #4 (gibson#1098): a SaaS deploy that
// forgot the knob gets denied requests, not unlimited.
func TestNew_SaaS_MissingEndpoint_ReturnsBlockedProvider(t *testing.T) {
	t.Setenv(RequiredKnob, "true")
	t.Setenv(SeamKnob, "")

	p := New(nil)
	if _, ok := p.(*BlockedProvider); !ok {
		t.Fatalf("SaaS mode + missing endpoint: expected *BlockedProvider, got %T", p)
	}
}

// TestNew_SaaS_MissingEndpoint_DeniesChecks verifies end-to-end that the
// BlockedProvider installed by New in SaaS mode actually denies Limits calls.
func TestNew_SaaS_MissingEndpoint_DeniesChecks(t *testing.T) {
	t.Setenv(RequiredKnob, "true")
	t.Setenv(SeamKnob, "")

	p := New(nil)
	_, err := p.Limits(context.Background(), "acme")
	if !IsRequired(err) {
		t.Fatalf("SaaS mode + missing endpoint: Limits must return ErrEntitlementsRequired, got %v", err)
	}
}

// TestNew_SaaS_RemoteFailure_ReturnsBlockedProvider verifies that when the
// ENTITLEMENTS_ENDPOINT is set but remote construction fails (e.g. bad SVID,
// SPIRE socket missing), New returns a BlockedProvider in SaaS mode, not the
// OSS ConfigProvider fallback.
// Note: in the test environment the SPIRE socket is absent, so NewGRPCProvider
// always fails with a real endpoint — that's exactly the condition we want to
// test.
func TestNew_SaaS_RemoteFailure_ReturnsBlockedProvider(t *testing.T) {
	t.Setenv(RequiredKnob, "true")
	t.Setenv(SeamKnob, "localhost:59991") // unreachable; SPIRE socket absent → construction fails

	p := New(nil)
	// The seam fallback in SaaS mode must install BlockedProvider.
	if _, ok := p.(*BlockedProvider); !ok {
		t.Fatalf("SaaS mode + remote failure: expected *BlockedProvider, got %T", p)
	}
}

// TestNew_OSS_MissingEndpoint_ReturnsConfigProvider verifies that without the
// required knob, New returns the OSS config-driven default (unchanged behaviour).
// This is the "unlimited-but-metered" OSS acceptance test folded in from
// gibson#1095 / the #1097 comment.
func TestNew_OSS_MissingEndpoint_ReturnsConfigProvider(t *testing.T) {
	t.Setenv(RequiredKnob, "")
	t.Setenv(SeamKnob, "")

	p := New(nil)
	if _, ok := p.(*configProvider); !ok {
		t.Fatalf("OSS mode + missing endpoint: expected *configProvider, got %T", p)
	}
}

// TestNew_OSS_LimitsAreUnlimited verifies that OSS mode (required=false,
// endpoint unset) returns unlimited on every dimension with no error.
func TestNew_OSS_LimitsAreUnlimited(t *testing.T) {
	t.Setenv(RequiredKnob, "")
	t.Setenv(SeamKnob, "")

	p := New(nil)
	lim, err := p.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("OSS mode must not error, got %v", err)
	}
	if lim != (Limits{}) {
		t.Fatalf("OSS mode must be unlimited (zero Limits), got %+v", lim)
	}
}

// ---------------------------------------------------------------------------
// gRPC provider — SaaS per-call fail-closed (invariant #3, gibson#1097)
// ---------------------------------------------------------------------------

// newTestGRPCProviderRequired starts an in-process gRPC server and returns a
// Required=true grpcProvider wired to it.
func newTestGRPCProviderRequired(t *testing.T, srv *fakeEntitlementsServer) (Provider, *grpc.Server) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	grpcSrv := grpc.NewServer()
	entitlementsv1.RegisterEntitlementsServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		grpcSrv.Stop()
		t.Fatalf("dial: %v", err)
	}

	p, err := NewGRPCProvider(GRPCProviderOptions{
		Endpoint: lis.Addr().String(),
		CacheTTL: 60 * time.Second,
		DialConn: conn,
		Required: true, // SaaS mode
	})
	if err != nil {
		grpcSrv.Stop()
		t.Fatalf("NewGRPCProvider: %v", err)
	}

	return p, grpcSrv
}

// TestGRPCProvider_SaaS_RPCError_FailsClosed verifies that in SaaS mode
// (Required=true) a non-OK gRPC status returns ErrEntitlementsRequired
// rather than zero (unlimited) Limits.
// This is the per-call fix for invariant #3 (gibson#1097).
func TestGRPCProvider_SaaS_RPCError_FailsClosed(t *testing.T) {
	srv := &fakeEntitlementsServer{
		err: status.Error(codes.Internal, "billing service internal error"),
	}
	p, grpcSrv := newTestGRPCProviderRequired(t, srv)
	defer grpcSrv.Stop()

	_, err := p.Limits(context.Background(), "acme")
	if !IsRequired(err) {
		t.Fatalf("SaaS mode: RPC error must return ErrEntitlementsRequired, got %v", err)
	}
}

// TestGRPCProvider_SaaS_TransportError_FailsClosed verifies that in SaaS mode
// a transport-level failure (server stopped) also fails closed.
func TestGRPCProvider_SaaS_TransportError_FailsClosed(t *testing.T) {
	srv := &fakeEntitlementsServer{}
	p, grpcSrv := newTestGRPCProviderRequired(t, srv)
	grpcSrv.Stop() // drop the connection

	_, err := p.Limits(context.Background(), "acme")
	if !IsRequired(err) {
		t.Fatalf("SaaS mode: transport error must return ErrEntitlementsRequired, got %v", err)
	}
}

// TestGRPCProvider_SaaS_SuccessStillWorks verifies that successful RPC calls
// in SaaS mode still return the correct Limits (the fail-closed path is only
// for errors).
func TestGRPCProvider_SaaS_SuccessStillWorks(t *testing.T) {
	srv := &fakeEntitlementsServer{
		results: map[string]*entitlementsv1.Limits{
			"acme": {ConcurrentMissions: 5, ConcurrentAgents: 10},
		},
	}
	p, grpcSrv := newTestGRPCProviderRequired(t, srv)
	defer grpcSrv.Stop()

	lim, err := p.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("SaaS mode: successful RPC must not error, got %v", err)
	}
	want := Limits{ConcurrentMissions: 5, ConcurrentAgents: 10}
	if lim != want {
		t.Fatalf("SaaS mode: got %+v want %+v", lim, want)
	}
}

// TestGRPCProvider_OSS_RPCError_FailsOpen verifies that in OSS mode
// (Required=false, the default) an RPC error still yields unlimited (nil
// error, zero Limits) — the pre-existing fail-open behaviour is unchanged.
func TestGRPCProvider_OSS_RPCError_FailsOpen(t *testing.T) {
	srv := &fakeEntitlementsServer{
		err: status.Error(codes.Internal, "billing service internal error"),
	}
	p, grpcSrv := newTestGRPCProvider(t, srv, 60*time.Second) // Required=false (existing helper)
	defer grpcSrv.Stop()

	lim, err := p.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("OSS mode: RPC error must not propagate error, got %v", err)
	}
	if lim != (Limits{}) {
		t.Fatalf("OSS mode: RPC error must yield zero (unlimited) Limits, got %+v", lim)
	}
}
