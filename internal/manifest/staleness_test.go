package manifest

import (
	"context"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func mdCtx(headers ...string) context.Context {
	md := metadata.MD{}
	for i := 0; i+1 < len(headers); i += 2 {
		md.Append(headers[i], headers[i+1])
	}
	return metadata.NewIncomingContext(context.Background(), md)
}

func stalenessInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func stalenessHandlerOK(called *bool) grpc.UnaryHandler {
	return func(ctx context.Context, req any) (any, error) {
		*called = true
		return "ok", nil
	}
}

func TestStaleness_PassesOnCurrentHeader(t *testing.T) {
	vs := newCountingVersions()
	vs.bumps["tenant-a"] = 10
	ctx := mdCtx(ManifestVersionHeader, "10")
	intr := NewStalenessInterceptor(vs, StalenessOptions{
		TenantResolver: func(_ context.Context) string { return "tenant-a" },
	})
	called := false
	_, err := intr(ctx, nil, stalenessInfo("/svc/M"), stalenessHandlerOK(&called))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !called {
		t.Fatalf("handler should have been invoked")
	}
}

func TestStaleness_PassesWithinTolerance(t *testing.T) {
	vs := newCountingVersions()
	vs.bumps["tenant-a"] = 10
	ctx := mdCtx(ManifestVersionHeader, "8") // delta 2 == tolerance
	intr := NewStalenessInterceptor(vs, StalenessOptions{
		Tolerance:      2,
		TenantResolver: func(_ context.Context) string { return "tenant-a" },
	})
	called := false
	if _, err := intr(ctx, nil, stalenessInfo("/svc/M"), stalenessHandlerOK(&called)); err != nil {
		t.Fatalf("err = %v", err)
	}
	if !called {
		t.Fatalf("within-tolerance call should pass")
	}
}

func TestStaleness_RejectsBeyondTolerance(t *testing.T) {
	vs := newCountingVersions()
	vs.bumps["tenant-a"] = 10
	ctx := mdCtx(ManifestVersionHeader, "5") // delta 5 > tolerance 2
	intr := NewStalenessInterceptor(vs, StalenessOptions{
		Tolerance:      2,
		TenantResolver: func(_ context.Context) string { return "tenant-a" },
	})
	called := false
	_, err := intr(ctx, nil, stalenessInfo("/svc/M"), stalenessHandlerOK(&called))
	if err == nil {
		t.Fatalf("expected staleness rejection")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", st.Code())
	}
	cur, sup, ok := ParseStalenessError(err)
	if !ok || cur != 10 || sup != 5 {
		t.Fatalf("ParseStalenessError = (%d, %d, %v)", cur, sup, ok)
	}
	if called {
		t.Fatalf("handler should NOT be called on stale rejection")
	}
}

func TestStaleness_SkipsManifestRPCs(t *testing.T) {
	vs := newCountingVersions()
	vs.bumps["tenant-a"] = 10
	// Supply a very stale header — would normally reject — but the
	// skip list must short-circuit it.
	ctx := mdCtx(ManifestVersionHeader, "1")
	intr := NewStalenessInterceptor(vs, StalenessOptions{
		Tolerance:      2,
		TenantResolver: func(_ context.Context) string { return "tenant-a" },
	})
	called := false
	_, err := intr(ctx, nil, stalenessInfo("/gibson.daemon.v1.DaemonService/GetCapabilityManifest"), stalenessHandlerOK(&called))
	if err != nil {
		t.Fatalf("skipped RPC should not reject: %v", err)
	}
	if !called {
		t.Fatalf("skipped RPC handler should run")
	}
}

func TestStaleness_AgentPrincipalMustSupplyHeader(t *testing.T) {
	vs := newCountingVersions()
	ctx := context.Background() // no header
	intr := NewStalenessInterceptor(vs, StalenessOptions{
		RequireHeaderForAgentPrincipal: true,
		SubjectIsAgentPrincipal:        func(_ context.Context) bool { return true },
	})
	called := false
	_, err := intr(ctx, nil, stalenessInfo("/svc/M"), stalenessHandlerOK(&called))
	if err == nil {
		t.Fatalf("expected rejection for agent without header")
	}
	if called {
		t.Fatalf("handler must not run when agent omits header")
	}
}

func TestStaleness_HumanMayOmitHeader(t *testing.T) {
	vs := newCountingVersions()
	ctx := context.Background()
	intr := NewStalenessInterceptor(vs, StalenessOptions{
		RequireHeaderForAgentPrincipal: true,
		SubjectIsAgentPrincipal:        func(_ context.Context) bool { return false },
	})
	called := false
	if _, err := intr(ctx, nil, stalenessInfo("/svc/M"), stalenessHandlerOK(&called)); err != nil {
		t.Fatalf("human without header should pass: %v", err)
	}
	if !called {
		t.Fatalf("handler should run for human caller")
	}
}

func TestStaleness_UnparseableHeaderTreatedAsAbsent(t *testing.T) {
	vs := newCountingVersions()
	ctx := mdCtx(ManifestVersionHeader, "not-a-number")
	intr := NewStalenessInterceptor(vs, StalenessOptions{
		TenantResolver: func(_ context.Context) string { return "tenant-a" },
	})
	called := false
	if _, err := intr(ctx, nil, stalenessInfo("/svc/M"), stalenessHandlerOK(&called)); err != nil {
		t.Fatalf("unparseable header should be treated as absent: %v", err)
	}
	if !called {
		t.Fatalf("handler should run")
	}
}

// Compile-time sanity: strconv import used from test body in ParseStalenessError roundtrip.
var _ = strconv.ParseUint
