// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zeroroot-ai/gibson/internal/infra/grpcvalidate"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// claimChainValidator returns the validator that CallbackServer.Start gives to
// identityUnaryChain.
func claimChainValidator(t *testing.T) protovalidate.Validator {
	t.Helper()
	pv, err := grpcvalidate.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	return pv
}

// recordingCallback counts the calls that reach the service, so a test can
// tell a refusal by the chain from a refusal by a handler.
type recordingCallback struct {
	harnesspb.UnimplementedHarnessCallbackServiceServer
	service *HarnessCallbackService
	reached int
}

func (r *recordingCallback) CreateMission(
	_ context.Context, _ *harnesspb.CreateMissionRequest,
) (*harnesspb.CreateMissionResponse, error) {
	r.reached++
	return &harnesspb.CreateMissionResponse{}, nil
}

// callbackChainClient serves a recording service behind the unary chain of the
// callback listener, with the validator that Start builds, and returns a client.
func callbackChainClient(t *testing.T) (harnesspb.HarnessCallbackServiceClient, *recordingCallback) {
	t.Helper()
	return callbackChainClientWith(t, &fakeGrantVerifier{})
}

// callbackChainClientWith is callbackChainClient with the given grant verifier.
func callbackChainClientWith(t *testing.T, verifier TaskGrantVerifier) (harnesspb.HarnessCallbackServiceClient, *recordingCallback) {
	t.Helper()
	s, _ := claimService(t)
	grantUnary, _ := taskGrantScopeInterceptors(getter(verifier),
		&forkGuard{ledger: s.forkLedger, identity: s.sandboxIdentity}, slog.Default())
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(s.identityUnaryChain(grantUnary, claimChainValidator(t))...))
	rec := &recordingCallback{service: s}
	harnesspb.RegisterHarnessCallbackServiceServer(srv, rec)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return harnesspb.NewHarnessCallbackServiceClient(conn), rec
}

// agentCallCtx is the outgoing metadata of a call from a component, as the
// edge forwards it.
func agentCallCtx() context.Context {
	md := metadata.MD{}
	for k, v := range headers.Emit(headers.Identity{
		Subject:        "component:zerocool",
		Issuer:         headers.IssuerCapabilityGrant,
		CredentialType: headers.CredentialCapabilityGrant,
		Tenant:         "acme",
		IssuedAt:       time.Now().UTC(),
	}) {
		md.Set(k, v...)
	}
	return metadata.NewOutgoingContext(context.Background(), md)
}

func pairsOf(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("p%d", i)] = "v"
	}
	return m
}

// CreateMission with more catalog_params pairs than the cap is refused as
// InvalidArgument before the service sees it. The agent path and the person
// path accept the same input (gibson#1668).
func TestCallbackChain_CreateMissionCatalogParamsCap(t *testing.T) {
	cases := []struct {
		name      string
		params    map[string]string
		want      codes.Code
		wantReach int
	}{
		{"64 pairs pass", pairsOf(64), codes.OK, 1},
		{"65 pairs are refused", pairsOf(65), codes.InvalidArgument, 0},
		{"a bad key is refused", map[string]string{"1bad": "v"}, codes.InvalidArgument, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, rec := callbackChainClient(t)
			_, err := client.CreateMission(agentCallCtx(), &harnesspb.CreateMissionRequest{
				CatalogMission: "recon",
				CatalogParams:  tc.params,
			})
			if got := status.Code(err); got != tc.want {
				t.Fatalf("code = %v (%v), want %v", got, err, tc.want)
			}
			if rec.reached != tc.wantReach {
				t.Fatalf("handler reached %d times, want %d", rec.reached, tc.wantReach)
			}
		})
	}
}

// The validation runs after the identity and the grant. A request with no
// identity gets PermissionDenied, and a request with a grant that cannot be
// verified gets Unauthenticated too. Neither learns that the request breaks a
// rule (gibson#1668).
func TestCallbackChain_ValidationRunsAfterAuthAndGrant(t *testing.T) {
	bad := &harnesspb.CreateMissionRequest{CatalogMission: "recon", CatalogParams: pairsOf(65)}

	t.Run("no identity", func(t *testing.T) {
		client, rec := callbackChainClient(t)
		_, err := client.CreateMission(context.Background(), bad)
		// The sdk auth interceptor refuses a call with no identity headers as
		// PermissionDenied. The code that matters here is that it is not
		// InvalidArgument.
		if got := status.Code(err); got != codes.PermissionDenied {
			t.Fatalf("code = %v (%v), want PermissionDenied", got, err)
		}
		if rec.reached != 0 {
			t.Fatalf("handler reached %d times, want 0", rec.reached)
		}
	})

	t.Run("grant that cannot be verified", func(t *testing.T) {
		client, rec := callbackChainClientWith(t, &fakeGrantVerifier{err: errors.New("bad signature")})
		ctx := metadata.AppendToOutgoingContext(agentCallCtx(), taskGrantHeader, "not-a-real-grant")
		_, err := client.CreateMission(ctx, bad)
		if got := status.Code(err); got != codes.Unauthenticated {
			t.Fatalf("code = %v (%v), want Unauthenticated", got, err)
		}
		if rec.reached != 0 {
			t.Fatalf("handler reached %d times, want 0", rec.reached)
		}
	})
}

// freeLoopbackPort returns a port that no listener holds at the time of the call.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	tcp, ok := lis.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T is not a TCP address", lis.Addr())
	}
	return tcp.Port
}

// The real server that Start builds refuses a CreateMission with 65
// catalog_params pairs as InvalidArgument (gibson#1668).
func TestCallbackServer_StartRunsTheProtovalidateInterceptor(t *testing.T) {
	port := freeLoopbackPort(t)
	s := NewCallbackServerWithRegistry(slog.Default(), port, NewCallbackHarnessRegistry(), testEventBus())
	s.service.forkLedger = newForkLedger(t)
	s.service.componentRegistry = struct{ component.ComponentRegistry }{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := harnesspb.NewHarnessCallbackServiceClient(conn)

	req := &harnesspb.CreateMissionRequest{CatalogMission: "recon", CatalogParams: pairsOf(65)}
	callCtx, callCancel := context.WithTimeout(agentCallCtx(), 10*time.Second)
	defer callCancel()
	type result struct{ err error }
	called := make(chan result, 1)
	go func() {
		_, err := client.CreateMission(callCtx, req, grpc.WaitForReady(true))
		called <- result{err}
	}()
	select {
	case startErr := <-done:
		t.Fatalf("Start returned before the call finished: %v", startErr)
	case r := <-called:
		if status.Code(r.err) != codes.InvalidArgument {
			t.Fatalf("code = %v (%v), want InvalidArgument", status.Code(r.err), r.err)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after the context ended")
	}
}
