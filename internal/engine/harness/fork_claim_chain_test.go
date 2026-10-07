// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/fork"
)

// claimChainClient serves s behind the interceptor chain of the callback
// listener (identityUnaryChain, which CallbackServer.Start also uses) and returns a
// client of it.
func claimChainClient(t *testing.T, s *HarnessCallbackService) harnesspb.HarnessCallbackServiceClient {
	t.Helper()
	grantUnary, _ := taskGrantScopeInterceptors(getter(&fakeGrantVerifier{}),
		&forkGuard{ledger: s.forkLedger, identity: s.sandboxIdentity}, slog.Default())
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(s.identityUnaryChain(grantUnary)...))
	harnesspb.RegisterHarnessCallbackServiceServer(srv, s)
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
	return harnesspb.NewHarnessCallbackServiceClient(conn)
}

// edgeClaimCtx is the outgoing metadata of a ClaimFork call as the edge
// forwards it: the identity headers from headers.SandboxClaimIdentity and the
// identity token of the sandbox.
func edgeClaimCtx(token string) context.Context {
	md := metadata.MD{}
	for k, v := range headers.Emit(headers.SandboxClaimIdentity(time.Now().UTC())) {
		md.Set(k, v...)
	}
	md.Set(fork.MetadataSandboxIdentity, token)
	return metadata.NewOutgoingContext(context.Background(), md)
}

// A ClaimFork through the real interceptor chain, with the headers that the
// edge emits, succeeds for the sandbox that the daemon started and fails for
// another sandbox (gibson#1016).
func TestClaimFork_ThroughTheInterceptorChain(t *testing.T) {
	s, l := claimService(t)
	recordFork(t, l, "ns/fork-1/u1", "n2")
	client := claimChainClient(t, s)

	// A token of another sandbox is refused and does not use the claim.
	_, err := client.ClaimFork(edgeClaimCtx("tok-fork-2"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other sandbox: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}
	// A sandbox the daemon did not start is refused.
	_, err = client.ClaimFork(edgeClaimCtx("tok-fork-9"), &harnesspb.ClaimForkRequest{SandboxId: "fork-9"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown sandbox: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}
	resp, err := client.ClaimFork(edgeClaimCtx("tok-fork-1"), &harnesspb.ClaimForkRequest{SandboxId: "fork-1"})
	if err != nil {
		t.Fatalf("the right sandbox must claim: %v", err)
	}
	if resp.GetNodeId() != "n2" || resp.GetGrant() == "" {
		t.Fatalf("response = %v", resp)
	}
}

// The edge sends no tenant, so a tenant header that the caller adds does not
// survive: the tenant comes from the start record.
func TestClaimFork_TenantComesFromTheStartRecord(t *testing.T) {
	var seen string
	s, l := claimService(t)
	recordFork(t, l, "ns/fork-1/u1", "n2")
	probe := s.claimForkTenantInterceptor()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		auth.HeaderCredentialType, credentialSandboxIdentity, auth.HeaderTenant, "evil"))
	_, err := probe(ctx, &harnesspb.ClaimForkRequest{SandboxId: "fork-1"},
		&grpc.UnaryServerInfo{FullMethod: claimForkMethod},
		func(ctx context.Context, _ any) (any, error) {
			seen = firstMetadata(ctx, auth.HeaderTenant)
			return nil, nil
		})
	if err != nil || seen != "acme" {
		t.Fatalf("tenant = %q, err = %v; want acme", seen, err)
	}
}
