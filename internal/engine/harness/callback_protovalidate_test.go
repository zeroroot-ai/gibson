// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
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
	s, _ := claimService(t)
	grantUnary, _ := taskGrantScopeInterceptors(getter(&fakeGrantVerifier{}),
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

func catalogParams(n int) map[string]string {
	m := make(map[string]string, n)
	for i := 0; i < n; i++ {
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
		{"64 pairs pass", catalogParams(64), codes.OK, 1},
		{"65 pairs are refused", catalogParams(65), codes.InvalidArgument, 0},
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
