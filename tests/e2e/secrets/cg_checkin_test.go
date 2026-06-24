//go:build e2e
// +build e2e

// Package e2e — cg_checkin_test.go
//
// Shared capability-grant check-in helper for the secrets E2E suite.
//
// WHY THIS EXISTS
// ---------------
// The secrets tests used to authenticate a component (agent / tool / plugin)
// by minting a per-agent Zitadel service account at CreateAgentIdentity time
// (client_id / client_secret) and exchanging it for an OIDC Bearer token via
// the client_credentials grant. That shortcut was removed in gibson#670: an
// agent no longer gets a Zitadel OAuth app. A component's identity is now a
// capability-grant JWT (CG-JWT) it self-signs after a one-time check-in
// (ADR-0045 / ADR-0046). This helper performs that real check-in — the same
// flow a production component runs, and the same SDK client (no mission
// required):
//
//  1. CreateAgentIdentity (admin) mints a single-use bootstrap token.
//  2. capabilitygrant.NewClient generates fresh host + agent Ed25519 keypairs.
//  3. Discover reads the daemon's /.well-known/agent-configuration document.
//  4. Register (Authorization: Bearer <bootstrap>) registers the public keys
//     via POST /capabilitygrant/v1/register; the daemon upserts the host,
//     creates the agent, and resolves the component's FGA capabilities.
//  5. The returned gRPC conn carries per-RPC credentials that sign a fresh
//     CG-JWT into the x-capability-grant header on every call — exactly how
//     ext-authz expects a component to authenticate.
//
// Spec: non-plugin-secret-isolation; gibson#972 (test migration off the
// removed client_credentials path).
package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// cgPlatformURL returns the base URL of the daemon's pre-auth listener, which
// serves the capability-grant discovery (/.well-known/agent-configuration) and
// host-registration (/capabilitygrant/v1/register) endpoints. The kind e2e
// harness must point GIBSON_PLATFORM_URL at the NodePort exposing the daemon's
// pre-auth listener (default container port 8085). The default below is a
// best-effort local value.
func cgPlatformURL() string {
	if u := os.Getenv("GIBSON_PLATFORM_URL"); u != "" {
		return u
	}
	return "http://localhost:8085"
}

// enrolledComponent is a checked-in agent / tool / plugin. CG holds the SDK
// capability-grant client (its host + agent keypairs are registered with the
// daemon); Conn is a gRPC connection whose per-RPC credentials sign and inject
// the component's CG-JWT (x-capability-grant) on every call. This is the real
// component-authentication path — no mission, no Zitadel Bearer.
type enrolledComponent struct {
	CG   *capabilitygrant.Client
	Conn *grpc.ClientConn
}

// enrollComponent performs the full component check-in for a principal that was
// just created via CreateAgentIdentity, using its single-use bootstrap token.
// It returns a gRPC conn that authenticates every call with the component's
// self-signed per-RPC CG-JWT. The conn is closed automatically via t.Cleanup.
//
// Replaces the removed exchangeClientCredentials shortcut (gibson#670 / #972).
func enrollComponent(ctx context.Context, t *testing.T, bootstrapToken, agentName string) *enrolledComponent {
	t.Helper()

	cg, err := capabilitygrant.NewClient(capabilitygrant.ClientConfig{
		PlatformURL:    cgPlatformURL(),
		BootstrapToken: bootstrapToken,
		AgentName:      agentName,
		// Per-test host key so concurrent enrollments never share on-disk state.
		HostKeyPath: filepath.Join(t.TempDir(), "host_key.json"),
	})
	require.NoError(t, err, "capabilitygrant.NewClient(%s)", agentName)

	require.NoError(t, cg.Discover(ctx), "capabilitygrant Discover(%s)", agentName)
	require.NoError(t, cg.Register(ctx), "capabilitygrant Register(%s)", agentName)

	conn, err := grpc.NewClient(daemonGRPCAddr(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(cg.GRPCPerRPCCredentials()),
	)
	require.NoError(t, err, "dial CG-authenticated conn(%s)", agentName)
	t.Cleanup(func() { _ = conn.Close() })

	return &enrolledComponent{CG: cg, Conn: conn}
}

// cgCtx returns a context carrying only the tenant header. The component's
// CG-JWT is injected automatically by the conn's per-RPC credentials, so —
// unlike the old Bearer flow — no authorization header is set here.
func cgCtx(ctx context.Context, tenantID string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-tenant-id", tenantID)
}
