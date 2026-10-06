// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e

// Package e2e is the secrets isolation suite (spec non-plugin-secret-isolation).
//
// In plain words: an agent or a tool can never read a tenant secret, and a
// forged capability grant reads nothing. Only a plugin that a tenant admin
// bound to a secret reads it.
//
// THE VENUE (gibson#213). The suite runs in-cluster as the exit-test runner
// Job of exit-test-e2e-cluster.yml, with the runner's SVID:
//
//   - Admin calls (create and revoke a principal, set and delete a secret) go
//     to the daemon's mTLS listener with the SVID. The test-mode daemon takes
//     the tenant from x-gibson-identity-tenant for that SVID only
//     (internal/server/daemon/e2e_peer_policy.go), and the method policy
//     there lists each admin RPC this suite calls.
//   - Component calls go through the Envoy edge, the path a shipped
//     component takes (charts: helm/gibson-workloads/templates/plugins). The
//     component checks in at the public api origin with its bootstrap token,
//     and each call carries its self-signed capability grant. ext-authz
//     verifies the grant and makes the can_resolve decision. The daemon's
//     mTLS listener does not accept a capability grant, so the edge is the
//     only place where this decision can be proven.
//
// The positive arm (a bound plugin reads its secret) is
// tests/e2e/plugin_secret_revocation_test.go on exit-test-tool-dispatch.yml:
// the real plugin image enrols, binds its declared secret and resolves it.
//
// Environment, set by the workflow:
//
//	GIBSON_TEST_FIXTURES_ENABLED=true
//	GIBSON_TEST_TENANT_ID   the tenant of the runner (GIBSON_PLATFORM_TENANT)
//	GIBSON_URL              the public api origin (gibson-domains apiOrigin)
//	GIBSON_EDGE_ADDR        the in-cluster Envoy address, host:port
//	GIBSON_EDGE_CA_PEM_B64  the CA of the edge certificate, base64 PEM
//	DAEMON_GRPC_ADDR        the daemon's mTLS listener
package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentidentityv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/capabilitygrant"

	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
)

// denyWait bounds the wait for a new principal to be known at the edge. A
// component that registered a moment ago can get Unauthenticated until
// ext-authz has its key. The verdict is the first answer that is not that.
const (
	denyWait = 60 * time.Second
	denyPoll = 2 * time.Second
)

// venue holds the two connections of the suite: the admin connection with the
// runner's SVID, and the edge that the components dial.
type venue struct {
	tenant     string
	adminCtx   context.Context
	identities agentidentityv1.AgentIdentityServiceClient
	secrets    secretsv1.SecretsServiceClient
	edge       edge
}

// requireVenue reads the environment of the venue and dials the daemon. A
// missing value fails the test: the workflow sets each one, so a missing
// value is a broken venue, not a reason to skip.
func requireVenue(ctx context.Context, t *testing.T) *venue {
	t.Helper()
	if os.Getenv("GIBSON_TEST_FIXTURES_ENABLED") != "true" {
		t.Skip("set GIBSON_TEST_FIXTURES_ENABLED=true to run the secrets suite in its venue")
	}
	tenant := requireEnv(t, "GIBSON_TEST_TENANT_ID")

	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial the daemon at DAEMON_GRPC_ADDR with the runner SVID")
	t.Cleanup(func() { _ = clients.Close() })

	return &venue{
		tenant:     tenant,
		adminCtx:   auth.ContextWithTenantString(ctx, tenant),
		identities: agentidentityv1.NewAgentIdentityServiceClient(clients.Conn()),
		secrets:    secretsv1.NewSecretsServiceClient(clients.Conn()),
		edge:       requireEdge(t),
	}
}

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: the venue of the secrets suite sets it (exit-test-e2e-cluster.yml)", name)
	}
	return v
}

// edge is the Envoy edge as a component sees it. The component names the
// public api origin, and every connection goes to the in-cluster Envoy
// address with that host in SNI and :authority. No pod needs the public name
// in DNS.
type edge struct {
	origin *url.URL
	addr   string
	tls    *tls.Config
}

func requireEdge(t *testing.T) edge {
	t.Helper()
	origin, err := url.Parse(requireEnv(t, "GIBSON_URL"))
	require.NoError(t, err, "parse GIBSON_URL")
	require.Equal(t, "https", origin.Scheme, "GIBSON_URL must be the https api origin")

	pemBytes, err := base64.StdEncoding.DecodeString(requireEnv(t, "GIBSON_EDGE_CA_PEM_B64"))
	require.NoError(t, err, "decode GIBSON_EDGE_CA_PEM_B64")
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pemBytes), "GIBSON_EDGE_CA_PEM_B64 holds no PEM certificate")

	return edge{
		origin: origin,
		addr:   requireEnv(t, "GIBSON_EDGE_ADDR"),
		tls:    &tls.Config{RootCAs: pool, ServerName: origin.Hostname(), MinVersion: tls.VersionTLS12},
	}
}

// httpClient sends each request for the api origin to the Envoy address.
func (e edge) httpClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: e.tls.Clone(),
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, e.addr)
			},
		},
	}
}

// dial opens a gRPC connection to the edge. extra carries the per-RPC
// credentials of the caller, or nothing.
func (e edge) dial(t *testing.T, extra ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(e.tls.Clone())),
		grpc.WithAuthority(e.origin.Host),
	}, extra...)
	conn, err := grpc.NewClient(e.addr, opts...)
	require.NoError(t, err, "dial the edge at %s", e.addr)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// component is a principal that checked in at the edge. Its connection signs
// a fresh capability grant into x-capability-grant on each call.
type component struct {
	principalID string
	credentials componentpb.ComponentServiceClient
}

// provision creates a principal of the given kind, checks it in at the edge
// with its bootstrap token, and revokes it when the test ends.
func (v *venue) provision(ctx context.Context, t *testing.T, kind agentidentityv1.PrincipalKind, name string) *component {
	t.Helper()
	resp, err := v.identities.CreateAgentIdentity(v.adminCtx, &agentidentityv1.CreateAgentIdentityRequest{
		Name:        name,
		Kind:        kind,
		Description: "ephemeral principal of the secrets isolation suite",
	})
	require.NoError(t, err, "CreateAgentIdentity(%s, %s)", name, kind)
	principalID := resp.GetPrincipalId()
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := v.identities.RevokeAgentIdentity(auth.ContextWithTenantString(c, v.tenant),
			&agentidentityv1.RevokeAgentIdentityRequest{PrincipalId: principalID}); err != nil {
			t.Logf("cleanup: RevokeAgentIdentity(%s): %v", principalID, err)
		}
	})

	cg, err := capabilitygrant.NewClient(capabilitygrant.ClientConfig{
		PlatformURL:    v.edge.origin.String(),
		BootstrapToken: resp.GetBootstrapToken(),
		AgentName:      name,
		HostKeyPath:    filepath.Join(t.TempDir(), "host_key.json"),
	})
	require.NoError(t, err, "capabilitygrant.NewClient(%s)", name)
	cg.SetHTTPClient(v.edge.httpClient())
	require.NoError(t, cg.Discover(ctx), "capability-grant discovery for %s at %s", name, v.edge.origin)
	require.NoError(t, cg.Register(ctx), "capability-grant registration of %s", name)

	conn := v.edge.dial(t, grpc.WithPerRPCCredentials(cg.GRPCPerRPCCredentials()))
	return &component{principalID: principalID, credentials: componentpb.NewComponentServiceClient(conn)}
}

// seedSecret stores a credential for the tenant and deletes it when the test
// ends. It returns the stored name that GetCredential takes.
func (v *venue) seedSecret(t *testing.T, name string) string {
	t.Helper()
	_, err := v.secrets.SetSecret(v.adminCtx, &secretsv1.SetSecretRequest{
		Name:     name,
		Category: secretsv1.SecretCategory_SECRET_CATEGORY_CRED,
		Value:    []byte("secrets-suite-payload-" + name),
	})
	require.NoError(t, err, "SetSecret(%s)", name)
	stored := "cred:" + name
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := v.secrets.DeleteSecret(auth.ContextWithTenantString(c, v.tenant),
			&secretsv1.DeleteSecretRequest{Name: stored}); err != nil {
			t.Logf("cleanup: DeleteSecret(%s): %v", stored, err)
		}
	})
	return stored
}

// runID makes the names of one run unique.
func runID() string { return fmt.Sprintf("%d", time.Now().UnixNano()) }

// requirePermissionDenied calls call until the answer is not Unauthenticated
// or Unavailable, then requires PermissionDenied. Unauthenticated is the
// answer while ext-authz does not yet know a new component. A success or a
// NotFound means the call reached the secret, which is the failure this suite
// exists to catch.
func requirePermissionDenied(t *testing.T, what string, call func() error) {
	t.Helper()
	deadline := time.Now().Add(denyWait)
	var err error
	for {
		err = call()
		code := status.Code(err)
		if (code != codes.Unauthenticated && code != codes.Unavailable) || time.Now().After(deadline) {
			break
		}
		time.Sleep(denyPoll)
	}
	require.Error(t, err, "%s returned the secret; it must be denied", what)
	st, _ := status.FromError(err)
	require.Equal(t, codes.PermissionDenied, st.Code(),
		"%s: want PermissionDenied from the can_resolve decision, got %s: %s", what, st.Code(), st.Message())
}
