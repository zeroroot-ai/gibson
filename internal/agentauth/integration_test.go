//go:build integration
// +build integration

// Package agentauth — integration_test.go
//
// End-to-end integration tests for the Agent Auth Protocol using real
// infrastructure containers. These tests exercise the full lifecycle:
//
//   - Bootstrap registration via single-use API key
//   - FGA capability resolution at registration time
//   - Capability listing and execution checks
//   - FGA grant revocation causing execution denial
//   - Agent revocation cascading to grants and audit log
//   - Audit log persistence and queryability
//
// Infrastructure:
//   - Postgres 15 (testcontainers): stores api_keys, agent_auth_*, audit_log
//   - OpenFGA (testcontainers): evaluates and stores authorization tuples
//   - miniredis: not required for this package (no Redis dependency)
//
// Run with:
//
//	go test -tags integration -v -timeout 5m ./internal/agentauth/...
package agentauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	fgasdk "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zero-day-ai/gibson/internal/agentauth"
	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/provisioner"
)

// ---------------------------------------------------------------------------
// Container setup helpers
// ---------------------------------------------------------------------------

// setupIntegrationPostgres starts a Postgres 15 container, runs all migrations,
// and returns a ready *sql.DB plus a cleanup function.
func setupIntegrationPostgres(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	ctx := context.Background()

	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping agentauth integration test: %v", err)
		return nil, func() {}
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker not running, skipping agentauth integration test: %v", healthErr)
		return nil, func() {}
	}

	const (
		pgUser     = "testuser"
		pgPassword = "testpassword"
		pgDB       = "testdb"
	)

	req := testcontainers.ContainerRequest{
		Image: "postgres:15-alpine",
		Env: map[string]string{
			"POSTGRES_USER":     pgUser,
			"POSTGRES_PASSWORD": pgPassword,
			"POSTGRES_DB":       pgDB,
		},
		ExposedPorts: []string{"5432/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForLog("database system is ready to accept connections"),
			wait.ForListeningPort("5432/tcp"),
		),
	}

	pgC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start Postgres container")

	cleanup := func() {
		if termErr := pgC.Terminate(context.Background()); termErr != nil {
			t.Logf("warning: failed to terminate Postgres container: %v", termErr)
		}
	}

	host, err := pgC.Host(ctx)
	require.NoError(t, err)

	mappedPort, err := pgC.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, mappedPort.Port(), pgUser, pgPassword, pgDB)

	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err, "failed to open Postgres connection")
	t.Cleanup(func() { _ = db.Close() })

	require.Eventually(t, func() bool {
		return db.PingContext(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres did not become ready in time")

	// Run all migrations: api_keys, agent_auth_*, audit_log.
	require.NoError(t, provisioner.RunMigrations(ctx, db), "RunMigrations must succeed")

	return db, cleanup
}

// setupIntegrationFGA starts an OpenFGA container with an in-memory store,
// creates the Gibson authorization model, and returns the Authorizer plus a
// cleanup function.
func setupIntegrationFGA(t *testing.T, ctx context.Context) (authz.Authorizer, func()) {
	t.Helper()

	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping agentauth integration test: %v", err)
		return nil, func() {}
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker not running, skipping agentauth integration test: %v", healthErr)
		return nil, func() {}
	}

	req := testcontainers.ContainerRequest{
		Image:        "openfga/openfga:latest",
		Cmd:          []string{"run", "--datastore-engine", "memory"},
		ExposedPorts: []string{"8080/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("8080/tcp"),
			wait.ForLog("starting openfga service"),
		).WithDeadline(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start OpenFGA container")

	cleanup := func() {
		if termErr := container.Terminate(context.Background()); termErr != nil {
			t.Logf("warning: failed to terminate FGA container: %v", termErr)
		}
	}

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "8080")
	require.NoError(t, err)

	baseURL := fmt.Sprintf("http://%s:%s", host, port.Port())

	storeID, modelID := setupIntegrationFGAStore(t, ctx, baseURL)

	a, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:  baseURL,
		StoreID:   storeID,
		ModelID:   modelID,
		TimeoutMs: 5000,
		Logger:    slog.Default(),
	})
	require.NoError(t, err, "failed to construct FGA authorizer")

	return a, cleanup
}

// setupIntegrationFGAStore creates a new FGA store and writes the Gibson
// authorization model. Returns storeID and modelID.
func setupIntegrationFGAStore(t *testing.T, ctx context.Context, baseURL string) (string, string) {
	t.Helper()

	mgmtClient, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl: baseURL,
	})
	require.NoError(t, err, "failed to create FGA management client")

	createResp, err := mgmtClient.CreateStore(ctx).Body(struct {
		Name string `json:"name"`
	}{Name: "agentauth-integration-test"}).Execute()
	require.NoError(t, err, "failed to create FGA store")

	storeID := createResp.GetId()
	require.NotEmpty(t, storeID)

	modelID := writeIntegrationFGAModel(t, ctx, baseURL, storeID)
	return storeID, modelID
}

// writeIntegrationFGAModel writes the Gibson authorization model to the FGA
// store identified by storeID and returns the resulting model ID.
//
// The model mirrors core/gibson/internal/authz/model.fga exactly:
// types: user, tenant (admin/member), component (owner/can_execute/can_configure/can_read), system_tenant.
func writeIntegrationFGAModel(t *testing.T, ctx context.Context, baseURL, storeID string) string {
	t.Helper()

	c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:  baseURL,
		StoreId: storeID,
	})
	require.NoError(t, err)

	userType := "user"
	tenantType := "tenant"
	componentType := "component"
	systemTenantType := "system_tenant"

	adminStr := "admin"
	ownerStr := "owner"

	// user type — no relations
	userTypeDef := fgasdk.TypeDefinition{
		Type:      userType,
		Relations: &map[string]fgasdk.Userset{},
	}

	// tenant type — admin: [user], member: [user] ∪ computed(admin)
	tenantTypeDef := fgasdk.TypeDefinition{
		Type: tenantType,
		Relations: &map[string]fgasdk.Userset{
			"admin": {This: &map[string]interface{}{}},
			"member": {
				Union: &fgasdk.Usersets{
					Child: []fgasdk.Userset{
						{This: &map[string]interface{}{}},
						{ComputedUserset: &fgasdk.ObjectRelation{Relation: &adminStr}},
					},
				},
			},
		},
		Metadata: &fgasdk.Metadata{
			Relations: &map[string]fgasdk.RelationMetadata{
				"admin": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userType},
					},
				},
				"member": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userType},
					},
				},
			},
		},
	}

	// component type — owner: [tenant], can_execute/can_configure/can_read via
	// direct user grant OR via owner→admin tupleset traversal.
	accessUserset := fgasdk.Userset{
		Union: &fgasdk.Usersets{
			Child: []fgasdk.Userset{
				{This: &map[string]interface{}{}},
				{TupleToUserset: &fgasdk.TupleToUserset{
					Tupleset:        fgasdk.ObjectRelation{Relation: &ownerStr},
					ComputedUserset: fgasdk.ObjectRelation{Relation: &adminStr},
				}},
			},
		},
	}

	componentTypeDef := fgasdk.TypeDefinition{
		Type: componentType,
		Relations: &map[string]fgasdk.Userset{
			"owner":         {This: &map[string]interface{}{}},
			"can_execute":   accessUserset,
			"can_configure": accessUserset,
			"can_read":      accessUserset,
		},
		Metadata: &fgasdk.Metadata{
			Relations: &map[string]fgasdk.RelationMetadata{
				"owner": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: tenantType},
					},
				},
				"can_execute": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userType},
						{Type: tenantType, Relation: fgasdk.PtrString("member")},
					},
				},
				"can_configure": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userType},
						{Type: tenantType, Relation: fgasdk.PtrString("member")},
					},
				},
				"can_read": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userType},
						{Type: tenantType, Relation: fgasdk.PtrString("member")},
					},
				},
			},
		},
	}

	// system_tenant type — platform_operator: [user]
	systemTenantTypeDef := fgasdk.TypeDefinition{
		Type: systemTenantType,
		Relations: &map[string]fgasdk.Userset{
			"platform_operator": {This: &map[string]interface{}{}},
		},
		Metadata: &fgasdk.Metadata{
			Relations: &map[string]fgasdk.RelationMetadata{
				"platform_operator": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userType},
					},
				},
			},
		},
	}

	writeResp, err := c.WriteAuthorizationModel(ctx).Body(fgasdk.WriteAuthorizationModelRequest{
		SchemaVersion: "1.1",
		TypeDefinitions: []fgasdk.TypeDefinition{
			userTypeDef,
			tenantTypeDef,
			componentTypeDef,
			systemTenantTypeDef,
		},
	}).Execute()
	require.NoError(t, err, "failed to write FGA authorization model")

	modelID := writeResp.GetAuthorizationModelId()
	require.NotEmpty(t, modelID)
	return modelID
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// noopRegistryForIntegration is a minimal ComponentRegistry that returns
// pre-configured components. Used for FGA bridge construction in integration
// tests where a real Redis-backed registry is not needed.
type noopRegistryForIntegration struct {
	components []component.ComponentInfo
}

func (r *noopRegistryForIntegration) Register(_ context.Context, _, _, _ string, _ component.ComponentInfo) (string, error) {
	return "inst-1", nil
}
func (r *noopRegistryForIntegration) Deregister(_ context.Context, _, _, _, _ string) error {
	return nil
}
func (r *noopRegistryForIntegration) RefreshTTL(_ context.Context, _, _, _, _ string) error {
	return nil
}
func (r *noopRegistryForIntegration) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return r.components, nil
}
func (r *noopRegistryForIntegration) DiscoverAll(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return r.components, nil
}
func (r *noopRegistryForIntegration) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return r.components, nil
}
func (r *noopRegistryForIntegration) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return r.components, nil
}
func (r *noopRegistryForIntegration) DiscoverSystemOnly(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return r.components, nil
}

var _ component.ComponentRegistry = (*noopRegistryForIntegration)(nil)

// generateECDSAJWK generates an ECDSA P-256 key pair and returns the public
// key serialised as a minimal JWK JSON object suitable for use as
// hostPublicKeyJWK or agentPublicKeyJWK in RegisterAgentAuth.
func generateECDSAJWK(t *testing.T) json.RawMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed to generate ECDSA key pair")

	// Encode the public key as a minimal JWK (kty=EC, crv=P-256, x, y).
	x := key.PublicKey.X.Bytes()
	y := key.PublicKey.Y.Bytes()

	// Pad to 32 bytes (P-256 field size).
	pad := func(b []byte) []byte {
		if len(b) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(b):], b)
			return padded
		}
		return b
	}

	jwkMap := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   fmt.Sprintf("%x", pad(x)),
		"y":   fmt.Sprintf("%x", pad(y)),
	}
	raw, err := json.Marshal(jwkMap)
	require.NoError(t, err, "failed to marshal JWK")
	return raw
}

// newIntegrationService assembles a fully-wired AgentAuthService from the
// provided infrastructure handles. The audit.Writer is started and registered
// for cleanup via t.Cleanup.
func newIntegrationService(
	t *testing.T,
	db *sql.DB,
	fgaAuthorizer authz.Authorizer,
	registryComponents []component.ComponentInfo,
) *agentauth.AgentAuthService {
	t.Helper()

	apiKeys, err := auth.NewAPIKeyAuthenticator(db)
	require.NoError(t, err, "failed to construct APIKeyAuthenticator")

	store := agentauth.NewAgentAuthStore(db)

	registry := &noopRegistryForIntegration{components: registryComponents}
	bridge := agentauth.NewFGABridge(fgaAuthorizer, registry, slog.Default())

	auditWriter := audit.NewWriter(db, slog.Default())
	ctx := context.Background()
	auditWriter.Start(ctx)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		auditWriter.Stop(stopCtx)
	})

	auditQuery := audit.NewQuery(db)

	return agentauth.NewAgentAuthService(agentauth.AgentAuthServiceConfig{
		Store:       store,
		FGABridge:   bridge,
		Authorizer:  fgaAuthorizer,
		APIKeys:     apiKeys,
		AuditWriter: auditWriter,
		AuditQuery:  auditQuery,
		Logger:      slog.Default(),
	})
}

// waitForAuditEvents polls the audit_log table until at least wantCount rows
// matching the given filters are present, or the deadline is reached.
func waitForAuditEvents(
	t *testing.T,
	db *sql.DB,
	tenantID string,
	filters audit.Filters,
	wantCount int,
) []audit.PgEntry {
	t.Helper()
	q := audit.NewQuery(db)
	ctx := context.Background()

	var entries []audit.PgEntry
	require.Eventually(t, func() bool {
		var err error
		entries, _, err = q.List(ctx, tenantID, filters, 100, 0)
		if err != nil {
			t.Logf("waitForAuditEvents: query error: %v", err)
			return false
		}
		return len(entries) >= wantCount
	}, 5*time.Second, 100*time.Millisecond,
		"timed out waiting for %d audit events (have %d) — action=%q",
		wantCount, len(entries), filters.Action,
	)
	return entries
}

// ---------------------------------------------------------------------------
// TestAgentAuthFullLifecycle
// ---------------------------------------------------------------------------

// TestAgentAuthFullLifecycle exercises the complete Agent Auth Protocol flow:
//
//  1. Bootstrap with a single-use API key
//  2. Agent registration with FGA capability resolution
//  3. Bootstrap key is consumed after first use
//  4. Second registration attempt with same key is rejected
//  5. ListAgentCapabilities returns the same grants as at registration
//  6. ExecuteAgentCapability succeeds for an allowed component
//  7. FGA grant revocation causes subsequent execution to be denied
//  8. Agent revocation marks agent and grants as revoked
//  9. Audit log contains expected event sequence
func TestAgentAuthFullLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Start infrastructure.
	db, pgCleanup := setupIntegrationPostgres(t)
	defer pgCleanup()

	fgaAuthorizer, fgaCleanup := setupIntegrationFGA(t, ctx)
	defer fgaCleanup()
	defer fgaAuthorizer.Close()

	const (
		tenantID    = "testorg"
		ownerUserID = "testuser"
	)

	// Step 1: Write FGA tuples.
	// - testuser is admin of tenant:testorg
	// - tenant:testorg owns component:nmap and component:httpx
	require.NoError(t, fgaAuthorizer.Write(ctx, []authz.Tuple{
		{User: "user:" + ownerUserID, Relation: "admin", Object: "tenant:" + tenantID},
		{User: "tenant:" + tenantID, Relation: "owner", Object: "component:nmap"},
		{User: "tenant:" + tenantID, Relation: "owner", Object: "component:httpx"},
	}), "failed to seed FGA tuples")

	// Step 2: Create a single-use (max_uses=1) bootstrap API key.
	apiKeys, err := auth.NewAPIKeyAuthenticator(db)
	require.NoError(t, err)

	rawBootstrapKey, bootstrapRecord, err := apiKeys.CreateKey(
		ctx,
		tenantID,
		[]string{"host"},
		[]string{},
		[]string{"register:host"},
		"host-bootstrap",
		"test-setup",
	)
	require.NoError(t, err, "failed to create bootstrap API key")
	require.NotEmpty(t, rawBootstrapKey)
	require.NotEmpty(t, bootstrapRecord.KeyID)

	// Insert with max_uses=1 so the bootstrap key is single-use.
	// The CreateKey path does not accept max_uses as a parameter — we update it directly.
	_, err = db.ExecContext(ctx,
		`UPDATE api_keys SET max_uses = 1 WHERE key_id = $1`,
		bootstrapRecord.KeyID,
	)
	require.NoError(t, err, "failed to set max_uses=1 on bootstrap key")

	// Step 3: Construct the service wired against both infrastructure pieces.
	// Registry knows about nmap and httpx so FGABridge can enrich capabilities.
	registryComponents := []component.ComponentInfo{
		{Name: "nmap", Kind: "tool", TenantID: "_system", Metadata: map[string]string{"description": "Network scanner"}},
		{Name: "httpx", Kind: "tool", TenantID: "_system", Metadata: map[string]string{"description": "HTTP prober"}},
	}
	svc := newIntegrationService(t, db, fgaAuthorizer, registryComponents)

	hostJWK := generateECDSAJWK(t)
	agentJWK := generateECDSAJWK(t)

	// Step 4: Register the agent using the bootstrap key.
	result, err := svc.RegisterAgentAuth(
		ctx,
		tenantID,
		ownerUserID,
		"test-agent",
		"delegated",
		hostJWK,
		agentJWK,
		"api_key",
		rawBootstrapKey,
	)
	require.NoError(t, err, "RegisterAgentAuth must succeed with valid bootstrap key")
	require.NotNil(t, result)

	agentID := result.AgentID
	hostID := result.HostID
	require.NotEmpty(t, agentID, "agent ID must be set")
	require.NotEmpty(t, hostID, "host ID must be set")
	assert.Equal(t, "active", result.Status)

	// Capabilities: testuser is admin→member of testorg which owns nmap and httpx.
	// FGA grants can_execute (and potentially can_configure, can_read) on both.
	// At minimum we expect execute:tool:nmap and execute:tool:httpx.
	capsByName := make(map[string]agentauth.Capability, len(result.Capabilities))
	for _, c := range result.Capabilities {
		capsByName[c.Name] = c
	}
	assert.Contains(t, capsByName, "execute:tool:nmap",
		"registration result must include execute:tool:nmap capability")
	assert.Contains(t, capsByName, "execute:tool:httpx",
		"registration result must include execute:tool:httpx capability")

	t.Logf("agent registered: id=%s host=%s capabilities=%d", agentID, hostID, len(result.Capabilities))

	// Step 5: Bootstrap key must be consumed (max_uses reached).
	_, authErr := apiKeys.Authenticate(ctx, rawBootstrapKey)
	require.Error(t, authErr, "consumed bootstrap key must not authenticate again")

	// Step 6: Second RegisterAgentAuth with the same bootstrap key must fail.
	secondJWK := generateECDSAJWK(t)
	_, secondErr := svc.RegisterAgentAuth(
		ctx,
		tenantID,
		ownerUserID,
		"second-agent",
		"delegated",
		secondJWK,
		generateECDSAJWK(t),
		"api_key",
		rawBootstrapKey,
	)
	require.Error(t, secondErr, "second registration with consumed key must fail")

	// Step 7: ListAgentCapabilities returns the same capability set.
	listedCaps, err := svc.ListAgentCapabilities(ctx, tenantID, ownerUserID)
	require.NoError(t, err)

	listedByName := make(map[string]agentauth.Capability, len(listedCaps))
	for _, c := range listedCaps {
		listedByName[c.Name] = c
	}
	assert.Contains(t, listedByName, "execute:tool:nmap",
		"ListAgentCapabilities must include execute:tool:nmap")
	assert.Contains(t, listedByName, "execute:tool:httpx",
		"ListAgentCapabilities must include execute:tool:httpx")

	// Step 8: ExecuteAgentCapability succeeds for nmap.
	execResult, err := svc.ExecuteAgentCapability(ctx, agentID, "execute:tool:nmap", nil, tenantID)
	require.NoError(t, err)
	require.NotNil(t, execResult)
	assert.Equal(t, "success", execResult.Status,
		"execute:tool:nmap must be allowed before grant revocation")

	// Step 9: Revoke the FGA can_execute grant for nmap from testuser.
	// This simulates an admin removing direct access while tenant ownership remains.
	// To deny execution we remove the user:testuser directly-related tuple that was
	// implied via admin→member ownership. We need to explicitly deny it — in the
	// current model the user gets access via tenant ownership, so we delete the
	// tenant owner tuple for nmap specifically.
	require.NoError(t, fgaAuthorizer.Delete(ctx, []authz.Tuple{
		{User: "tenant:" + tenantID, Relation: "owner", Object: "component:nmap"},
	}), "failed to remove tenant owner tuple for nmap")

	// FGA is eventually consistent; poll until the check returns denied.
	require.Eventually(t, func() bool {
		allowed, checkErr := fgaAuthorizer.Check(ctx,
			"user:"+ownerUserID, "can_execute", "component:nmap")
		return checkErr == nil && !allowed
	}, 10*time.Second, 200*time.Millisecond,
		"FGA must deny can_execute on nmap after owner tuple removed")

	// ExecuteAgentCapability for nmap must now be denied.
	deniedResult, err := svc.ExecuteAgentCapability(ctx, agentID, "execute:tool:nmap", nil, tenantID)
	require.NoError(t, err, "ExecuteAgentCapability must not return a hard error on denial")
	require.NotNil(t, deniedResult)
	assert.Equal(t, "error", deniedResult.Status,
		"execute:tool:nmap must be denied after FGA grant revocation")
	assert.Contains(t, deniedResult.ErrorMessage, "permission denied")

	// httpx still allowed (its owner tuple was not removed).
	httpxResult, err := svc.ExecuteAgentCapability(ctx, agentID, "execute:tool:httpx", nil, tenantID)
	require.NoError(t, err)
	require.NotNil(t, httpxResult)
	assert.Equal(t, "success", httpxResult.Status,
		"execute:tool:httpx must still be allowed")

	// Step 10: Revoke the agent.
	require.NoError(t, svc.RevokeAgentAuth(ctx, agentID, tenantID, ownerUserID))

	// Agent status must be revoked.
	store := agentauth.NewAgentAuthStore(db)
	agent, err := store.GetAgent(ctx, agentID)
	require.NoError(t, err)
	require.NotNil(t, agent)
	assert.Equal(t, "revoked", agent.Status,
		"agent status must be 'revoked' after RevokeAgentAuth")

	// Grants must all be revoked.
	grants, err := store.GetGrants(ctx, agentID)
	require.NoError(t, err)
	for _, g := range grants {
		assert.Equal(t, "revoked", g.Status,
			"grant %q must be revoked after agent revocation", g.CapabilityName)
	}

	// GetAgentAuthStatus still returns the record.
	statusResult, err := svc.GetAgentAuthStatus(ctx, agentID, tenantID)
	require.NoError(t, err)
	require.NotNil(t, statusResult)
	assert.Equal(t, "revoked", statusResult.Agent.Status)

	// Step 11: Verify audit log entries.
	// Wait for async flush (Writer flushes every second).
	// Expected actions in order: agent_registered, capability_executed (allow for nmap),
	// capability_executed (deny for nmap), capability_executed (allow for httpx), agent_revoked.

	registeredEvents := waitForAuditEvents(t, db, tenantID,
		audit.Filters{Action: "agent_registered", TargetID: agentID},
		1,
	)
	require.Len(t, registeredEvents, 1, "must have exactly one agent_registered event")
	assert.Equal(t, ownerUserID, registeredEvents[0].ActorID)
	assert.Equal(t, "user", registeredEvents[0].ActorType)
	assert.Equal(t, "agent", registeredEvents[0].TargetType)

	executedEvents := waitForAuditEvents(t, db, tenantID,
		audit.Filters{Action: "capability_executed"},
		3, // allow:nmap, deny:nmap, allow:httpx
	)
	require.GreaterOrEqual(t, len(executedEvents), 3,
		"must have at least 3 capability_executed events")

	// Find the allow and deny events by decision.
	decisions := make(map[string]int)
	for _, e := range executedEvents {
		decisions[e.Decision]++
	}
	assert.GreaterOrEqual(t, decisions["allow"], 2,
		"must have at least 2 allow decisions (nmap before revocation, httpx)")
	assert.GreaterOrEqual(t, decisions["deny"], 1,
		"must have at least 1 deny decision (nmap after FGA revocation)")

	revokedEvents := waitForAuditEvents(t, db, tenantID,
		audit.Filters{Action: "agent_revoked", TargetID: agentID},
		1,
	)
	require.Len(t, revokedEvents, 1, "must have exactly one agent_revoked event")
	assert.Equal(t, ownerUserID, revokedEvents[0].ActorID)
}

// ---------------------------------------------------------------------------
// TestHostRegistrationTokenLifecycle
// ---------------------------------------------------------------------------

// TestHostRegistrationTokenLifecycle verifies the single-use token flow:
//
//  1. CreateHostRegistrationToken issues a gsk_ token
//  2. Token can authenticate exactly once (max_uses=1)
//  3. Second authentication is rejected
//  4. RegisterAgentAuth rejects the consumed token
func TestHostRegistrationTokenLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db, pgCleanup := setupIntegrationPostgres(t)
	defer pgCleanup()

	fgaAuthorizer, fgaCleanup := setupIntegrationFGA(t, ctx)
	defer fgaCleanup()
	defer fgaAuthorizer.Close()

	const tenantID = "token-test-tenant"

	// Seed minimal FGA tuples so the service can function.
	require.NoError(t, fgaAuthorizer.Write(ctx, []authz.Tuple{
		{User: "user:token-owner", Relation: "admin", Object: "tenant:" + tenantID},
	}))

	svc := newIntegrationService(t, db, fgaAuthorizer, nil)

	// Step 1: Create a host registration token.
	tokenResult, err := svc.CreateHostRegistrationToken(ctx, tenantID, "ci-runner-token", "test-admin", 1)
	require.NoError(t, err, "CreateHostRegistrationToken must succeed")
	require.NotEmpty(t, tokenResult.RawToken, "raw token must be non-empty")
	require.NotEmpty(t, tokenResult.KeyID, "key ID must be non-empty")
	assert.True(t, tokenResult.ExpiresAt.After(time.Now()),
		"expiry must be in the future")

	apiKeys, err := auth.NewAPIKeyAuthenticator(db)
	require.NoError(t, err)

	// Step 2: Set max_uses=1 on the token (CreateHostRegistrationToken creates the
	// key but delegates max_uses enforcement to the API key layer; we set it here
	// to enforce single-use behaviour in the test).
	_, err = db.ExecContext(ctx,
		`UPDATE api_keys SET max_uses = 1 WHERE key_id = $1`,
		tokenResult.KeyID,
	)
	require.NoError(t, err, "failed to set max_uses=1 on registration token")

	// Step 3: First authentication must succeed.
	identity, err := apiKeys.Authenticate(ctx, tokenResult.RawToken)
	require.NoError(t, err, "first authentication with registration token must succeed")
	require.NotNil(t, identity)

	// Step 4: Token must now be consumed; second authentication must fail.
	_, secondErr := apiKeys.Authenticate(ctx, tokenResult.RawToken)
	require.Error(t, secondErr, "second authentication with consumed token must fail")

	// Step 5: RegisterAgentAuth with the consumed token must be rejected.
	_, regErr := svc.RegisterAgentAuth(
		ctx,
		tenantID,
		"token-owner",
		"token-test-agent",
		"delegated",
		generateECDSAJWK(t),
		generateECDSAJWK(t),
		"api_key",
		tokenResult.RawToken,
	)
	require.Error(t, regErr,
		"RegisterAgentAuth must reject a consumed registration token")
}

// ---------------------------------------------------------------------------
// TestAgentListAndPagination
// ---------------------------------------------------------------------------

// TestAgentListAndPagination verifies that ListAgentAuthAgents returns the
// correct set of agents for a tenant, in the correct order, with accurate
// total counts.
func TestAgentListAndPagination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db, pgCleanup := setupIntegrationPostgres(t)
	defer pgCleanup()

	fgaAuthorizer, fgaCleanup := setupIntegrationFGA(t, ctx)
	defer fgaCleanup()
	defer fgaAuthorizer.Close()

	const (
		tenantID = "list-test-tenant"
		userID   = "list-test-user"
	)

	require.NoError(t, fgaAuthorizer.Write(ctx, []authz.Tuple{
		{User: "user:" + userID, Relation: "admin", Object: "tenant:" + tenantID},
	}))

	apiKeys, err := auth.NewAPIKeyAuthenticator(db)
	require.NoError(t, err)

	svc := newIntegrationService(t, db, fgaAuthorizer, nil)

	// Register three agents under the same tenant using separate bootstrap keys.
	agentIDs := make([]string, 3)
	for i := 0; i < 3; i++ {
		rawKey, record, createErr := apiKeys.CreateKey(ctx, tenantID, nil, nil, nil, "", "")
		require.NoError(t, createErr, "CreateKey must succeed for agent %d", i)

		_, err = db.ExecContext(ctx,
			`UPDATE api_keys SET max_uses = 1 WHERE key_id = $1`, record.KeyID)
		require.NoError(t, err)

		res, regErr := svc.RegisterAgentAuth(
			ctx,
			tenantID,
			userID,
			fmt.Sprintf("list-agent-%d", i),
			"delegated",
			generateECDSAJWK(t),
			generateECDSAJWK(t),
			"api_key",
			rawKey,
		)
		require.NoError(t, regErr, "RegisterAgentAuth must succeed for agent %d", i)
		agentIDs[i] = res.AgentID
	}

	// List all three — first page.
	listResult, listErr := svc.ListAgentAuthAgents(ctx, tenantID, 10, 0)
	require.NoError(t, listErr)
	require.NotNil(t, listResult)
	assert.Equal(t, 3, listResult.Total, "total must be 3")
	assert.Len(t, listResult.Agents, 3, "first page must have 3 agents")

	// Page size 2 — first page returns 2.
	page1, err := svc.ListAgentAuthAgents(ctx, tenantID, 2, 0)
	require.NoError(t, err)
	assert.Len(t, page1.Agents, 2)
	assert.Equal(t, 3, page1.Total)

	// Page size 2, offset 2 — second page returns 1.
	page2, err := svc.ListAgentAuthAgents(ctx, tenantID, 2, 2)
	require.NoError(t, err)
	assert.Len(t, page2.Agents, 1)
	assert.Equal(t, 3, page2.Total)

	// Tenant isolation: a different tenant sees zero agents.
	otherResult, otherErr := svc.ListAgentAuthAgents(ctx, "other-tenant", 10, 0)
	require.NoError(t, otherErr)
	assert.Equal(t, 0, otherResult.Total)
	assert.Empty(t, otherResult.Agents)
}

// ---------------------------------------------------------------------------
// TestBatchGrantComponentAccessV2Integration
// ---------------------------------------------------------------------------

// TestBatchGrantComponentAccessV2Integration verifies that bulk grant/revoke
// operations round-trip through FGA and generate audit events.
func TestBatchGrantComponentAccessV2Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db, pgCleanup := setupIntegrationPostgres(t)
	defer pgCleanup()

	fgaAuthorizer, fgaCleanup := setupIntegrationFGA(t, ctx)
	defer fgaCleanup()
	defer fgaAuthorizer.Close()

	const (
		tenantID = "batch-grant-tenant"
		actorID  = "batch-admin"
		userID   = "batch-user"
	)

	svc := newIntegrationService(t, db, fgaAuthorizer, nil)

	// Grant: batch-user can_execute component:nuclei.
	changes := []agentauth.GrantChangeV2{
		{
			UserID:        userID,
			PrincipalType: "user",
			ComponentRef:  "component:nuclei",
			Action:        "execute",
			Grant:         true,
		},
	}
	applied, err := svc.BatchGrantComponentAccessV2(ctx, tenantID, actorID, changes)
	require.NoError(t, err)
	assert.Equal(t, 1, applied, "one change must be applied")

	// FGA should now allow the check.
	allowed, err := fgaAuthorizer.Check(ctx, "user:"+userID, "can_execute", "component:nuclei")
	require.NoError(t, err)
	assert.True(t, allowed, "FGA must allow can_execute after BatchGrantComponentAccessV2 grant")

	// Revoke the same grant.
	revokeChanges := []agentauth.GrantChangeV2{
		{
			UserID:        userID,
			PrincipalType: "user",
			ComponentRef:  "component:nuclei",
			Action:        "execute",
			Grant:         false,
		},
	}
	revokedCount, revokeErr := svc.BatchGrantComponentAccessV2(ctx, tenantID, actorID, revokeChanges)
	require.NoError(t, revokeErr)
	assert.Equal(t, 1, revokedCount, "one revocation must be applied")

	// FGA should now deny the check.
	require.Eventually(t, func() bool {
		denied, checkErr := fgaAuthorizer.Check(ctx, "user:"+userID, "can_execute", "component:nuclei")
		return checkErr == nil && !denied
	}, 5*time.Second, 100*time.Millisecond, "FGA must deny can_execute after revocation")

	// Audit events must include both grant and revoke.
	grantAuditEvents := waitForAuditEvents(t, db, tenantID,
		audit.Filters{Action: "component_access_granted"},
		1,
	)
	assert.Len(t, grantAuditEvents, 1)

	revokeAuditEvents := waitForAuditEvents(t, db, tenantID,
		audit.Filters{Action: "component_access_revoked"},
		1,
	)
	assert.Len(t, revokeAuditEvents, 1)
}

// ---------------------------------------------------------------------------
// TestAgentAuthStatus_NotFound
// ---------------------------------------------------------------------------

// TestAgentAuthStatus_NotFound verifies that GetAgentAuthStatus returns
// (nil, nil) for an agent that does not exist, consistent with the store
// contract.
func TestAgentAuthStatus_NotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db, pgCleanup := setupIntegrationPostgres(t)
	defer pgCleanup()

	fgaAuthorizer, fgaCleanup := setupIntegrationFGA(t, ctx)
	defer fgaCleanup()
	defer fgaAuthorizer.Close()

	svc := newIntegrationService(t, db, fgaAuthorizer, nil)

	result, err := svc.GetAgentAuthStatus(ctx, "agt_nonexistent", "any-tenant")
	require.NoError(t, err, "GetAgentAuthStatus must not error for missing agent")
	assert.Nil(t, result, "result must be nil for non-existent agent")
}
