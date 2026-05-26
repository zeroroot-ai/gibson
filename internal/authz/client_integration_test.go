//go:build integration
// +build integration

package authz_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/zeroroot-ai/gibson/internal/authz"
)

// setupFGAContainer starts an OpenFGA container with in-memory SQLite store.
// Returns the container, HTTP base URL, and a cleanup function.
func setupFGAContainer(t *testing.T, ctx context.Context) (testcontainers.Container, string, func()) {
	t.Helper()

	// Check if Docker is available.
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skip("Docker not available, skipping integration test")
		return nil, "", func() {}
	}
	if err := provider.Health(ctx); err != nil {
		t.Skip("Docker not running, skipping integration test")
		return nil, "", func() {}
	}

	// OpenFGA with SQLite memory store (no external Postgres needed in CI).
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
	if err != nil {
		t.Fatalf("failed to start OpenFGA container: %v", err)
	}

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "8080")
	require.NoError(t, err)

	baseURL := fmt.Sprintf("http://%s:%s", host, port.Port())

	cleanup := func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("warning: failed to terminate FGA container: %v", err)
		}
	}

	return container, baseURL, cleanup
}

// setupFGAStore creates a new FGA store and writes the model from model.fga.
// Returns storeID and modelID.
func setupFGAStore(t *testing.T, ctx context.Context, baseURL string) (string, string) {
	t.Helper()

	// Use the FGA HTTP API directly to create store and write model.
	// We use the openfga/go-sdk client package for this.
	fgaclientPkg := newRawFGAClient(t, baseURL)

	// Create store.
	createResp, err := fgaclientPkg.CreateStore(ctx).Body(struct {
		Name string `json:"name"`
	}{Name: "gibson-integration-test"}).Execute()
	require.NoError(t, err, "failed to create FGA store")

	storeID := createResp.GetId()
	require.NotEmpty(t, storeID, "store ID must not be empty")

	// Write authorization model from the checked-in model.fga.
	// We send the model DSL via the write model endpoint.
	// The openfga SDK's WriteAuthorizationModel takes a parsed model object.
	// We hardcode the equivalent JSON type definitions here to avoid importing
	// the openfga CLI parser (which is a separate binary, not a Go library).
	modelID := writeTestModel(t, ctx, baseURL, storeID)

	return storeID, modelID
}

// TestIntegration_FGA_FiveScenarios runs the five authorization scenarios
// defined in requirements.md §6 against a real OpenFGA container.
//
// Scenario 1: user:alice with admin on tenant:acme → Check(user:alice, admin, tenant:acme) = true
// Scenario 2: user:alice with admin on tenant:acme → Check(user:alice, member, tenant:acme) = true (admin implies member)
// Scenario 3: user:bob has no tuples → Check(user:bob, admin, tenant:acme) = false
// Scenario 4: tenant:acme owns component:plugin-gitlab → Check(user:alice, can_execute, component:plugin-gitlab) = true (via admin→member)
// Scenario 5: user:root with platform_operator → Check(user:root, platform_operator, system_tenant:_system) = true
func TestIntegration_FGA_FiveScenarios(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, baseURL, cleanup := setupFGAContainer(t, ctx)
	defer cleanup()

	storeID, modelID := setupFGAStore(t, ctx, baseURL)
	require.NotEmpty(t, storeID)
	require.NotEmpty(t, modelID)

	// Build the Authorizer under test.
	a, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:  baseURL,
		StoreID:   storeID,
		ModelID:   modelID,
		TimeoutMs: 5000,
		Logger:    slog.Default(),
	})
	require.NoError(t, err)
	defer a.Close()

	// Seed tuples for the test scenarios.
	err = a.Write(ctx, []authz.Tuple{
		// alice is admin of tenant:acme (covers scenarios 1, 2, 4)
		{User: "user:alice", Relation: "admin", Object: "tenant:acme"},
		// tenant:acme owns component:plugin-gitlab (covers scenario 4)
		{User: "tenant:acme", Relation: "owner", Object: "component:plugin-gitlab"},
		// root is platform_operator on system_tenant:_system (covers scenario 5)
		{User: "user:root", Relation: "platform_operator", Object: "system_tenant:_system"},
	})
	require.NoError(t, err, "failed to write test tuples")

	t.Run("Scenario1_AdminDirectCheck", func(t *testing.T) {
		allowed, err := a.Check(ctx, "user:alice", "admin", "tenant:acme")
		require.NoError(t, err)
		assert.True(t, allowed, "alice must be admin of tenant:acme")
	})

	t.Run("Scenario2_AdminImpliesMember", func(t *testing.T) {
		allowed, err := a.Check(ctx, "user:alice", "member", "tenant:acme")
		require.NoError(t, err)
		assert.True(t, allowed, "alice must be member of tenant:acme (computed from admin)")
	})

	t.Run("Scenario3_BobHasNoTuples", func(t *testing.T) {
		allowed, err := a.Check(ctx, "user:bob", "admin", "tenant:acme")
		require.NoError(t, err)
		assert.False(t, allowed, "bob has no tuples, must be denied")
	})

	t.Run("Scenario4_ComponentExecuteViaAdminMembership", func(t *testing.T) {
		allowed, err := a.Check(ctx, "user:alice", "can_execute", "component:plugin-gitlab")
		require.NoError(t, err)
		assert.True(t, allowed, "alice can_execute plugin-gitlab via admin→member→can_execute")
	})

	t.Run("Scenario5_PlatformOperator", func(t *testing.T) {
		allowed, err := a.Check(ctx, "user:root", "platform_operator", "system_tenant:_system")
		require.NoError(t, err)
		assert.True(t, allowed, "root must be platform_operator on system_tenant:_system")
	})
}

// TestIntegration_FGA_EmptyInputReturnsError ensures that invalid inputs
// never reach the FGA service.
func TestIntegration_FGA_EmptyInputReturnsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, baseURL, cleanup := setupFGAContainer(t, ctx)
	defer cleanup()

	storeID, modelID := setupFGAStore(t, ctx, baseURL)

	a, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:  baseURL,
		StoreID:   storeID,
		ModelID:   modelID,
		TimeoutMs: 5000,
	})
	require.NoError(t, err)
	defer a.Close()

	tests := []struct {
		name     string
		user     string
		relation string
		object   string
	}{
		{"empty user", "", "admin", "tenant:acme"},
		{"empty relation", "user:alice", "", "tenant:acme"},
		{"empty object", "user:alice", "admin", ""},
		{"all empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := a.Check(ctx, tt.user, tt.relation, tt.object)
			assert.False(t, allowed)
			assert.Error(t, err)
			assert.True(t, authz.IsInvalidArgument(err), "expected ErrInvalidArgument, got: %v", err)
		})
	}
}

// TestIntegration_FGA_WriteDelete verifies write and delete are idempotent.
func TestIntegration_FGA_WriteDelete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, baseURL, cleanup := setupFGAContainer(t, ctx)
	defer cleanup()

	storeID, modelID := setupFGAStore(t, ctx, baseURL)

	a, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:  baseURL,
		StoreID:   storeID,
		ModelID:   modelID,
		TimeoutMs: 5000,
	})
	require.NoError(t, err)
	defer a.Close()

	tuple := authz.Tuple{User: "user:carol", Relation: "admin", Object: "tenant:test"}

	// Write twice — must be idempotent.
	require.NoError(t, a.Write(ctx, []authz.Tuple{tuple}))
	require.NoError(t, a.Write(ctx, []authz.Tuple{tuple}))

	// Verify the write took effect.
	allowed, err := a.Check(ctx, "user:carol", "admin", "tenant:test")
	require.NoError(t, err)
	assert.True(t, allowed)

	// Delete the tuple.
	require.NoError(t, a.Delete(ctx, []authz.Tuple{tuple}))

	// Verify deletion.
	allowed, err = a.Check(ctx, "user:carol", "admin", "tenant:test")
	require.NoError(t, err)
	assert.False(t, allowed, "tuple must be gone after Delete")
}
