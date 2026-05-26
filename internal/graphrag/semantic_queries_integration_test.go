//go:build integration
// +build integration

package graphrag

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/ontology"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// setupSemanticNeo4j starts a Neo4j container and returns a connected client
// plus cleanup. Mirrors the pattern from internal/graphrag/ingest/integration_test.go.
func setupSemanticNeo4j(t *testing.T, ctx context.Context) (graph.GraphClient, func()) {
	t.Helper()

	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skip("Docker not available, skipping integration test")
		return nil, func() {}
	}
	if err := provider.Health(ctx); err != nil {
		t.Skip("Docker not running, skipping integration test")
		return nil, func() {}
	}

	req := testcontainers.ContainerRequest{
		Image:        "neo4j:5",
		ExposedPorts: []string{"7687/tcp"},
		Env: map[string]string{
			"NEO4J_AUTH": "none",
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("7687/tcp"),
			wait.ForLog("Started."),
		).WithDeadline(120 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start Neo4j container: %v", err)
	}

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "7687")
	require.NoError(t, err)

	cfg := graph.GraphClientConfig{
		URI:                     fmt.Sprintf("bolt://%s:%s", host, port.Port()),
		Username:                "neo4j",
		Password:                "ignored",
		Database:                "",
		MaxConnectionPoolSize:   5,
		ConnectionTimeout:       30 * time.Second,
		MaxTransactionRetryTime: 30 * time.Second,
	}
	client, err := graph.NewNeo4jClient(cfg)
	require.NoError(t, err)
	require.NoError(t, client.Connect(ctx))
	require.True(t, client.Health(ctx).IsHealthy())

	cleanup := func() {
		_ = client.Close(ctx)
		_ = container.Terminate(ctx)
	}
	return client, cleanup
}

// seedComplianceSignal writes a synthetic compliance_signal node directly into
// Neo4j for the given tenant. Returns the nodeID of the created node.
func seedComplianceSignal(t *testing.T, ctx context.Context, client graph.GraphClient, tenantID string, controlIDs []string, action, effect string) string {
	t.Helper()
	nodeID := fmt.Sprintf("cs-test-%s-%d", tenantID, time.Now().UnixNano())

	_, err := client.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		cypher := `
CREATE (cs:compliance_signal {
  id:          $id,
  tenant_id:   $tenant,
  control_ids: $control_ids,
  action:      $action,
  effect:      $effect,
  created_at:  datetime()
})
RETURN cs.id
`
		ids := make([]any, len(controlIDs))
		for i, id := range controlIDs {
			ids[i] = id
		}
		_, err := tx.Run(ctx, cypher, map[string]any{
			"id":          nodeID,
			"tenant":      tenantID,
			"control_ids": ids,
			"action":      action,
			"effect":      effect,
		})
		return nil, err
	})
	require.NoError(t, err, "seed compliance_signal")
	return nodeID
}

// -----------------------------------------------------------------------
// Integration test: signal-write → reasoner-expanded-query → result
// -----------------------------------------------------------------------

// TestIntegration_SemanticQuery_FindingsByControl exercises the full path:
//  1. Load a fixture ontology into the reasoner (soc2:CC6 → CC6.1 hierarchy).
//  2. Write a synthetic compliance_signal with control_ids = ["soc2:CC6.1"]
//     into a testcontainer Neo4j.
//  3. Query FindingsByControl for the parent IRI "soc2:CC6".
//  4. Assert the synthetic signal is returned (i.e., the descendant expansion worked).
func TestIntegration_SemanticQuery_FindingsByControl(t *testing.T) {
	ctx := context.Background()

	client, cleanup := setupSemanticNeo4j(t, ctx)
	defer cleanup()

	// --- Step 1: Load fixture ontology ---
	r := ontology.NewReasoner(ontology.NewMetrics())
	ext := sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{
			"soc2": "https://trust.aicpa.org/soc2#",
		},
		Hierarchies: []sdkgraphrag.HierarchyDef{
			{NodeType: "control", Label: "soc2:CC6"},
			{NodeType: "control", Label: "soc2:CC6.1", SubClassOf: "soc2:CC6"},
			{NodeType: "control", Label: "soc2:CC6.2", SubClassOf: "soc2:CC6"},
			{NodeType: "control", Label: "soc2:CC6.1.1", SubClassOf: "soc2:CC6.1"},
		},
	}
	require.NoError(t, r.RegisterExtension("fixture", ext))

	// Verify the reasoner knows the hierarchy.
	desc := r.Descendants("soc2:CC6")
	assert.Contains(t, desc, "soc2:CC6.1")

	// --- Step 2: Write synthetic compliance_signal with leaf IRI ---
	tenantID := "tenant-integration-test"
	// Signal stamped with the *child* IRI only (as the evaluator would write).
	seededID := seedComplianceSignal(t, ctx, client, tenantID,
		[]string{"soc2:CC6.1"},
		"tool_call", "allow",
	)

	// Also seed a signal with CC6.1.1 (grandchild) to test multi-level expansion.
	seededGrandchildID := seedComplianceSignal(t, ctx, client, tenantID,
		[]string{"soc2:CC6.1.1"},
		"tool_call", "allow",
	)

	// Seed a signal for a different tenant — must NOT appear in results.
	_ = seedComplianceSignal(t, ctx, client, "other-tenant",
		[]string{"soc2:CC6.1"},
		"tool_call", "allow",
	)

	// Seed a signal with an unrelated IRI — must NOT appear.
	_ = seedComplianceSignal(t, ctx, client, tenantID,
		[]string{"soc2:CC7"},
		"tool_call", "deny",
	)

	// --- Step 3: Query FindingsByControl for the parent IRI ---
	sq := NewSemanticQuerier(client, r)
	results, err := sq.FindingsByControl(ctx, tenantID, "soc2:CC6")
	require.NoError(t, err)

	// --- Step 4: Assert the synthetic signals are returned ---
	require.NotEmpty(t, results, "FindingsByControl('soc2:CC6') should return descendant signals")

	nodeIDs := make(map[string]bool)
	for _, sig := range results {
		nodeIDs[sig.NodeID] = true
		assert.Equal(t, tenantID, sig.TenantID, "tenant isolation: only correct tenant returned")
	}

	assert.True(t, nodeIDs[seededID], "signal with CC6.1 (direct child) must be returned for CC6 query")
	assert.True(t, nodeIDs[seededGrandchildID], "signal with CC6.1.1 (grandchild) must be returned for CC6 query")
}

// TestIntegration_SemanticQuery_DirectIRIMatch verifies that querying for an
// IRI that is already in the signal's control_ids returns the signal even when
// the reasoner has no descendants for that IRI (leaf node case).
func TestIntegration_SemanticQuery_DirectIRIMatch(t *testing.T) {
	ctx := context.Background()

	client, cleanup := setupSemanticNeo4j(t, ctx)
	defer cleanup()

	r := ontology.NewReasoner(ontology.NewMetrics())
	ext := sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{"soc2": "https://trust.aicpa.org/soc2#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{
			{NodeType: "control", Label: "soc2:CC6.1"},
		},
	}
	require.NoError(t, r.RegisterExtension("leaf", ext))

	tenantID := "tenant-leaf-test"
	seededID := seedComplianceSignal(t, ctx, client, tenantID,
		[]string{"soc2:CC6.1"},
		"authz_decision", "deny",
	)

	sq := NewSemanticQuerier(client, r)
	// Query for the leaf IRI directly — should match the signal.
	results, err := sq.FindingsByControl(ctx, tenantID, "soc2:CC6.1")
	require.NoError(t, err)
	require.NotEmpty(t, results)

	nodeIDs := make(map[string]bool)
	for _, sig := range results {
		nodeIDs[sig.NodeID] = true
	}
	assert.True(t, nodeIDs[seededID], "leaf IRI query must return signal with exact IRI match")
}

// TestIntegration_SemanticQuery_UnknownIRIReturnsEmpty ensures that querying
// for an IRI unknown to the reasoner returns an empty result, not an error.
func TestIntegration_SemanticQuery_UnknownIRIReturnsEmpty(t *testing.T) {
	ctx := context.Background()

	client, cleanup := setupSemanticNeo4j(t, ctx)
	defer cleanup()

	r := ontology.NewReasoner(ontology.NewMetrics())
	tenantID := "tenant-unknown-test"

	// Seed some data to ensure the empty result is not due to an empty DB.
	_ = seedComplianceSignal(t, ctx, client, tenantID, []string{"soc2:CC6.1"}, "tool_call", "allow")

	sq := NewSemanticQuerier(client, r)
	// Query for an IRI not in the ontology — reasoner returns empty descendants;
	// the literal IRI is still used in the query but no signals match.
	results, err := sq.FindingsByControl(ctx, tenantID, "soc2:NONEXISTENT")
	require.NoError(t, err)
	assert.Empty(t, results)
}
