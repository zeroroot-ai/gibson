//go:build integration

// Package harness — graphrag_bridge_integration_test.go
//
// Integration test for the full finding pipeline:
//
//	storeToGraphRAG → GraphLoader.LoadFindings → graph node persisted
//
// Uses the mock GraphClient from internal/graphrag/graph to verify that a
// Finding node is passed to the graph after bridge.StoreAsync is called.
// Set GIBSON_INTEGRATION_TESTS=1 to enable this test.
package harness

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/graphrag/loader"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestIntegration_GraphRAGBridge_FindingStored(t *testing.T) {
	if os.Getenv("GIBSON_INTEGRATION_TESTS") == "" {
		t.Skip("skipping integration test (set GIBSON_INTEGRATION_TESTS=1 to run)")
	}

	ctx := context.Background()

	// Set up a mock graph client that records queries.
	client := graph.NewMockGraphClient()
	require.NoError(t, client.Connect(ctx))

	// Pre-load a result for the CREATE query that LoadFindings will issue.
	nodeID := "finding-node-001"
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": nodeID, "idx": float64(0)},
		},
	})

	// Wire the bridge with a real GraphLoader backed by the mock client.
	gl := loader.NewGraphLoader(client)
	cfg := DefaultGraphRAGBridgeConfig()
	bridge := NewGraphRAGBridge(nil, cfg).WithGraphLoader(gl)

	// Construct a sample finding.
	finding := agent.Finding{
		ID:          types.ID("test-finding-001"),
		Title:       "SQL Injection in /api/login",
		Description: "Unsanitized user input allows SQL injection",
		Severity:    agent.SeverityHigh,
		Category:    "injection",
		CreatedAt:   time.Now(),
	}

	missionID := types.ID("mission-integration-001")

	// Call StoreAsync — it queues storage in a background goroutine.
	bridge.StoreAsync(ctx, finding, missionID, nil)

	// Wait for the background goroutine to complete.
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, bridge.Shutdown(shutdownCtx))

	// Verify that the mock graph client received at least one call after StoreAsync.
	// The GraphLoader issues a Query or CreateNode call for the Finding node.
	calls := client.GetCalls()
	// Filter out the Connect call.
	var dataCalls []graph.MockCall
	for _, c := range calls {
		if c.Method != "Connect" {
			dataCalls = append(dataCalls, c)
		}
	}
	assert.NotEmpty(t, dataCalls, "expected at least one graph operation after StoreAsync")

	// Verify that at least one call carried the finding ID in its params.
	foundFindingID := false
	for _, c := range dataCalls {
		if len(c.Args) < 2 {
			continue
		}
		params, ok := c.Args[1].(map[string]any)
		if !ok {
			continue
		}
		for _, v := range params {
			if s, ok := v.(string); ok && s == string(finding.ID) {
				foundFindingID = true
				break
			}
		}
		if foundFindingID {
			break
		}
	}
	assert.True(t, foundFindingID,
		"expected to find finding ID %q in graph call parameters; calls: %d",
		finding.ID, len(dataCalls))
}

// TestIntegration_GraphRAGBridge_NilLoader_NoOp verifies that when no GraphLoader
// is wired, StoreAsync completes without error and no queries are issued.
func TestIntegration_GraphRAGBridge_NilLoader_NoOp(t *testing.T) {
	if os.Getenv("GIBSON_INTEGRATION_TESTS") == "" {
		t.Skip("skipping integration test (set GIBSON_INTEGRATION_TESTS=1 to run)")
	}

	ctx := context.Background()

	// Bridge with no GraphLoader wired.
	cfg := DefaultGraphRAGBridgeConfig()
	bridge := NewGraphRAGBridge(nil, cfg)

	finding := agent.Finding{
		ID:    types.ID("no-loader-finding"),
		Title: "Test Finding",
	}

	bridge.StoreAsync(ctx, finding, types.ID("mission-001"), nil)

	shutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Should complete without error even with nil graphLoader.
	assert.NoError(t, bridge.Shutdown(shutdownCtx))
}
