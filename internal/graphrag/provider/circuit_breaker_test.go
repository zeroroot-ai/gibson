package provider

// TestGraphRAG_CircuitOpensAfter5Failures, TestGraphRAG_GraphHealthyFalseWhenOpen,
// and TestGraphRAG_GraphHealthyRestoredOnClose exercise the gobreaker circuit
// breaker wired into LocalGraphRAGProvider.
//
// The tests use a MockGraphClient (from internal/graphrag/graph) that can be
// configured to return errors, together with a real *gobreaker.CircuitBreaker
// constructed by newGraphRAGBreaker so that state-machine transitions happen
// exactly as they would in production.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
)

// newTestProviderWithMock creates a LocalGraphRAGProvider wired with a connected
// MockGraphClient that is ready to use. The provider has a real circuit breaker
// using the supplied config so tests can control the trip threshold.
func newTestProviderWithMock(t *testing.T, cfg resilience.CircuitConfig) (*LocalGraphRAGProvider, *graph.MockGraphClient) {
	t.Helper()
	p := &LocalGraphRAGProvider{
		config:      graphrag.GraphRAGConfig{Provider: "neo4j"},
		initialized: true,
	}
	p.graphHealthy.Store(true)
	p.cb = resilience.NewBreaker(
		"graphrag-test",
		cfg,
		func(name string, from, to gobreaker.State) {
			switch to {
			case gobreaker.StateClosed:
				p.graphHealthy.Store(true)
			case gobreaker.StateOpen:
				p.graphHealthy.Store(false)
				// StateHalfOpen: leave graphHealthy as-is; the probe determines outcome.
			}
		},
	)

	mc := graph.NewMockGraphClient()
	require.NoError(t, mc.Connect(context.Background()))
	p.graphClient = mc
	return p, mc
}

// fiveFailureCfg returns a CircuitConfig that trips after 5 consecutive failures
// and has a very short half-open timeout so probe tests run quickly.
func fiveFailureCfg() resilience.CircuitConfig {
	return resilience.CircuitConfig{
		ConsecutiveFailures: 5,
		Interval:            10 * time.Second,
		Timeout:             100 * time.Millisecond, // short for tests
	}
}

// TestGraphRAG_CircuitOpensAfter5Failures verifies that after 5 consecutive
// errors the circuit opens and the 6th call returns gobreaker.ErrOpenState
// (mapped to ProviderUnavailable) immediately without hitting the mock client.
func TestGraphRAG_CircuitOpensAfter5Failures(t *testing.T) {
	p, mc := newTestProviderWithMock(t, fiveFailureCfg())

	// Configure the mock to always return an error on CreateNode.
	sentinel := errors.New("neo4j connection refused")
	mc.SetCreateNodeError(sentinel)

	ctx := context.Background()
	// Use a node with a label (required for validation) but no embedding
	// so only the graph path is exercised.
	node := graphrag.NewGraphNode(types.NewID(), graphrag.NodeType("finding"))

	// Calls 1–5: all fail, each one counted as a failure by the breaker.
	for i := 0; i < 5; i++ {
		err := p.StoreNode(ctx, *node)
		assert.Error(t, err, "call %d should fail", i+1)
	}

	// Record the call count so far (should be 5 CreateNode calls).
	callsBefore := len(mc.GetCallsByMethod("CreateNode"))
	assert.Equal(t, 5, callsBefore, "expected exactly 5 CreateNode calls before circuit opens")

	// Call 6: the circuit should now be open. The mock must NOT be called.
	err := p.StoreNode(ctx, *node)
	require.Error(t, err)
	// The error should indicate unavailability (circuit open).
	assert.Contains(t, err.Error(), "circuit breaker open",
		"expected circuit-open error, got: %v", err)

	callsAfter := len(mc.GetCallsByMethod("CreateNode"))
	assert.Equal(t, callsBefore, callsAfter, "mock must not be called when circuit is open")
}

// TestGraphRAG_GraphHealthyFalseWhenOpen verifies that graphHealthy is set to
// false once the circuit breaker trips to the Open state.
func TestGraphRAG_GraphHealthyFalseWhenOpen(t *testing.T) {
	p, mc := newTestProviderWithMock(t, fiveFailureCfg())

	sentinel := errors.New("neo4j down")
	mc.SetCreateNodeError(sentinel)

	ctx := context.Background()
	node := graphrag.NewGraphNode(types.NewID(), graphrag.NodeType("finding"))

	for i := 0; i < 5; i++ {
		_ = p.StoreNode(ctx, *node)
	}

	// After 5 failures the circuit is Open and the callback must have fired.
	assert.False(t, p.graphHealthy.Load(), "graphHealthy must be false when circuit is open")
}

// TestGraphRAG_GraphHealthyRestoredOnClose verifies that when the circuit
// transitions from Open → Half-Open → Closed (after a successful probe),
// graphHealthy is restored to true.
func TestGraphRAG_GraphHealthyRestoredOnClose(t *testing.T) {
	p, mc := newTestProviderWithMock(t, fiveFailureCfg())

	sentinel := errors.New("neo4j down")
	mc.SetCreateNodeError(sentinel)

	ctx := context.Background()
	node := graphrag.NewGraphNode(types.NewID(), graphrag.NodeType("finding"))

	// Trip the circuit.
	for i := 0; i < 5; i++ {
		_ = p.StoreNode(ctx, *node)
	}

	// Verify the circuit is open and graphHealthy is false.
	assert.False(t, p.graphHealthy.Load(), "graphHealthy must be false after trip")

	// Wait for the Timeout to expire so the breaker transitions to Half-Open.
	time.Sleep(150 * time.Millisecond)

	// Clear the error so the next (probe) call succeeds.
	mc.SetCreateNodeError(nil)

	// Issue a successful call — this is the probe in Half-Open state.
	// gobreaker transitions to Closed after MaxRequests (1) successful probe.
	// The OnStateChange callback fires synchronously inside Execute.
	_ = p.StoreNode(ctx, *node)

	// The OnStateChange callback fires synchronously inside cb.Execute, so by the
	// time StoreNode returns, graphHealthy must be true.
	assert.True(t, p.graphHealthy.Load(), "graphHealthy must be restored to true after circuit closes")
}
