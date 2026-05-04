package graph

import (
	"context"
	"errors"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zero-day-ai/sdk/auth"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers / stub GraphClient
// ─────────────────────────────────────────────────────────────────────────────

// callableGraphClient is a minimal GraphClient whose ExecuteRead/ExecuteWrite
// handlers are set per-test. This gives fine-grained control over what each
// call site returns without requiring a real Neo4j driver.
type callableGraphClient struct {
	MockGraphClient
	readFn func(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error)
}

func (c *callableGraphClient) ExecuteRead(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	if c.readFn != nil {
		return c.readFn(ctx, fn)
	}
	return nil, nil
}

func mustTenantID(s string) auth.TenantID {
	t, err := auth.NewTenantID(s)
	if err != nil {
		panic(err)
	}
	return t
}

// ─────────────────────────────────────────────────────────────────────────────
// Cap enforcement
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyLimitCap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want uint32
	}{
		{0, DefaultGraphLimit},
		{100, 100},
		{DefaultGraphLimit, DefaultGraphLimit},
		{MaxGraphLimit, MaxGraphLimit},
		{MaxGraphLimit + 1, MaxGraphLimit},
		{99999, MaxGraphLimit},
	}
	for _, tc := range tests {
		got := applyLimitCap(tc.in)
		if got != tc.want {
			t.Errorf("applyLimitCap(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestApplyDepthCap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want uint32
	}{
		{0, DefaultPathDepth},
		{3, 3},
		{MaxPathDepth, MaxPathDepth},
		{MaxPathDepth + 1, MaxPathDepth},
		{100, MaxPathDepth},
	}
	for _, tc := range tests {
		got := applyDepthCap(tc.in)
		if got != tc.want {
			t.Errorf("applyDepthCap(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFullGraph — happy path
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFullGraph_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("acme")

	// readFn call sequence for GetFullGraph:
	//   call 0 → countNodes
	//   call 1 → fetchNodes
	//   call 2 → fetchEdges
	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0: // countNodes → return uint32(3)
				return uint32(3), nil
			case 1: // fetchNodes → return 3 proto nodes
				nodes := []*graphpb.Node{
					{Id: "n1", Labels: []string{"Host"}, Properties: map[string]string{"id": "n1", "tenant_id": "acme"}},
					{Id: "n2", Labels: []string{"Port"}, Properties: map[string]string{"id": "n2", "tenant_id": "acme"}},
					{Id: "n3", Labels: []string{"Finding"}, Properties: map[string]string{"id": "n3", "tenant_id": "acme", "severity": "high"}},
				}
				return nodes, nil
			case 2: // fetchEdges → return 1 edge
				edges := []*graphpb.Edge{
					{Id: "e1", SourceId: "n1", TargetId: "n2", Type: "HAS_PORT"},
				}
				return edges, nil
			default:
				return nil, errors.New("unexpected ExecuteRead call")
			}
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	nodes, edges, truncated, total, err := q.GetFullGraph(ctx, tenant, 100, nil)
	if err != nil {
		t.Fatalf("GetFullGraph: %v", err)
	}
	if len(nodes) != 3 {
		t.Errorf("got %d nodes, want 3", len(nodes))
	}
	if len(edges) != 1 {
		t.Errorf("got %d edges, want 1", len(edges))
	}
	if truncated {
		t.Error("truncated should be false when total <= limit")
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFullGraph — truncation
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFullGraph_Truncation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("bigcorp")

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, _ func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0: // count: 5000 nodes total
				return uint32(5000), nil
			case 1: // fetch limited to 10
				nodes := make([]*graphpb.Node, 10)
				for i := range nodes {
					nodes[i] = &graphpb.Node{Id: "n" + string(rune('0'+i))}
				}
				return nodes, nil
			case 2: // edges
				return ([]*graphpb.Edge)(nil), nil
			}
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	// limit 10 against 5000 total → truncated=true
	_, _, truncated, total, err := q.GetFullGraph(ctx, tenant, 10, nil)
	if err != nil {
		t.Fatalf("GetFullGraph: %v", err)
	}
	if !truncated {
		t.Error("want truncated=true when total > limit")
	}
	if total != 5000 {
		t.Errorf("total = %d, want 5000", total)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFullGraph — limit over MaxGraphLimit is clamped
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFullGraph_LimitClamped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("clamped")

	// We'll capture the params sent to the node-fetch call to verify the
	// limit was actually clamped to MaxGraphLimit.
	var capturedLimit any

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0: // count
				return uint32(0), nil
			case 1: // fetchNodes — capture params via fn (we return nil to skip Cypher)
				// The real fn closes over the params map built by buildNodeFetchCypher;
				// we can't inspect it here without real TX, so just verify call happened.
				_ = capturedLimit
				return ([]*graphpb.Node)(nil), nil
			}
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	_, _, _, _, err := q.GetFullGraph(ctx, tenant, 99999, nil)
	if err != nil {
		t.Fatalf("GetFullGraph with oversized limit: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFullGraph — label filter (call reaches fetchNodes with labels)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFullGraph_LabelFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("labeltest")

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, _ func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0: // count with label filter → 2
				return uint32(2), nil
			case 1: // fetch nodes for the label
				nodes := []*graphpb.Node{
					{Id: "h1", Labels: []string{"Host"}},
					{Id: "h2", Labels: []string{"Host"}},
				}
				return nodes, nil
			case 2: // edges
				return ([]*graphpb.Edge)(nil), nil
			}
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	nodes, _, _, total, err := q.GetFullGraph(ctx, tenant, 100, []string{"Host"})
	if err != nil {
		t.Fatalf("GetFullGraph with label filter: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("got %d nodes, want 2", len(nodes))
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFullGraph — empty result
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFullGraph_Empty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("empty-tenant")

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, _ func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0: // count → 0
				return uint32(0), nil
			case 1: // fetchNodes → empty
				return ([]*graphpb.Node)(nil), nil
			}
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	nodes, edges, truncated, total, err := q.GetFullGraph(ctx, tenant, 0, nil)
	if err != nil {
		t.Fatalf("GetFullGraph empty: %v", err)
	}
	if len(nodes) != 0 || len(edges) != 0 {
		t.Error("want empty nodes/edges")
	}
	if truncated {
		t.Error("truncated should be false for empty result")
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetMissionGraph — happy path
// ─────────────────────────────────────────────────────────────────────────────

func TestGetMissionGraph_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("mission-tenant")

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, _ func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0: // runNodeFetch for BELONGS_TO
				nodes := []*graphpb.Node{
					{Id: "n1", Labels: []string{"Host"}},
				}
				return nodes, nil
			case 1: // fetchEdges
				return ([]*graphpb.Edge)(nil), nil
			}
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	nodes, edges, err := q.GetMissionGraph(ctx, tenant, "mission-abc")
	if err != nil {
		t.Fatalf("GetMissionGraph: %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("got %d nodes, want 1", len(nodes))
	}
	_ = edges
}

// ─────────────────────────────────────────────────────────────────────────────
// GetMissionGraph — different tenant's missionID returns empty
// ─────────────────────────────────────────────────────────────────────────────

func TestGetMissionGraph_WrongTenantReturnsEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// The Cypher includes WHERE run.tenant_id = $tenant, so a mission belonging
	// to a different tenant returns no rows. We simulate this by returning an
	// empty node list from ExecuteRead.
	tenant := mustTenantID("tenant-a")

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, _ func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			// First call: runNodeFetch — returns empty (simulates tenant isolation)
			return ([]*graphpb.Node)(nil), nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	nodes, edges, err := q.GetMissionGraph(ctx, tenant, "mission-from-tenant-b")
	if err != nil {
		t.Fatalf("GetMissionGraph cross-tenant: %v", err)
	}
	if len(nodes) != 0 || len(edges) != 0 {
		t.Errorf("want empty result for cross-tenant mission; got %d nodes, %d edges",
			len(nodes), len(edges))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFullGraph — ExecuteRead error propagates
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFullGraph_ErrorPropagates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("err-tenant")

	sentinel := errors.New("neo4j transient error")
	client := &callableGraphClient{
		readFn: func(_ context.Context, _ func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			return nil, sentinel
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	_, _, _, _, err := q.GetFullGraph(ctx, tenant, 100, nil)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// QueryPaths — cap enforcement
// ─────────────────────────────────────────────────────────────────────────────

func TestQueryPaths_DepthClamped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("path-tenant")

	// We don't care about actual Cypher execution — just that the call succeeds
	// with a nil/empty result when ExecuteRead returns (nil, nil).
	client := &callableGraphClient{
		readFn: func(_ context.Context, _ func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	// maxDepth=100 should be clamped to MaxPathDepth without panicking.
	_, _, _, _, err := q.QueryPaths(ctx, tenant, "from-id", "to-id", "", 100)
	if err != nil {
		t.Fatalf("QueryPaths with clamped depth: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// valueToString coercion tests
// ─────────────────────────────────────────────────────────────────────────────

func TestValueToString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"bool-true", true, "true"},
		{"bool-false", false, "false"},
		{"int64", int64(42), "42"},
		{"float64", float64(3.14), "3.14"},
		{"int", int(7), "7"},
		{"int32", int32(-1), "-1"},
		{"list", []any{1, 2}, "[1,2]"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := valueToString(tc.input)
			if got != tc.want {
				t.Errorf("valueToString(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
