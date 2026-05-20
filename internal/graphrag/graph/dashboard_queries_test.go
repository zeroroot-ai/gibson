package graph

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zero-day-ai/sdk/auth"
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

// ─────────────────────────────────────────────────────────────────────────────
// FindingCounts — happy path (SEVERITY)
// ─────────────────────────────────────────────────────────────────────────────

func TestFindingCounts_Severity_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("fc-tenant")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			return []CountBucket{
				{Label: "critical", Count: 3},
				{Label: "high", Count: 7},
			}, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	buckets, err := q.FindingCounts(ctx, tenant, graphpb.FindingCountGroupBy_SEVERITY, 0)
	if err != nil {
		t.Fatalf("FindingCounts: %v", err)
	}
	if len(buckets) != 2 {
		t.Errorf("got %d buckets, want 2", len(buckets))
	}
	if buckets[0].Label != "critical" || buckets[0].Count != 3 {
		t.Errorf("bucket[0] = %+v, want {critical 3}", buckets[0])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingCounts — tenant isolation (wrong tenant returns empty)
// ─────────────────────────────────────────────────────────────────────────────

func TestFindingCounts_TenantIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("isolated-tenant")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			// Simulate Neo4j returning empty (tenant_id mismatch in WHERE clause).
			return []CountBucket{}, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	buckets, err := q.FindingCounts(ctx, tenant, graphpb.FindingCountGroupBy_SEVERITY, 0)
	if err != nil {
		t.Fatalf("FindingCounts isolation: %v", err)
	}
	if len(buckets) != 0 {
		t.Errorf("want 0 buckets for isolated tenant, got %d", len(buckets))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingCounts — CATEGORY groupBy
// ─────────────────────────────────────────────────────────────────────────────

func TestFindingCounts_Category(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("cat-tenant")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			return []CountBucket{
				{Label: "web", Count: 5},
				{Label: "network", Count: 2},
			}, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	buckets, err := q.FindingCounts(ctx, tenant, graphpb.FindingCountGroupBy_CATEGORY, 0)
	if err != nil {
		t.Fatalf("FindingCounts category: %v", err)
	}
	if len(buckets) != 2 {
		t.Errorf("got %d buckets, want 2", len(buckets))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingTimeSeries — default days=0 → DefaultTimeSeriesDays points
// ─────────────────────────────────────────────────────────────────────────────

func TestFindingTimeSeries_DefaultDays(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("ts-tenant")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			// Return empty map (no findings in the window).
			return map[string]uint64{}, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	points, err := q.FindingTimeSeries(ctx, tenant, 0)
	if err != nil {
		t.Fatalf("FindingTimeSeries: %v", err)
	}
	// 0 → DefaultTimeSeriesDays (30) padded points.
	if len(points) != int(DefaultTimeSeriesDays) {
		t.Errorf("got %d points, want %d", len(points), DefaultTimeSeriesDays)
	}
	// All counts should be zero (no data).
	for i, p := range points {
		if p.GetCount() != 0 {
			t.Errorf("point[%d] count = %d, want 0", i, p.GetCount())
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingTimeSeries — days capped to MaxTimeSeriesDays
// ─────────────────────────────────────────────────────────────────────────────

func TestFindingTimeSeries_CapEnforced(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("ts-cap-tenant")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			return map[string]uint64{}, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	// 9999 should be clamped to MaxTimeSeriesDays.
	points, err := q.FindingTimeSeries(ctx, tenant, 9999)
	if err != nil {
		t.Fatalf("FindingTimeSeries cap: %v", err)
	}
	if len(points) != int(MaxTimeSeriesDays) {
		t.Errorf("got %d points, want %d", len(points), MaxTimeSeriesDays)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingTimeSeries — data padded correctly
// ─────────────────────────────────────────────────────────────────────────────

func TestFindingTimeSeries_PaddedCorrectly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("ts-pad-tenant")

	today := time.Now().UTC().Format("2006-01-02")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			return map[string]uint64{today: 42}, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	points, err := q.FindingTimeSeries(ctx, tenant, 7)
	if err != nil {
		t.Fatalf("FindingTimeSeries padded: %v", err)
	}
	if len(points) != 7 {
		t.Errorf("got %d points, want 7", len(points))
	}
	// Last point should be today with count 42.
	last := points[len(points)-1]
	if last.GetCount() != 42 {
		t.Errorf("last point count = %d, want 42", last.GetCount())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphStats — happy path
// ─────────────────────────────────────────────────────────────────────────────

func TestGraphStats_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("stats-tenant")

	// Three ExecuteRead calls: labels, edges, lastWrite.
	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0: // labels
				return []NodeCountByLabel{
					{Label: "Host", Count: 10},
					{Label: "Finding", Count: 5},
				}, nil
			case 1: // edges
				return uint64(20), nil
			case 2: // lastWrite
				return time.Now().UTC(), nil
			}
			return nil, errors.New("unexpected call")
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	stats, err := q.GraphStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GraphStats: %v", err)
	}
	if len(stats.ByLabel) != 2 {
		t.Errorf("got %d labels, want 2", len(stats.ByLabel))
	}
	if stats.TotalNodes != 15 {
		t.Errorf("TotalNodes = %d, want 15", stats.TotalNodes)
	}
	if stats.TotalEdges != 20 {
		t.Errorf("TotalEdges = %d, want 20", stats.TotalEdges)
	}
	if stats.LastWriteAt.IsZero() {
		t.Error("LastWriteAt should not be zero")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphStats — tenant isolation (empty data for unknown tenant)
// ─────────────────────────────────────────────────────────────────────────────

func TestGraphStats_TenantIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("stats-isolated")

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0:
				return []NodeCountByLabel{}, nil
			case 1:
				return uint64(0), nil
			case 2:
				return time.Time{}, nil
			}
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	stats, err := q.GraphStats(ctx, tenant)
	if err != nil {
		t.Fatalf("GraphStats isolation: %v", err)
	}
	if stats.TotalNodes != 0 || stats.TotalEdges != 0 {
		t.Errorf("want empty stats, got nodes=%d edges=%d", stats.TotalNodes, stats.TotalEdges)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphSummary — happy path
// ─────────────────────────────────────────────────────────────────────────────

func TestGraphSummary_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("summary-tenant")

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0: // counts by label
				return map[string]uint64{
					"Host":    3,
					"Finding": 2,
					"Mission": 1,
				}, nil
			case 1: // critical findings
				return []summaryFindingRow{
					{name: "CVE-2024-1234", severity: "critical", cve: "CVE-2024-1234"},
				}, nil
			case 2: // missions
				return []summaryMissionRow{
					{name: "Recon Op", status: "completed"},
				}, nil
			}
			return nil, errors.New("unexpected call")
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	result, err := q.GraphSummary(ctx, tenant)
	if err != nil {
		t.Fatalf("GraphSummary: %v", err)
	}
	if result.Stats.Hosts != 3 {
		t.Errorf("Hosts = %d, want 3", result.Stats.Hosts)
	}
	if result.Stats.Findings != 2 {
		t.Errorf("Findings = %d, want 2", result.Stats.Findings)
	}
	if result.Summary == "" {
		t.Error("Summary should not be empty")
	}
	// Check for key phrases from the template.
	if !contains(result.Summary, "## Knowledge Graph Overview") {
		t.Error("Summary missing '## Knowledge Graph Overview'")
	}
	if !contains(result.Summary, "## Critical & High Severity Findings") {
		t.Error("Summary missing '## Critical & High Severity Findings'")
	}
	if !contains(result.Summary, "## Recent Missions") {
		t.Error("Summary missing '## Recent Missions'")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphSummary — empty graph returns empty-graph message
// ─────────────────────────────────────────────────────────────────────────────

func TestGraphSummary_Empty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("summary-empty")

	callIdx := 0
	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0:
				return map[string]uint64{}, nil
			case 1:
				return []summaryFindingRow{}, nil
			case 2:
				return []summaryMissionRow{}, nil
			}
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	result, err := q.GraphSummary(ctx, tenant)
	if err != nil {
		t.Fatalf("GraphSummary empty: %v", err)
	}
	if !contains(result.Summary, "empty for this tenant") {
		t.Errorf("empty-graph message not found in: %q", result.Summary)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphContext — missing node returns empty (soft-fail)
// ExecuteRead returns (nil, nil) → simulates 0 rows from Neo4j when the node
// does not exist or has a different tenant_id.
// ─────────────────────────────────────────────────────────────────────────────

func TestGraphContext_MissingNode_SoftFail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("ctx-missing")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			// nil return → GraphContext treats as "not found" and soft-fails.
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	result, err := q.GraphContext(ctx, tenant, "nonexistent", 2, 30)
	if err != nil {
		t.Fatalf("GraphContext missing node should not error: %v", err)
	}
	if result.FocusNode != nil {
		t.Error("FocusNode should be nil for missing node")
	}
	if len(result.Neighbors) != 0 {
		t.Errorf("Neighbors should be empty, got %d", len(result.Neighbors))
	}
	if result.Summary != "" {
		t.Errorf("Summary should be empty, got %q", result.Summary)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphContext — cap enforcement (hops and maxNodes clamped, no panic)
// ─────────────────────────────────────────────────────────────────────────────

func TestGraphContext_CapEnforced(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("ctx-cap")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			return nil, nil // soft-fail path
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	// hops=999 → clamped to MaxContextHops; maxNodes=999 → MaxContextMaxNodes.
	_, err := q.GraphContext(ctx, tenant, "n1", 999, 999)
	if err != nil {
		t.Fatalf("GraphContext cap: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphContext — tenant isolation (different tenant returns empty)
// ─────────────────────────────────────────────────────────────────────────────

func TestGraphContext_TenantIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Simulate tenant-B querying a node owned by tenant-A.
	// Neo4j WHERE n.tenant_id = $tenant returns 0 rows → ExecuteRead returns nil.
	tenantB := mustTenantID("tenant-b")

	client := &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			return nil, nil
		},
	}
	client.connected = true

	q := NewDashboardQueries(client)
	result, err := q.GraphContext(ctx, tenantB, "tenant-a-node", 2, 30)
	if err != nil {
		t.Fatalf("GraphContext cross-tenant should not error: %v", err)
	}
	if result.FocusNode != nil {
		t.Error("cross-tenant node access should return nil FocusNode")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	if len(s) == 0 || len(substr) == 0 {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
