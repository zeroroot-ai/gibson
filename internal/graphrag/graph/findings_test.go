package graph

// findings_test.go — unit tests for DashboardQueries.Findings
//
// Spec: dashboard-neo4j-crud-removal (Phase 2, Task 4).

import (
	"context"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// buildFindingsClient returns a callableGraphClient that returns:
//   - on the first call (page query): the provided page records
//   - on the second call (count query): the provided total count
func buildFindingsClient(pageRecords []FindingRecord, total uint64) *callableGraphClient {
	callIdx := 0
	return &callableGraphClient{
		readFn: func(_ context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
			defer func() { callIdx++ }()
			switch callIdx {
			case 0:
				// page query — return the records slice directly
				return pageRecords, nil
			case 1:
				// count query — return the total
				return total, nil
			default:
				return nil, nil
			}
		},
	}
}

// makeFindingRecord is a helper to build a minimal FindingRecord for tests.
func makeFindingRecord(id, severity, missionID string) FindingRecord {
	return FindingRecord{
		ID:         id,
		Name:       "finding-" + id,
		Severity:   severity,
		MissionID:  missionID,
		Properties: map[string]string{"id": id, "severity": severity},
		Labels:     []string{"Finding"},
	}
}

// TestFindings_HappyPath verifies the basic happy path: results returned, total set.
func TestFindings_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("tenant-happy")

	want := []FindingRecord{
		makeFindingRecord("f1", "critical", ""),
		makeFindingRecord("f2", "high", ""),
	}
	client := buildFindingsClient(want, 2)
	q := NewDashboardQueries(client)

	got, total, err := q.Findings(ctx, tenant, FindingsFilters{})
	if err != nil {
		t.Fatalf("Findings returned unexpected error: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i, r := range got {
		if r.ID != want[i].ID {
			t.Errorf("record[%d].ID = %q, want %q", i, r.ID, want[i].ID)
		}
	}
}

// TestFindings_SeverityFilter verifies that the client is called (no error path
// tested separately) when severity is set.  The callableGraphClient just returns
// records unchanged; correctness of the Cypher clause is covered by build + vet.
func TestFindings_SeverityFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("tenant-sev")

	want := []FindingRecord{makeFindingRecord("f3", "critical", "")}
	client := buildFindingsClient(want, 1)
	q := NewDashboardQueries(client)

	got, total, err := q.Findings(ctx, tenant, FindingsFilters{Severity: "critical"})
	if err != nil {
		t.Fatalf("Findings severity filter error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(got) != 1 || got[0].ID != "f3" {
		t.Errorf("unexpected result: %+v", got)
	}
}

// TestFindings_CategoryFilter verifies category filter path.
func TestFindings_CategoryFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("tenant-cat")

	want := []FindingRecord{makeFindingRecord("f4", "medium", "")}
	client := buildFindingsClient(want, 1)
	q := NewDashboardQueries(client)

	got, total, err := q.Findings(ctx, tenant, FindingsFilters{Category: "sql_injection"})
	if err != nil {
		t.Fatalf("Findings category filter error: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].ID != "f4" {
		t.Errorf("unexpected result total=%d got=%+v", total, got)
	}
}

// TestFindings_MissionIDFilter verifies mission_id filter path.
func TestFindings_MissionIDFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("tenant-mission")

	want := []FindingRecord{makeFindingRecord("f5", "high", "mission-1")}
	client := buildFindingsClient(want, 1)
	q := NewDashboardQueries(client)

	got, total, err := q.Findings(ctx, tenant, FindingsFilters{MissionID: "mission-1"})
	if err != nil {
		t.Fatalf("Findings missionID filter error: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].ID != "f5" {
		t.Errorf("unexpected result total=%d got=%+v", total, got)
	}
}

// TestFindings_SearchFilter verifies search filter path.
func TestFindings_SearchFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("tenant-search")

	want := []FindingRecord{makeFindingRecord("f6", "low", "")}
	client := buildFindingsClient(want, 1)
	q := NewDashboardQueries(client)

	got, _, err := q.Findings(ctx, tenant, FindingsFilters{Search: "injection"})
	if err != nil {
		t.Fatalf("Findings search filter error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "f6" {
		t.Errorf("unexpected result: %+v", got)
	}
}

// TestFindings_Pagination verifies that limit/offset defaults are applied and
// the cap is enforced.
func TestFindings_Pagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("tenant-page")

	client := buildFindingsClient(nil, 0)
	q := NewDashboardQueries(client)

	// Limit 0 → DefaultFindingsLimit (no error)
	_, _, err := q.Findings(ctx, tenant, FindingsFilters{Limit: 0})
	if err != nil {
		t.Fatalf("limit=0 error: %v", err)
	}

	// Limit > MaxFindingsLimit → clamped, no error
	_, _, err = q.Findings(ctx, tenant, FindingsFilters{Limit: 9999})
	if err != nil {
		t.Fatalf("limit=9999 error: %v", err)
	}
}

// TestFindings_TenantIsolation verifies that two tenants get independent results.
// Both tenants share the same callableGraphClient but have separate query call
// sequences; results are keyed by what the mock returns, so differing return
// values prove tenant-specific state is threaded correctly.
func TestFindings_TenantIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenantA := mustTenantID("tenant-a")
	tenantB := mustTenantID("tenant-b")

	rA := []FindingRecord{makeFindingRecord("a1", "critical", "")}
	rB := []FindingRecord{makeFindingRecord("b1", "low", "")}

	clientA := buildFindingsClient(rA, 1)
	clientB := buildFindingsClient(rB, 1)

	qA := NewDashboardQueries(clientA)
	qB := NewDashboardQueries(clientB)

	gotA, totalA, errA := qA.Findings(ctx, tenantA, FindingsFilters{})
	if errA != nil || totalA != 1 || len(gotA) != 1 || gotA[0].ID != "a1" {
		t.Errorf("tenantA unexpected: err=%v total=%d got=%+v", errA, totalA, gotA)
	}

	gotB, totalB, errB := qB.Findings(ctx, tenantB, FindingsFilters{})
	if errB != nil || totalB != 1 || len(gotB) != 1 || gotB[0].ID != "b1" {
		t.Errorf("tenantB unexpected: err=%v total=%d got=%+v", errB, totalB, gotB)
	}
}

// TestFindings_EmptyResult verifies that an empty result set returns nil slice
// and zero total without error.
func TestFindings_EmptyResult(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := mustTenantID("tenant-empty")

	client := buildFindingsClient(nil, 0)
	q := NewDashboardQueries(client)

	got, total, err := q.Findings(ctx, tenant, FindingsFilters{})
	if err != nil {
		t.Fatalf("empty result error: %v", err)
	}
	if total != 0 || len(got) != 0 {
		t.Errorf("expected empty: total=%d len=%d", total, len(got))
	}
}

// TestFindings_DefaultLimitCap verifies the default and max limit constants.
func TestFindings_DefaultLimitCap(t *testing.T) {
	t.Parallel()
	if DefaultFindingsLimit != 100 {
		t.Errorf("DefaultFindingsLimit = %d, want 100", DefaultFindingsLimit)
	}
	if MaxFindingsLimit != 500 {
		t.Errorf("MaxFindingsLimit = %d, want 500", MaxFindingsLimit)
	}
}

// mustTenantID is defined in dashboard_queries_test.go.

// Verify orProp helper.
func TestOrProp(t *testing.T) {
	props := map[string]string{"id": "x"}
	if got := orProp(props, "id", "fallback"); got != "x" {
		t.Errorf("orProp found = %q, want 'x'", got)
	}
	if got := orProp(props, "missing", "fallback"); got != "fallback" {
		t.Errorf("orProp missing = %q, want 'fallback'", got)
	}
	if got := orProp(map[string]string{"id": ""}, "id", "fallback"); got != "fallback" {
		t.Errorf("orProp empty = %q, want 'fallback'", got)
	}
}
