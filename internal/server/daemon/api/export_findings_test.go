package api

// export_findings_test.go — unit tests for TenantAdminService.ExportFindings.
//
// Spec: dashboard-neo4j-crud-removal (Phase 2, Task 6).

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// csvRows is used by TestExportFindings_CSV to count and inspect output.
func parseCSSV(t *testing.T, data []byte) [][]string {
	t.Helper()
	r := csv.NewReader(strings.NewReader(string(data)))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	return rows
}

// newExportServer builds a minimal DaemonServer wired with a no-op pool and
// an injected findings result.  The pool is configured to return a conn whose
// Neo4j session is nil; the GraphClient injected via the test mock intercepts
// the DashboardQueries.Findings call instead.
//
// Because Findings is called via the real DashboardQueries (which calls
// ExecuteRead on the session), we need a pool that returns a mockable session.
// For simplicity the test replaces ExportFindings at the findingsFetcher layer
// by using a pool that returns a mockable Conn backed by a mock session.

// For these unit tests we stub out the poolGetter to return nil (which causes
// codes.Unavailable) for the "pool not configured" tests, and for format
// tests we inject a pre-built AllFindings list via a test-only helper.
func newExportServerNoPool() *DaemonServer {
	return &DaemonServer{}
}

// ---------------------------------------------------------------------------
// Pool-nil → Unavailable
// ---------------------------------------------------------------------------

func TestExportFindings_NilPool_Unavailable(t *testing.T) {
	t.Parallel()
	srv := newExportServerNoPool() // poolGetter = nil
	ctx := context.Background()

	_, err := srv.ExportFindings(ctx, &tenantv1.ExportFindingsRequest{TenantId: "t1"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	assertGRPCStatusCode(t, err, "Unavailable")
}

// ---------------------------------------------------------------------------
// Format serialiser unit tests (bypass the handler, test helpers directly)
// ---------------------------------------------------------------------------

func sampleRows() []findingExportRow {
	return []findingExportRow{
		{ID: "f1", Type: "sql_injection", Title: "SQL Injection", Severity: "critical", CVE: "CVE-2023-1234", MissionID: "m1", Description: "Desc1", DiscoveredAt: "2026-01-01T00:00:00Z"},
		{ID: "f2", Type: "xss", Title: "XSS", Severity: "high", MissionID: "", Description: "Desc2", DiscoveredAt: "2026-01-02T00:00:00Z"},
	}
}

// TestExportFindings_CSV verifies the CSV format output.
func TestExportFindings_CSV(t *testing.T) {
	t.Parallel()
	rows := sampleRows()
	data, err := serializeCSV(rows)
	if err != nil {
		t.Fatalf("serializeCSV: %v", err)
	}

	parsed := parseCSSV(t, data)
	// Header + 2 data rows.
	if len(parsed) != 3 {
		t.Fatalf("expected 3 rows (header + 2), got %d", len(parsed))
	}
	// Header check.
	wantHeader := []string{"id", "type", "title", "severity", "cve", "mission_id", "mission_name", "description", "discovered_at"}
	for i, h := range wantHeader {
		if parsed[0][i] != h {
			t.Errorf("header[%d] = %q, want %q", i, parsed[0][i], h)
		}
	}
	// First data row.
	if parsed[1][0] != "f1" {
		t.Errorf("row1 id = %q, want f1", parsed[1][0])
	}
	if parsed[1][3] != "critical" {
		t.Errorf("row1 severity = %q, want critical", parsed[1][3])
	}
}

// TestExportFindings_JSON verifies the JSON format output.
func TestExportFindings_JSON(t *testing.T) {
	t.Parallel()
	rows := sampleRows()
	data, err := serializeJSON(rows, "tenant-x")
	if err != nil {
		t.Fatalf("serializeJSON: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if payload["tenantId"] != "tenant-x" {
		t.Errorf("tenantId = %v, want tenant-x", payload["tenantId"])
	}
	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) != 2 {
		t.Fatalf("findings: expected 2, got %v", payload["findings"])
	}
}

// TestExportFindings_SARIF verifies the SARIF 2.1.0 format output.
func TestExportFindings_SARIF(t *testing.T) {
	t.Parallel()
	rows := sampleRows()
	data, err := serializeSARIF(rows)
	if err != nil {
		t.Fatalf("serializeSARIF: %v", err)
	}

	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(doc.Runs[0].Results))
	}
	// Critical → error level.
	if doc.Runs[0].Results[0].Level != "error" {
		t.Errorf("critical level = %q, want error", doc.Runs[0].Results[0].Level)
	}
	// High → error level.
	if doc.Runs[0].Results[1].Level != "error" {
		t.Errorf("high level = %q, want error", doc.Runs[0].Results[1].Level)
	}
}

// TestSeverityToSARIFLevel verifies severity → SARIF level mapping.
func TestSeverityToSARIFLevel(t *testing.T) {
	t.Parallel()
	cases := []struct{ sev, want string }{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"", "note"},
	}
	for _, tc := range cases {
		got := severityToSARIFLevel(tc.sev)
		if got != tc.want {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

// TestCsvEscape verifies the RFC 4180 CSV escaping.
func TestCsvEscape(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"simple", "simple"},
		{"with,comma", `"with,comma"`},
		{`with"quote`, `"with""quote"`},
		{"with\nnewline", "\"with\nnewline\""},
		{"", ""},
	}
	for _, tc := range cases {
		got := csvEscape(tc.in)
		if got != tc.want {
			t.Errorf("csvEscape(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRecordToRow verifies FindingRecord → findingExportRow conversion.
func TestRecordToRow(t *testing.T) {
	t.Parallel()
	r := graph.FindingRecord{
		ID:         "f99",
		Name:       "Test Finding",
		Severity:   "high",
		MissionID:  "m1",
		Properties: map[string]string{"cve": "CVE-1234"},
	}
	row := recordToRow(r)
	if row.ID != "f99" {
		t.Errorf("ID = %q, want f99", row.ID)
	}
	if row.CVE != "CVE-1234" {
		t.Errorf("CVE = %q, want CVE-1234", row.CVE)
	}
}

// assertGRPCStatusCode is a minimal helper for tests that don't import the
// codes package directly. It checks that the error string contains the code name.
func assertGRPCStatusCode(t *testing.T, err error, codeName string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", codeName)
	}
	if !strings.Contains(err.Error(), strings.ToLower(codeName)) &&
		!strings.Contains(err.Error(), codeName) {
		t.Errorf("error %q does not contain code %s", err.Error(), codeName)
	}
}
