// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
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

// The pool-backed read path runs against a real Postgres in
// graph_findings_integration_test.go and pgstore's integration tests. These unit
// tests cover the guard clauses and the format serialisers.
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

// TestFindingToRow verifies the conversion of a stored finding to an export
// row, and that the evidence has its tier only when the export asks for it.
func TestFindingToRow(t *testing.T) {
	t.Parallel()
	f := finding.EnhancedFinding{
		Finding: agent.Finding{
			ID: "5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e", Title: "Test Finding", Severity: agent.SeverityHigh,
			Metadata: map[string]any{"cve": "CVE-1234"},
			Evidence: []*typespb.Evidence{
				{Title: "t", Type: typespb.EvidenceType_EVIDENCE_TYPE_LOG, Content: "recorded",
					Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, ToolCallId: "call-1"},
				{Title: "u", Type: typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION, Content: "typed",
					Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED},
			},
		},
		MissionID: "6c5c9f0f-9f9f-4d9f-8f9f-9f9f9f9f9f9f",
	}

	row := findingToRow(f, false)
	if row.ID != f.ID.String() || row.CVE != "CVE-1234" || row.Severity != "high" || row.MissionID != f.MissionID.String() {
		t.Errorf("row = %+v", row)
	}
	if row.Evidence != nil {
		t.Errorf("evidence is in the row of an export that did not ask for it: %+v", row.Evidence)
	}

	row = findingToRow(f, true)
	if len(row.Evidence) != 2 {
		t.Fatalf("want 2 evidence items, got %d", len(row.Evidence))
	}
	if row.Evidence[0].Tier != 1 || row.Evidence[0].ToolCallID != "call-1" || row.Evidence[0].Content != "recorded" {
		t.Errorf("item 0 = %+v", row.Evidence[0])
	}
	if row.Evidence[1].Tier != 2 || row.Evidence[1].Type != "conversation" {
		t.Errorf("item 1 = %+v", row.Evidence[1])
	}
}

// TestExportFindings_JSONAndSARIFHoldTheTier proves that the JSON and SARIF
// exports show the tier of each evidence item, and that the CSV has no
// evidence column.
func TestExportFindings_JSONAndSARIFHoldTheTier(t *testing.T) {
	t.Parallel()
	rows := []findingExportRow{{
		ID: "f1", Title: "x", Severity: "high",
		Evidence: []exportEvidence{{Type: "log", Content: "c", Tier: 1, ToolCallID: "call-1"}},
	}}

	data, err := serializeJSON(rows, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"tier":1`) || !strings.Contains(string(data), `"toolCallId":"call-1"`) {
		t.Errorf("json export has no tier: %s", data)
	}

	data, err = serializeSARIF(rows)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"tier": 1`) {
		t.Errorf("sarif export has no tier: %s", data)
	}

	data, err = serializeCSV(rows)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "call-1") {
		t.Errorf("csv export holds evidence: %s", data)
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
