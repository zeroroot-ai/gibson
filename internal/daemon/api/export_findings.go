// Package api — export_findings.go implements TenantAdminService.ExportFindings.
//
// This handler replaces the deferred stub that was in deferred_stubs.go.
// It fetches findings from per-tenant Neo4j via DashboardQueries.Findings
// (same Cypher path as GraphService.GetFindings) and serialises them to
// CSV, JSON, or SARIF format, ported byte-for-byte from the dashboard route at
// enterprise/platform/dashboard/app/api/findings/export/route.ts.
//
// Spec: dashboard-neo4j-crud-removal (Phase 2, Task 6).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/tenant/v1"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/sdk/auth"
)

const (
	// exportMaxBytes is the server-side cap on the serialised export payload.
	// If the assembled buffer exceeds this, the handler returns ResourceExhausted.
	exportMaxBytes = 50 * 1024 * 1024 // 50 MB

	// exportBatchSize is the number of findings fetched per DashboardQueries.Findings call.
	exportBatchSize uint32 = 500
)

// ExportFindings implements TenantAdminService.ExportFindings.
// It reads the tenant from the request tenant_id field (admin callers supply
// this explicitly), acquires a per-tenant Neo4j session via poolGetter, pages
// through all findings using DashboardQueries.Findings, and serialises to
// CSV / JSON / SARIF.  Total response body is capped at exportMaxBytes.
func (s *DaemonServer) ExportFindings(ctx context.Context, req *tenantv1.ExportFindingsRequest) (*tenantv1.ExportFindingsResponse, error) {
	if s.poolGetter == nil {
		return nil, status_grpc.Error(codes.Unavailable, "ExportFindings: data-plane pool not configured")
	}

	pool := s.poolGetter()
	if pool == nil {
		return nil, status_grpc.Error(codes.Unavailable, "ExportFindings: data-plane pool not yet ready")
	}

	// Resolve tenant: prefer the context tenant (set by ext-authz); fall back
	// to the req.tenant_id field for admin callers that supply it explicitly.
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		if req.GetTenantId() == "" {
			return nil, status_grpc.Error(codes.PermissionDenied, "ExportFindings: missing tenant in context")
		}
		var err error
		tenantID, err = auth.NewTenantID(req.GetTenantId())
		if err != nil {
			return nil, status_grpc.Errorf(codes.InvalidArgument, "ExportFindings: invalid tenant_id: %v", err)
		}
	}

	conn, connErr := pool.For(ctx, tenantID)
	if connErr != nil {
		return nil, datapool.MapPoolError(connErr)
	}
	defer conn.Release()

	// Build filters from request.
	filters := tenantv1FindingFiltersToGraph(req.GetFilters())

	// Page through all findings.
	var allFindings []graph.FindingRecord
	var offset uint32
	for {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		filters.Limit = exportBatchSize
		filters.Offset = offset
		q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
		batch, _, err := q.Findings(qctx, tenantID, filters)
		cancel()
		if err != nil {
			return nil, status_grpc.Errorf(codes.Internal, "ExportFindings: findings query failed: %v", err)
		}
		allFindings = append(allFindings, batch...)
		if uint32(len(batch)) < exportBatchSize {
			break
		}
		offset += exportBatchSize
	}

	// Determine format.
	format := strings.ToLower(strings.TrimSpace(req.GetFormat()))
	if format == "" {
		format = "json"
	}
	switch format {
	case "csv", "json", "sarif":
	default:
		return nil, status_grpc.Errorf(codes.InvalidArgument, "ExportFindings: unsupported format %q; use csv, json, or sarif", format)
	}

	// Serialise.
	data, err := serializeFindings(format, allFindings, tenantID.String())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "ExportFindings: serialization failed: %v", err)
	}

	if len(data) > exportMaxBytes {
		return nil, status_grpc.Errorf(codes.ResourceExhausted,
			"ExportFindings: export size (%d bytes) exceeds 50 MB limit; narrow your filters or request a smaller date range",
			len(data))
	}

	dateStr := time.Now().UTC().Format("2006-01-02")
	filename := fmt.Sprintf("findings-%s-%s.%s", tenantID.String(), dateStr, format)

	return &tenantv1.ExportFindingsResponse{
		Data:     data,
		Format:   format,
		Filename: filename,
		Count:    int32(len(allFindings)),
	}, nil
}

// tenantv1FindingFiltersToGraph maps a proto FindingFilters to the graph
// package's FindingsFilters.  The FindingFilters.severity is a repeated field;
// we use the first element if present (the Cypher layer does exact-match).
func tenantv1FindingFiltersToGraph(f *tenantv1.FindingFilters) graph.FindingsFilters {
	if f == nil {
		return graph.FindingsFilters{}
	}
	sev := ""
	if len(f.GetSeverity()) > 0 {
		sev = f.GetSeverity()[0]
	}
	cat := ""
	if len(f.GetType()) > 0 {
		cat = f.GetType()[0]
	}
	return graph.FindingsFilters{
		Severity:  sev,
		Category:  cat,
		MissionID: f.GetMissionId(),
		Search:    f.GetSearch(),
	}
}

// ---------------------------------------------------------------------------
// Format serialisers — ported byte-for-byte from
// enterprise/platform/dashboard/app/api/findings/export/route.ts
// ---------------------------------------------------------------------------

// findingExportRow is the common intermediate representation used by all three
// format serialisers.  Field order matches the TypeScript interface FindingRow.
type findingExportRow struct {
	ID           string
	Type         string
	Title        string
	Severity     string
	CVE          string
	MissionID    string
	MissionName  string
	Description  string
	DiscoveredAt string
}

func recordToRow(r graph.FindingRecord) findingExportRow {
	discoveredAt := ""
	if !r.CreatedAt.IsZero() {
		discoveredAt = r.CreatedAt.UTC().Format(time.RFC3339)
	} else if v, ok := r.Properties["discoveredAt"]; ok {
		discoveredAt = v
	}
	return findingExportRow{
		ID:           r.ID,
		Type:         r.Type,
		Title:        r.Name,
		Severity:     r.Severity,
		CVE:          r.Properties["cve"],
		MissionID:    r.MissionID,
		MissionName:  r.Properties["missionName"],
		Description:  r.Description,
		DiscoveredAt: discoveredAt,
	}
}

func serializeFindings(format string, records []graph.FindingRecord, tenantID string) ([]byte, error) {
	rows := make([]findingExportRow, len(records))
	for i, r := range records {
		rows[i] = recordToRow(r)
	}
	switch format {
	case "csv":
		return serializeCSV(rows)
	case "sarif":
		return serializeSARIF(rows)
	default:
		return serializeJSON(rows, tenantID)
	}
}

// csvEscape escapes a string value for RFC 4180 CSV.
func csvEscape(s string) string {
	if s == "" {
		return ""
	}
	if strings.ContainsAny(s, "\",\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

const csvHeader = "id,type,title,severity,cve,mission_id,mission_name,description,discovered_at\n"

func rowToCSV(r findingExportRow) string {
	return strings.Join([]string{
		csvEscape(r.ID),
		csvEscape(r.Type),
		csvEscape(r.Title),
		csvEscape(r.Severity),
		csvEscape(r.CVE),
		csvEscape(r.MissionID),
		csvEscape(r.MissionName),
		csvEscape(r.Description),
		csvEscape(r.DiscoveredAt),
	}, ",") + "\n"
}

func serializeCSV(rows []findingExportRow) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(csvHeader)
	for _, r := range rows {
		buf.WriteString(rowToCSV(r))
	}
	return buf.Bytes(), nil
}

// jsonFindingRow is the JSON-exported shape; matches FindingRow from route.ts.
type jsonFindingRow struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	CVE          string `json:"cve"`
	MissionID    string `json:"missionId"`
	MissionName  string `json:"missionName"`
	Description  string `json:"description"`
	DiscoveredAt string `json:"discoveredAt"`
}

func serializeJSON(rows []findingExportRow, tenantID string) ([]byte, error) {
	jsonRows := make([]jsonFindingRow, len(rows))
	for i, r := range rows {
		jsonRows[i] = jsonFindingRow{
			ID:           r.ID,
			Type:         r.Type,
			Title:        r.Title,
			Severity:     r.Severity,
			CVE:          r.CVE,
			MissionID:    r.MissionID,
			MissionName:  r.MissionName,
			Description:  r.Description,
			DiscoveredAt: r.DiscoveredAt,
		}
	}
	payload := map[string]any{
		"tenantId":   tenantID,
		"exportedAt": time.Now().UTC().Format(time.RFC3339),
		"count":      len(rows),
		"findings":   jsonRows,
	}
	return json.Marshal(payload)
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0 serialiser
// ---------------------------------------------------------------------------

// sarifDoc is the minimal SARIF 2.1.0 envelope sufficient for security tooling.
type sarifDoc struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func severityToSARIFLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func serializeSARIF(rows []findingExportRow) ([]byte, error) {
	results := make([]sarifResult, 0, len(rows))
	for _, r := range rows {
		msg := r.Title
		if r.Description != "" {
			msg = r.Title + ": " + r.Description
		}
		results = append(results, sarifResult{
			RuleID:  r.ID,
			Level:   severityToSARIFLevel(r.Severity),
			Message: sarifMessage{Text: msg},
		})
	}
	doc := sarifDoc{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool:    sarifTool{Driver: sarifDriver{Name: "Gibson", Version: "1.0"}},
				Results: results,
			},
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}
