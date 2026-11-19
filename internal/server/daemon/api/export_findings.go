// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — export_findings.go implements TenantAdminService.ExportFindings.
//
// This handler replaces the deferred stub that was in deferred_stubs.go.
// It reads findings from the findings table of the Postgres database of the
// tenant, with all evidence of each finding when the request asks for it, and
// serialises them to CSV, JSON, or SARIF format. The CSV columns match the
// dashboard route at zeroroot-ai/dashboard app/api/findings/export/route.ts.
// This is the one export path of findings.
//
// Spec: dashboard-neo4j-crud-removal (Phase 2, Task 6).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// exportMaxBytes is the server-side cap on the serialised export payload.
	// If the assembled buffer exceeds this, the handler returns ResourceExhausted.
	exportMaxBytes = 50 * 1024 * 1024 // 50 MB

	// exportBatchSize is the number of findings fetched per query.
	exportBatchSize = 500
)

// ExportFindings implements TenantAdminService.ExportFindings.
// It takes the tenant from the authenticated context, pages through the findings
// of the tenant in Postgres with pgstore, and serialises to CSV / JSON / SARIF.
// Total response body is capped at exportMaxBytes.
func (s *DaemonServer) ExportFindings(ctx context.Context, req *tenantv1.ExportFindingsRequest) (*tenantv1.ExportFindingsResponse, error) {
	if s.poolGetter == nil {
		return nil, status_grpc.Error(codes.Unavailable, "ExportFindings: data-plane pool not configured")
	}

	pool := s.poolGetter()
	if pool == nil {
		return nil, status_grpc.Error(codes.Unavailable, "ExportFindings: data-plane pool not yet ready")
	}

	// Resolve tenant from the context set by ext-authz, and only from there.
	// The request's tenant_id field is not consulted: ext-authz derives this
	// RPC's authorization object from the caller's identity, so a body tenant
	// id is authorized by nothing. A call with no derivable tenant is denied
	// upstream, so this branch is unreachable for a real caller — it fails
	// closed rather than reaching for the wire value.
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, status_grpc.Error(codes.PermissionDenied, "ExportFindings: missing tenant in context")
	}

	// Build the query from the request. An export holds each finding that
	// matches, with all of its evidence when include_evidence is true.
	// An ID that is not a UUID is a caller error. The database would refuse
	// it, and the caller would get an internal error.
	if id := req.GetFilters().GetMissionId(); id != "" {
		if _, err := types.ParseID(id); err != nil {
			return nil, status_grpc.Error(codes.InvalidArgument, "ExportFindings: filters.mission_id is not a UUID")
		}
	}
	query := tenantv1FindingFiltersToQuery(req.GetFilters())
	for _, id := range req.GetFindingIds() {
		findingID, err := types.ParseID(id)
		if err != nil {
			return nil, status_grpc.Error(codes.InvalidArgument, "ExportFindings: a finding ID is not a UUID")
		}
		query.IDs = append(query.IDs, findingID)
	}
	store := pgstore.New(func() datapool.Pool { return pool })
	find := store.Find
	if req.GetIncludeEvidence() {
		find = store.FindWithEvidence
	}

	// Page through all findings.
	var allFindings []finding.EnhancedFinding
	for {
		query.Limit = exportBatchSize
		query.Offset = len(allFindings)
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		batch, _, err := find(qctx, tenantID.String(), query)
		cancel()
		if err != nil {
			var notProvisioned *datapool.NotProvisionedError
			var evicted *datapool.EvictedError
			if errors.As(err, &notProvisioned) || errors.As(err, &evicted) {
				return nil, fmt.Errorf("export findings: %w", datapool.MapPoolError(err))
			}
			return nil, status_grpc.Errorf(codes.Internal, "ExportFindings: findings query failed: %v", err)
		}
		allFindings = append(allFindings, batch...)
		if len(batch) < exportBatchSize {
			break
		}
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
	data, err := serializeFindings(format, allFindings, tenantID.String(), req.GetIncludeEvidence())
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

// tenantv1FindingFiltersToQuery maps a proto FindingFilters to a finding query.
// The type filter selects the category of the finding. Only the first type is
// used, as before.
func tenantv1FindingFiltersToQuery(f *tenantv1.FindingFilters) pgstore.Query {
	if f == nil {
		return pgstore.Query{}
	}
	q := pgstore.Query{
		Severities: f.GetSeverity(),
		Search:     f.GetSearch(),
	}
	if len(f.GetType()) > 0 {
		q.Category = f.GetType()[0]
	}
	if id := f.GetMissionId(); id != "" {
		q.MissionID = types.ID(id)
	}
	return q
}

// ---------------------------------------------------------------------------
// Format serialisers — ported byte-for-byte from
// zeroroot-ai/dashboard app/api/findings/export/route.ts
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
	// Evidence holds every evidence item of the finding, as stored. It is nil
	// when the export does not include evidence.
	Evidence []exportEvidence
}

// exportEvidence is one evidence item in an export. It shows the tier and, on a
// tier 1 item, the ID of the tool call that backs it.
type exportEvidence struct {
	Type       string            `json:"type"`
	Title      string            `json:"title"`
	Content    string            `json:"content"`
	Tier       int               `json:"tier"`
	ToolCallID string            `json:"toolCallId,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func findingToRow(f finding.EnhancedFinding, includeEvidence bool) findingExportRow {
	cve, _ := f.Metadata["cve"].(string)
	row := findingExportRow{
		ID:          f.ID.String(),
		Type:        "finding",
		Title:       f.Title,
		Severity:    string(f.Severity),
		CVE:         cve,
		MissionID:   f.MissionID.String(),
		Description: f.Description,
	}
	if !f.CreatedAt.IsZero() {
		row.DiscoveredAt = f.CreatedAt.UTC().Format(time.RFC3339)
	}
	if includeEvidence {
		row.Evidence = make([]exportEvidence, len(f.Evidence))
		for i, e := range f.Evidence {
			row.Evidence[i] = exportEvidence{
				Type:       string(finding.EvidenceTypeName(e.GetType())),
				Title:      e.GetTitle(),
				Content:    e.GetContent(),
				Tier:       int(e.GetTier()),
				ToolCallID: e.GetToolCallId(),
				Metadata:   e.GetMetadata(),
			}
		}
	}
	return row
}

func serializeFindings(format string, records []finding.EnhancedFinding, tenantID string, includeEvidence bool) ([]byte, error) {
	rows := make([]findingExportRow, len(records))
	for i, r := range records {
		rows[i] = findingToRow(r, includeEvidence)
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
	// Evidence is present when the export includes evidence. Each item has its
	// tier.
	Evidence []exportEvidence `json:"evidence,omitempty"`
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
			Evidence:     r.Evidence,
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
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifMessage     `json:"message"`
	Properties *sarifProperties `json:"properties,omitempty"`
}

// sarifProperties holds the evidence of a result. Each item has its tier.
type sarifProperties struct {
	Evidence []exportEvidence `json:"evidence"`
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
		result := sarifResult{
			RuleID:  r.ID,
			Level:   severityToSARIFLevel(r.Severity),
			Message: sarifMessage{Text: msg},
		}
		if len(r.Evidence) > 0 {
			result.Properties = &sarifProperties{Evidence: r.Evidence}
		}
		results = append(results, result)
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
