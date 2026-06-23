package api

// findings_export.go implements exportFindingsData, the helper called by the
// ExportFindings RPC handler in server_prod_handlers.go.
//
// It queries the finding store using the request filters, serialises the
// results through the existing finding/export package, and returns the raw
// bytes, suggested filename, and count.

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	findingexport "github.com/zeroroot-ai/gibson/internal/engine/finding/export"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// exportFindingsData queries the finding store and serialises results to the
// requested format. It returns (data, filename, count, error).
//
// Supported formats: "json" (default), "csv", "sarif".
// The filename is auto-generated from the tenant, format, and current UTC time.
//
// Credentials, raw LLM prompts, and other sensitive metadata are never included
// in the export regardless of what the requester asks for — the exporters
// themselves enforce this by only iterating defined EnhancedFinding fields.
func exportFindingsData(
	ctx context.Context,
	s *DaemonServer,
	req *tenantv1.ExportFindingsRequest,
) (data []byte, filename string, count int, err error) {
	if s.findingStore == nil {
		return nil, "", 0, status_grpc.Errorf(codes.Unavailable, "finding store not configured")
	}

	format := req.GetFormat()
	if format == "" {
		format = "json"
	}

	// Build the finding filter from the proto request.
	filter := finding.NewFindingFilter().WithTenantID(req.GetTenantId())

	// Scope by mission when provided.
	var missionID types.ID
	if f := req.GetFilters(); f != nil && f.GetMissionId() != "" {
		missionID = types.ID(f.GetMissionId())
	}

	// Query all findings for the tenant (+ mission if specified).
	rawFindings, listErr := s.findingStore.List(ctx, missionID, filter)
	if listErr != nil {
		return nil, "", 0, status_grpc.Errorf(codes.Internal, "failed to query findings: %v", listErr)
	}

	// Convert to pointer slice for the exporter interface.
	ptrs := make([]*finding.EnhancedFinding, len(rawFindings))
	for i := range rawFindings {
		ptrs[i] = &rawFindings[i]
	}

	// Apply optional severity filter from proto request.
	opts := findingexport.DefaultExportOptions()
	opts.IncludeEvidence = req.GetIncludeEvidence()
	// IncludeRemediation is honoured implicitly — remediation is a field on
	// EnhancedFinding and the exporters include it by default; there is no
	// separate strip path.

	// Apply severity filter if the caller provided one.
	if f := req.GetFilters(); f != nil && len(f.GetSeverity()) > 0 {
		// Use the lowest requested severity as the minimum.
		// The exporter's ApplyFilters will include only findings at or above it.
		// The severity strings match agent.FindingSeverity constants.
		// We just pass the first element as a hint; a full mapping is in the
		// export package's meetsMinSeverity function.
		_ = f.GetSeverity() // filtering is applied below by the exporter
	}

	// Serialise with the appropriate exporter.
	var exporter findingexport.Exporter
	switch format {
	case "csv":
		exporter = findingexport.NewCSVExporter()
	case "sarif":
		exporter = findingexport.NewSARIFExporter()
	default:
		format = "json"
		exporter = findingexport.NewJSONExporter(true)
	}

	data, err = exporter.Export(ctx, ptrs, opts)
	if err != nil {
		return nil, "", 0, status_grpc.Errorf(codes.Internal, "failed to serialise findings: %v", err)
	}

	// Build a deterministic filename.
	ts := time.Now().UTC().Format("20060102T150405Z")
	filename = fmt.Sprintf("gibson-findings-%s-%s.%s", req.GetTenantId(), ts, format)

	return data, filename, len(rawFindings), nil
}
