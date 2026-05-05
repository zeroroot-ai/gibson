// Package harness — daemon-side callback handlers for the three
// mission-memory RPCs that landed in v0.103.0:
//
//   - GetMissionRunHistory     headline-feature-completion R6.2
//   - GetPreviousRunFindings   headline-feature-completion R6.2
//   - GetAllRunFindings        headline-feature-completion R6.2
//
// Each handler resolves the calling agent's harness via
// HarnessCallbackService.getHarness (which enforces mission-id +
// agent-name + tenant scoping), then delegates to the harness's
// existing GetMissionRunHistory / GetPreviousRunFindings /
// GetAllRunFindings methods. The harness wires these onto the per-tenant
// MissionRunStore + FindingStore.
//
// The handlers are tenant-scoped through the upstream getHarness call
// (which performs the cross-tenant rejection) — there is no additional
// tenant filtering needed here. FGA registry annotations live in the
// canonical SDK proto and were folded into internal/authz/registry/* by
// `make authz-registry`.
package harness

import (
	"context"

	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zero-day-ai/sdk/api/gen/gibson/types/v1"
)

// allRunFindingsCap caps the size of an aggregated GetAllRunFindings
// response page when the caller does not specify page_size. The cap
// matches the Spec 5 R6 acceptance criterion ("at most 1000 findings
// per page; further pages via page_token").
const allRunFindingsCap = 1000

// GetMissionRunHistory returns the chronological run history for the
// mission carried in the request's `context`. The list is ordered
// oldest-first per the proto contract.
func (s *HarnessCallbackService) GetMissionRunHistory(
	ctx context.Context,
	req *harnesspb.GetMissionRunHistoryRequest,
) (*harnesspb.GetMissionRunHistoryResponse, error) {
	harness, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}

	internalRuns, hErr := harness.GetMissionRunHistory(ctx)
	if hErr != nil {
		s.logger.Error("GetMissionRunHistory: harness call failed",
			"mission_id", req.GetContext().GetMissionId(),
			"error", hErr,
		)
		return &harnesspb.GetMissionRunHistoryResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: hErr.Error(),
			},
		}, nil
	}

	// Translate internal SDK summary type to proto wire type.
	// The proto contract returns oldest-first; the harness returns
	// newest-first (run_number DESC), so we reverse here.
	limit := int(req.GetLimit())
	out := make([]*harnesspb.MissionRunSummary, 0, len(internalRuns))
	for i := len(internalRuns) - 1; i >= 0; i-- {
		r := internalRuns[i]
		summary := &harnesspb.MissionRunSummary{
			MissionId:     r.MissionID,
			RunNumber:     int32(r.RunNumber),
			Status:        r.Status,
			FindingsCount: int32(r.FindingsCount),
			CreatedAtUnix: r.CreatedAt.Unix(),
		}
		if r.CompletedAt != nil {
			summary.CompletedAtUnix = r.CompletedAt.Unix()
		}
		out = append(out, summary)

		if limit > 0 && len(out) >= limit {
			break
		}
	}

	s.logger.Debug("GetMissionRunHistory: returning runs",
		"mission_id", req.GetContext().GetMissionId(),
		"count", len(out),
		"limit", limit,
	)

	return &harnesspb.GetMissionRunHistoryResponse{Runs: out}, nil
}

// GetPreviousRunFindings returns the findings produced by the immediate
// prior run of the mission carried in `context`. Empty findings list
// when there is no prior run.
func (s *HarnessCallbackService) GetPreviousRunFindings(
	ctx context.Context,
	req *harnesspb.GetPreviousRunFindingsRequest,
) (*harnesspb.GetPreviousRunFindingsResponse, error) {
	harness, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}

	filter := protoFilterToFindingFilter(req.GetFilter())

	internalFindings, hErr := harness.GetPreviousRunFindings(ctx, filter)
	if hErr != nil {
		s.logger.Error("GetPreviousRunFindings: harness call failed",
			"mission_id", req.GetContext().GetMissionId(),
			"error", hErr,
		)
		return &harnesspb.GetPreviousRunFindingsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: hErr.Error(),
			},
		}, nil
	}

	out := make([]*typespb.Finding, len(internalFindings))
	for i, f := range internalFindings {
		out[i] = findingToProtoFinding(f)
	}

	s.logger.Debug("GetPreviousRunFindings: returning findings",
		"mission_id", req.GetContext().GetMissionId(),
		"count", len(out),
	)

	return &harnesspb.GetPreviousRunFindingsResponse{Findings: out}, nil
}

// GetAllRunFindings returns one page of findings aggregated across every
// prior run of the mission carried in `context`. The method honours the
// proto's page_size + page_token contract; on the daemon side, paging
// is implemented as a simple offset-cursor over the harness's flat
// aggregated slice (the harness already coalesces per-run results).
//
// Caps responses at allRunFindingsCap to avoid OOM on missions with
// large historical finding counts.
func (s *HarnessCallbackService) GetAllRunFindings(
	ctx context.Context,
	req *harnesspb.GetAllRunFindingsRequest,
) (*harnesspb.GetAllRunFindingsResponse, error) {
	harness, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}

	filter := protoFilterToFindingFilter(req.GetFilter())

	internalFindings, hErr := harness.GetAllRunFindings(ctx, filter)
	if hErr != nil {
		s.logger.Error("GetAllRunFindings: harness call failed",
			"mission_id", req.GetContext().GetMissionId(),
			"error", hErr,
		)
		return &harnesspb.GetAllRunFindingsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: hErr.Error(),
			},
		}, nil
	}

	// Page: parse offset cursor from page_token, slice into the
	// aggregated findings, build next_page_token.
	offset := parseOffsetToken(req.GetPageToken())
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 || pageSize > allRunFindingsCap {
		pageSize = allRunFindingsCap
	}

	end := offset + pageSize
	if end > len(internalFindings) {
		end = len(internalFindings)
	}
	if offset > len(internalFindings) {
		offset = len(internalFindings)
	}

	page := internalFindings[offset:end]
	out := make([]*typespb.Finding, len(page))
	for i, f := range page {
		out[i] = findingToProtoFinding(f)
	}

	nextToken := ""
	if end < len(internalFindings) {
		nextToken = formatOffsetToken(end)
	}

	s.logger.Debug("GetAllRunFindings: returning findings page",
		"mission_id", req.GetContext().GetMissionId(),
		"offset", offset,
		"page_size", pageSize,
		"returned", len(out),
		"total", len(internalFindings),
		"has_next", nextToken != "",
	)

	return &harnesspb.GetAllRunFindingsResponse{
		Findings:      out,
		NextPageToken: nextToken,
	}, nil
}

// parseOffsetToken decodes a daemon-internal page_token. The token format
// is intentionally opaque to the client — we use a simple `offset:N`
// encoding so the cursor is human-readable in logs but treated as a
// black box by the SDK. Bad tokens return offset=0 (start of page).
func parseOffsetToken(token string) int {
	if token == "" {
		return 0
	}
	n := 0
	const prefix = "offset:"
	if len(token) <= len(prefix) || token[:len(prefix)] != prefix {
		return 0
	}
	for i := len(prefix); i < len(token); i++ {
		c := token[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n < 0 {
			return 0 // overflow
		}
	}
	return n
}

// formatOffsetToken encodes an offset as the daemon's opaque cursor.
func formatOffsetToken(offset int) string {
	if offset <= 0 {
		return ""
	}
	// strconv-free formatting to avoid an extra import.
	if offset == 0 {
		return "offset:0"
	}
	digits := make([]byte, 0, 12)
	for offset > 0 {
		digits = append([]byte{byte('0' + offset%10)}, digits...)
		offset /= 10
	}
	return "offset:" + string(digits)
}
