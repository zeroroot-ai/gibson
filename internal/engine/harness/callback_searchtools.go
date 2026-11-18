// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// SearchTools implements the connector-catalog discovery RPC (ADR-0065):
// it returns a small, ranked, authz-filtered set of tools matching the query.
//
// The caller subject is derived exactly as the Authorize handler does —
// "user:<run UserID>" from the run's authz state — so the can_execute
// filter matches the gate the eventual invocation enforces. Per-tool
// authorization is the catalog FGAAuthorizer's job; this handler does not invent
// an authz path. Tenant scoping comes from the run's TenantID.
func (s *HarnessCallbackService) SearchTools(ctx context.Context, req *harnesspb.SearchToolsRequest) (*harnesspb.SearchToolsResponse, error) {
	if s.componentRegistry == nil || s.componentAuthorizer == nil || s.authzStore == nil {
		return nil, status.Error(codes.Unavailable, "SearchTools: catalog search is not wired on this daemon")
	}

	runID := req.GetContext().GetMissionRunId()
	if runID == "" {
		runID = req.GetContext().GetAgentRunId()
	}
	if runID == "" {
		return nil, status.Error(codes.InvalidArgument, "SearchTools: context mission_run_id or agent_run_id is required")
	}

	state, err := s.authzStore.Get(ctx, runID)
	if err != nil {
		s.logger.WarnContext(ctx, "SearchTools: run authz state not found", "run_id", runID, "err", err)
		return searchToolsErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "run authz state not found"), nil
	}
	if state.Status != "active" {
		return searchToolsErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "mission run is not active"), nil
	}

	// A mission that denies an Agent Skill does not find it. The deny list is
	// read only when Agent Skills are wired, because an unread list is not an
	// empty one.
	var hide func(toolid.ID) bool
	if s.agentSkillStore() != nil {
		policy, perr := s.policyFromState(ctx, state)
		if perr != nil {
			s.logger.ErrorContext(ctx, "SearchTools: the mission policy could not be loaded", "run_id", runID, "err", perr)
			return searchToolsErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the mission policy could not be loaded"), nil
		}
		hide = hideBlockedSkills(policy.Blocked)
	}

	engine := catalog.NewEngine(
		s.toolLister(component.NewCatalogToolLister(s.componentRegistry, s.connectors)),
		catalog.NewFGAAuthorizer(s.componentAuthorizer),
	)
	caller := catalogCaller(ctx, state)

	candidates, err := engine.Search(ctx, caller, catalog.Query{
		Text:      req.GetQuery(),
		Sources:   toToolSources(req.GetSources()),
		Connector: req.GetConnector(),
		Limit:     int(req.GetLimit()),
		Hide:      hide,
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "SearchTools: search failed", "tenant", state.TenantID, "err", err)
		return searchToolsErr(commonpb.ErrorCode_ERROR_CODE_INTERNAL, "tool search failed"), nil
	}

	out := make([]*harnesspb.SearchToolsCandidate, len(candidates))
	for i, c := range candidates {
		out[i] = &harnesspb.SearchToolsCandidate{
			Id:              c.ID,
			Source:          c.Source,
			Connector:       c.Connector,
			Tool:            c.Tool,
			Description:     c.Description,
			InputSchemaJson: string(c.InputSchema),
		}
	}
	return &harnesspb.SearchToolsResponse{Candidates: out}, nil
}

// toToolSources maps wire source strings ("mcp", "native", "skill") to toolid.Source,
// dropping unrecognized values (the engine treats an empty filter as "all").
func toToolSources(ss []string) []toolid.Source {
	if len(ss) == 0 {
		return nil
	}
	out := make([]toolid.Source, 0, len(ss))
	for _, s := range ss {
		switch toolid.Source(s) {
		case toolid.SourceMCP:
			out = append(out, toolid.SourceMCP)
		case toolid.SourceNative:
			out = append(out, toolid.SourceNative)
		case toolid.SourceSkill:
			out = append(out, toolid.SourceSkill)
		}
	}
	return out
}

func searchToolsErr(code commonpb.ErrorCode, msg string) *harnesspb.SearchToolsResponse {
	return &harnesspb.SearchToolsResponse{
		Error: &harnesspb.HarnessError{Code: code, Message: msg},
	}
}
