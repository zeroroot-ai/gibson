// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"slices"
	"time"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/emitbounds"
	findingpkg "github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// A bank member has no mission, so it has no mission harness. A member finding
// takes its own path: the tenant, the member and the agent come from the
// verified grant of the call, the loop grant is read at the time of the call, and
// the finding is stored and raised as the member (gibson#1612).

// Audit names of a member finding.
const (
	memberFindingAuditAction   = "member.finding.submit"
	memberFindingAuditResource = "finding"
	submitFindingRPCName       = "SubmitFinding"
)

// WithMemberFindings wires the store and the sink of the findings that bank
// members submit. A daemon with neither refuses a member finding.
func WithMemberFindings(store FindingStore, sink FindingSink) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.memberFindings = store
		s.memberFindingSink = sink
	}
}

// memberPrincipal is the principal that a member finding names in SubmittedBy.
func memberPrincipal(m memberCall) string { return "member:" + m.memberID }

// canSubmitFindings reports whether the grant holds the right to submit
// findings.
func (g *LoopGrant) canSubmitFindings() bool {
	return g != nil && slices.Contains(g.HarnessCalls, submitFindingRPCName)
}

func findingErr(code commonpb.ErrorCode, msg string) *harnesspb.SubmitFindingResponse {
	return &harnesspb.SubmitFindingResponse{Error: &harnesspb.HarnessError{Code: code, Message: msg}}
}

// auditMemberFinding writes the audit record of a member finding. The actor is
// the member principal. It returns the error of the write.
func (s *HarnessCallbackService) auditMemberFinding(ctx context.Context, m memberCall, g *LoopGrant, result, findingID, reason string) error {
	if s.connectorAudit == nil {
		return errors.New("the audit log is not wired")
	}
	tid, err := auth.NewTenantID(m.tenant)
	if err != nil {
		return err //nolint:wrapcheck // the caller reports a fixed message
	}
	actx := auth.WithIdentity(ctx, auth.Identity{Subject: memberPrincipal(m), Tenant: tid, CredentialType: auth.CredentialOIDCUser})
	details := map[string]any{"member_id": m.memberID, "agent": m.agent}
	if g != nil {
		details["loop_grant_id"] = g.ID
		details["grantor"] = g.Grantor
	}
	if reason != "" {
		details["reason"] = reason
	}
	_, err = s.connectorAudit.RecordWithResult(actx, memberFindingAuditAction, memberFindingAuditResource, findingID, result, details)
	return err //nolint:wrapcheck // the caller reports a fixed message
}

// submitMemberFinding serves SubmitFinding for a bank member. The loop grant is
// read at the time of the call, so a revoked grant stops the next finding and
// does not wait for the renewal of the token. The finding names the member as its
// submitter, and the event that raises it names the agent of the verified grant.
// Nothing of either comes from the payload.
func (s *HarnessCallbackService) submitMemberFinding(ctx context.Context, req *harnesspb.SubmitFindingRequest, m memberCall) (*harnesspb.SubmitFindingResponse, error) {
	if !m.ownsContext(req.GetContext()) {
		return findingErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "a member call names a mission that the member does not own"), nil
	}
	g, err := s.loopGrant(ctx, m)
	switch {
	case errors.Is(err, ErrNoLoopGrant):
		_ = s.auditMemberFinding(ctx, m, nil, "failure", "", "no_loop_grant")
		return findingErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "this member holds no loop grant"), nil
	case err != nil:
		s.logger.ErrorContext(ctx, "member finding refused: the loop grant could not be read", "err", err)
		return findingErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the loop grant could not be read"), nil
	case !g.canSubmitFindings():
		_ = s.auditMemberFinding(ctx, m, g, "failure", "", "no_finding_right")
		return findingErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "the loop grant of this member does not hold the right to submit findings"), nil
	}
	if s.memberFindings == nil {
		return findingErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "findings of members are not wired on this daemon"), nil
	}

	finding := protoFindingToFinding(req.GetFinding())
	if key := req.GetIdempotencyKey(); key != "" {
		finding.ID = findingpkg.ResultID(m.tenant, memberPrincipal(m), key)
	}
	finding.SubmittedBy = memberPrincipal(m)
	finding.TenantID = m.tenant

	if err := emitbounds.CheckObservation(finding.WithoutRecordedEvidence()); err != nil {
		return findingErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, err.Error()), nil
	}
	// The record of the tool calls of this member. The mission of its calls is
	// its bank, so a call of another member or another tenant is not found.
	recorded, refusal, err := s.recordedFindingEvidence(ctx, m.bankID, req.GetToolCallIds())
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return &harnesspb.SubmitFindingResponse{Error: refusal}, nil
	}
	finding.Evidence = append(recorded, finding.Evidence...)

	// No finding is stored without its record.
	if err := s.auditMemberFinding(ctx, m, g, "success", finding.ID.String(), ""); err != nil {
		s.logger.ErrorContext(ctx, "member finding refused: the audit record could not be written", "err", err)
		return findingErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the audit record of the finding could not be written"), nil
	}
	// A member has no mission. The finding has none, and a rerun of the check is
	// its check.
	var noMission types.ID
	if err := s.memberFindings.Store(ctx, m.tenant, noMission, finding); err != nil {
		if errors.Is(err, emitbounds.ErrLimitExceeded) || evidenceRejected(err) {
			return findingErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, err.Error()), nil
		}
		s.logger.ErrorContext(ctx, "member finding could not be stored", "err", err)
		return findingErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the finding could not be stored. Try again"), nil
	}
	if s.memberFindingSink != nil {
		check := SubmittedFindingCheck(finding, noMission)
		s.memberFindingSink(ctx, FindingRaised{
			Tenant: m.tenant, ID: finding.ID.String(), Title: finding.Title, Description: finding.Description,
			Severity: string(finding.Severity), AgentName: m.agent, SubmittedBy: memberPrincipal(m),
			CheckKind: string(check.Kind), CheckRef: check.Ref, At: time.Now().UTC(),
		})
	}
	return &harnesspb.SubmitFindingResponse{}, nil
}
