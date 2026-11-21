// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/incidentreport"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// IncidentReportService serves GetIncidentReport (ADR-0180, gibson#1480). The
// reader does the work. This type maps the request, the errors and the
// response. The reader takes the tenant from the context, so the request has
// no tenant field.
type IncidentReportService struct {
	tenantv1.UnimplementedIncidentReportServiceServer

	reader *incidentreport.Reader
	logger *slog.Logger
}

// NewIncidentReportService returns the service over reader. A nil logger
// means slog.Default.
func NewIncidentReportService(reader *incidentreport.Reader, logger *slog.Logger) *IncidentReportService {
	if logger == nil {
		logger = slog.Default()
	}
	return &IncidentReportService{reader: reader, logger: logger}
}

// GetIncidentReport returns the report of one incident of the tenant of the caller.
func (s *IncidentReportService) GetIncidentReport(
	ctx context.Context, req *tenantv1.GetIncidentReportRequest,
) (*tenantv1.GetIncidentReportResponse, error) {
	rep, err := s.reader.Report(ctx, req.GetIncidentKey())
	if err != nil {
		return nil, s.incidentReportStatus(ctx, err)
	}
	return incidentReportResponse(rep), nil
}

func (s *IncidentReportService) incidentReportStatus(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, incidentreport.ErrInvalidQuery):
		return status_grpc.Error(codes.InvalidArgument, "GetIncidentReport: the incident key is empty or too long")
	case errors.Is(err, incidentreport.ErrNotFound):
		return status_grpc.Error(codes.NotFound, "GetIncidentReport: the tenant has no such incident")
	case errors.Is(err, incidentreport.ErrNoTenant):
		return status_grpc.Error(codes.PermissionDenied, "GetIncidentReport: missing tenant in context")
	default:
		// The cause stays in the daemon log. The caller gets a fixed text, so
		// no internal detail leaves the daemon (review m20).
		s.logger.ErrorContext(ctx, "incident report read failed", "error", err)
		return status_grpc.Error(codes.Unavailable, "GetIncidentReport: the report cannot be read now")
	}
}

func replayFrame(f incidentreport.Frame) *tenantv1.ReplayFrame {
	return &tenantv1.ReplayFrame{Known: f.Known, TimelineSeq: f.TimelineSeq, ReplaySeq: f.ReplaySeq}
}

var incidentOutcomes = map[incidentreport.Outcome]tenantv1.IncidentAction_Outcome{
	incidentreport.OutcomeDone:    tenantv1.IncidentAction_OUTCOME_DONE,
	incidentreport.OutcomeRefused: tenantv1.IncidentAction_OUTCOME_REFUSED,
	incidentreport.OutcomePending: tenantv1.IncidentAction_OUTCOME_PENDING_AUTHORIZATION,
	incidentreport.OutcomeFailed:  tenantv1.IncidentAction_OUTCOME_FAILED,
}

// incidentReportResponse maps the report onto the wire shape. It reads no store,
// so a test can run it with a plain report.
func incidentReportResponse(rep *incidentreport.Report) *tenantv1.GetIncidentReportResponse {
	out := &tenantv1.GetIncidentReportResponse{
		IncidentKey:   rep.IncidentKey,
		ControlIds:    rep.ControlIDs(),
		TimelineTotal: rep.TimelineTotal,
	}
	for _, a := range rep.Alerts {
		out.Alerts = append(out.Alerts, &tenantv1.IncidentAlert{
			Key: a.Key, Title: a.Title, Source: a.Source, Severity: a.Severity, Frame: replayFrame(a.Frame),
		})
	}
	for _, r := range rep.Reached {
		out.Reached = append(out.Reached, &tenantv1.IncidentReached{
			Label: r.Label, Key: r.Key, AlertKey: r.AlertKey, Frame: replayFrame(r.Frame),
		})
	}
	for _, a := range rep.Actions {
		ia := &tenantv1.IncidentAction{
			ToolId: a.ToolID, Connector: a.Connector, Tool: a.Tool, AgentName: a.AgentName,
			Outcome: incidentOutcomes[a.Outcome], Error: a.Error, Result: a.Result,
			ControlIds: a.Controls, Frame: replayFrame(a.Frame),
		}
		if a.Grant != nil {
			ia.Grant = &tenantv1.IncidentGrant{
				Id: a.Grant.ID, Capability: a.Grant.Capability,
				GrantedBy: a.Grant.GrantedBy, GrantedAtUnix: a.Grant.GrantedAtUnix,
			}
		}
		out.Actions = append(out.Actions, ia)
	}
	for _, c := range rep.Causes {
		ic := &tenantv1.IncidentCause{
			FindingKey: c.FindingKey, Title: c.Title, Severity: c.Severity, Status: c.Status,
			Raised: replayFrame(c.Raised),
		}
		for _, h := range c.History {
			ic.History = append(ic.History, &tenantv1.IncidentStatusChange{Status: h.Status, Frame: replayFrame(h.Frame)})
		}
		out.Causes = append(out.Causes, ic)
	}
	for _, f := range rep.Fixes {
		out.Fixes = append(out.Fixes, &tenantv1.IncidentFix{
			FindingKey: f.FindingKey, MergeRequestKey: f.MergeRequestKey, Url: f.URL, Ref: f.Ref,
			Frame: replayFrame(f.Frame), VerifiedBy: f.VerifiedBy, Verified: replayFrame(f.Verified),
		})
	}
	return out
}
