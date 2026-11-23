// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/platform/incidentreport"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func TestIncidentReportResponse_MapsEachLineWithItsFrame(t *testing.T) {
	fr := incidentreport.Frame{TimelineSeq: 4, ReplaySeq: 5, Known: true}
	rep := &incidentreport.Report{
		IncidentKey: "inc-1", TimelineTotal: 20,
		Alerts: []incidentreport.AlertLine{{Key: "a1", Frame: fr}},
		Actions: []incidentreport.ActionLine{
			{
				ToolID: "mcp:okta-response:suspend_user", Outcome: incidentreport.OutcomeDone,
				Controls: []string{"ac-2", "ir-4"}, Frame: fr,
				Grant: &incidentreport.GrantLine{ID: "g1", GrantedBy: "user-7", GrantedAtUnix: 9},
			},
			{ToolID: "mcp:okta-response:revoke_user_sessions", Outcome: incidentreport.OutcomeRefused, Controls: []string{"ac-12", "ir-4"}},
		},
		Causes: []incidentreport.CauseLine{{
			FindingKey: "f1", Raised: fr,
			History: []incidentreport.StatusLine{{Status: "verified", Frame: fr}},
		}},
		Fixes: []incidentreport.FixLine{{FindingKey: "f1", MergeRequestKey: "mr1", Verified: fr}},
	}
	got := incidentReportResponse(rep)
	if got.GetAlerts()[0].GetFrame().GetReplaySeq() != 5 || !got.GetAlerts()[0].GetFrame().GetKnown() {
		t.Errorf("alert frame = %v", got.GetAlerts()[0].GetFrame())
	}
	a0, a1 := got.GetActions()[0], got.GetActions()[1]
	if a0.GetGrant().GetGrantedBy() != "user-7" || a0.GetOutcome() != tenantv1.IncidentAction_OUTCOME_DONE {
		t.Errorf("action 0 = %v", a0)
	}
	if a1.GetGrant() != nil || a1.GetOutcome() != tenantv1.IncidentAction_OUTCOME_REFUSED {
		t.Errorf("action 1 = %v", a1)
	}
	if a1.GetFrame().GetKnown() {
		t.Errorf("an action with no frame must say so: %v", a1.GetFrame())
	}
	if len(got.GetControlIds()) != 3 || got.GetControlIds()[0] != "ac-12" {
		t.Errorf("control ids = %v", got.GetControlIds())
	}
	if got.GetCauses()[0].GetHistory()[0].GetFrame().GetTimelineSeq() != 4 || got.GetFixes()[0].GetVerified().GetReplaySeq() != 5 {
		t.Errorf("cause or fix frame lost: %v %v", got.GetCauses(), got.GetFixes())
	}
	if got.GetTimelineTotal() != 20 {
		t.Errorf("total = %d", got.GetTimelineTotal())
	}
}

func TestIncidentReportStatus_MapsEachErrorToACode(t *testing.T) {
	var logged bytes.Buffer
	svc := NewIncidentReportService(nil, slog.New(slog.NewTextHandler(&logged, nil)))
	for _, tc := range []struct {
		err  error
		want codes.Code
	}{
		{incidentreport.ErrInvalidQuery, codes.InvalidArgument},
		{incidentreport.ErrNotFound, codes.NotFound},
		{incidentreport.ErrNoTenant, codes.PermissionDenied},
		{errors.New("graph down"), codes.Unavailable},
	} {
		if got := status_grpc.Code(svc.incidentReportStatus(context.Background(), tc.err)); got != tc.want {
			t.Errorf("%v -> %v, want %v", tc.err, got, tc.want)
		}
		// No internal text reaches the caller (review m20).
		if msg := status_grpc.Convert(svc.incidentReportStatus(context.Background(), tc.err)).Message(); strings.Contains(msg, "graph down") {
			t.Errorf("the message carries the internal error: %q", msg)
		}
	}
	// The cause goes to the logger of the service (review r7).
	if !strings.Contains(logged.String(), "graph down") {
		t.Errorf("the service logger did not get the cause: %q", logged.String())
	}
}

// ---- handler tests ----------------------------------------------------------

type irGraph struct{ rows map[string][]map[string]any }

// Read returns the rows of the first key that the query holds. The keys are
// parts of the query text, so the test does not need the text of a query.
func (g irGraph) Read(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
	for part, rows := range g.rows {
		if strings.Contains(cypher, part) {
			return rows, nil
		}
	}
	return nil, nil
}

type irHistory struct{ evs []brain.Event }

func (h irHistory) HistoryFrom(context.Context, time.Time) ([]brain.Event, uint64, error) {
	return h.evs, 0, nil
}

type irGrants struct{}

func (irGrants) GrantByID(_ context.Context, _, id string, _ time.Time) (*incidentreport.Grant, error) {
	return &incidentreport.Grant{ID: id, Capability: "execute:tool:mcp:crowdstrike-response", GrantedBy: "user-7"}, nil
}

func irService(t *testing.T, rows map[string][]map[string]any) *IncidentReportService {
	t.Helper()
	reader, err := incidentreport.NewReader(irGraph{rows}, irHistory{[]brain.Event{
		brain.AgentRunObserved{RunID: "r1", AgentName: "incident-response"},
		brain.EntityObserved{Label: "Incident", Key: "inc-1", MissionID: "m1"},
		brain.AgentToolCallObserved{
			ToolCallID: "c1", MissionID: "m1", RunID: "r1", ToolName: "mcp:okta-response:suspend_user", GrantID: "g1",
		},
	}}, irGrants{})
	if err != nil {
		t.Fatal(err)
	}
	return NewIncidentReportService(reader, nil)
}

func irContext(t *testing.T) context.Context {
	t.Helper()
	id, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	return auth.ContextWithTenant(context.Background(), id)
}

func TestGetIncidentReport_Success(t *testing.T) {
	s := irService(t, map[string][]map[string]any{
		"OPTIONAL MATCH (a:Alert)-[:PART_OF]->(i)": {{"alert_key": "a1"}},
	})
	resp, err := s.GetIncidentReport(irContext(t), &tenantv1.GetIncidentReportRequest{IncidentKey: "inc-1"})
	if err != nil {
		t.Fatalf("GetIncidentReport: %v", err)
	}
	if len(resp.GetActions()) != 1 || resp.GetActions()[0].GetGrant().GetGrantedBy() != "user-7" {
		t.Errorf("actions = %v", resp.GetActions())
	}
	if resp.GetActions()[0].GetFrame().GetReplaySeq() != 3 {
		t.Errorf("frame = %v", resp.GetActions()[0].GetFrame())
	}
}

func TestGetIncidentReport_Errors(t *testing.T) {
	s := irService(t, nil)
	if _, err := s.GetIncidentReport(irContext(t), &tenantv1.GetIncidentReportRequest{IncidentKey: "none"}); status_grpc.Code(err) != codes.NotFound {
		t.Errorf("an unknown incident: err = %v", err)
	}
	if _, err := s.GetIncidentReport(context.Background(), &tenantv1.GetIncidentReportRequest{IncidentKey: "inc-1"}); status_grpc.Code(err) != codes.PermissionDenied {
		t.Errorf("no tenant: err = %v", err)
	}
	if _, err := s.GetIncidentReport(irContext(t), &tenantv1.GetIncidentReportRequest{}); status_grpc.Code(err) != codes.InvalidArgument {
		t.Errorf("no key: err = %v", err)
	}
}
