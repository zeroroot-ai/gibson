// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/blueteam"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// tenantOf returns the tenant of the caller. engine has checked it before.
func tenantOf(ctx context.Context) (string, bool) {
	t, ok := auth.TenantFromContext(ctx)
	return t.String(), ok
}

// world_service_blueteam.go serves the reads of the blue team console. Each
// read starts from the tenant of the caller (worldServer.engine). No request
// field names a tenant. Exposure, revert rate and the refusals read the
// durable Timeline, because the in-memory Timeline holds only the tail after a
// snapshot.

// defaultTrendPeriod is the period of a trend call that names none.
const defaultTrendPeriod = 7 * 24 * time.Hour

// auditPageSize and auditMaxPages bound the audit read of ListActionsByGrant.
const (
	auditPageSize = 1000
	auditMaxPages = 10
)

// FindingPlacesFunc returns the places that one finding of a tenant touches.
type FindingPlacesFunc func(ctx context.Context, tenant, findingID string) ([]component.Place, error)

// FindingConfidenceFunc returns the confidence of the check that raised a
// finding, from the findings table. ok is false when the table has no row.
type FindingConfidenceFunc func(ctx context.Context, tenant, findingID string) (confidence float64, ok bool, err error)

// ActionAuditFunc returns the audit records that the action read joins: the
// connector calls in [from, to] and the grant changes up to to. truncated is
// true when a bound cut the read.
type ActionAuditFunc func(ctx context.Context, tenant string, from, to time.Time) (calls, changes []audit.PgEntry, truncated bool, err error)

// blueTeamSources are the stores that the blue team reads need besides the
// World. A nil source makes its RPC answer Unavailable, and never an empty
// answer.
type blueTeamSources struct {
	places     FindingPlacesFunc
	confidence FindingConfidenceFunc
	actions    ActionAuditFunc
	now        func() time.Time
}

// WithBlueTeamSources sets the stores of the blue team reads and returns s.
func (s *worldServer) WithBlueTeamSources(
	places FindingPlacesFunc, confidence FindingConfidenceFunc, actions ActionAuditFunc,
) *worldServer {
	s.blue = blueTeamSources{places: places, confidence: confidence, actions: actions, now: time.Now}
	return s
}

func (s *worldServer) clockNow() time.Time {
	if s.blue.now != nil {
		return s.blue.now().UTC()
	}
	return time.Now().UTC()
}

func periodOf(seconds int64) time.Duration {
	if seconds <= 0 {
		return defaultTrendPeriod
	}
	return windowOf(uint64(seconds))
}

func (s *worldServer) history(ctx context.Context, e *brain.Engine) ([]brain.Event, error) {
	evs, err := e.History(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "world: durable history read failed", "error", err)
		return nil, status.Error(codes.Unavailable, "the Timeline is not readable now")
	}
	return evs, nil
}

// GetExposure implements WorldServiceServer.
func (s *worldServer) GetExposure(ctx context.Context, req *worldpb.GetExposureRequest) (*worldpb.GetExposureResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	evs, err := s.history(ctx, e)
	if err != nil {
		return nil, err
	}
	for _, w := range brain.ExposureWindows(evs, s.clockNow()) {
		if w.FindingID != req.GetFindingId() {
			continue
		}
		return &worldpb.GetExposureResponse{
			Found: true, FindingId: w.FindingID,
			Start: timestamppb.New(w.Start), End: timestamppb.New(w.End), Verified: w.Verified,
			TotalSeconds: seconds(w.Total), WaitSeconds: seconds(w.Wait), AgentSeconds: seconds(w.Agent),
		}, nil
	}
	return &worldpb.GetExposureResponse{Found: false, FindingId: req.GetFindingId()}, nil
}

// GetExposureTrend implements WorldServiceServer.
func (s *worldServer) GetExposureTrend(ctx context.Context, req *worldpb.GetExposureTrendRequest) (*worldpb.GetExposureTrendResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	evs, err := s.history(ctx, e)
	if err != nil {
		return nil, err
	}
	now, period := s.clockNow(), periodOf(req.GetPeriodSeconds())
	t := brain.MedianExposure(brain.ExposureWindows(evs, now), now, period)
	return &worldpb.GetExposureTrendResponse{
		PeriodSeconds: seconds(period), Count: pagetoken.Int32(t.Count),
		MedianSeconds: seconds(t.Median), MedianAgentSeconds: seconds(t.MedianAgent),
		MedianWaitSeconds: seconds(t.MedianWait),
		PreviousCount:     pagetoken.Int32(t.PreviousCount), PreviousMedianSeconds: seconds(t.PreviousMedian),
	}, nil
}

// GetRevertRate implements WorldServiceServer.
func (s *worldServer) GetRevertRate(ctx context.Context, req *worldpb.GetRevertRateRequest) (*worldpb.GetRevertRateResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	evs, err := s.history(ctx, e)
	if err != nil {
		return nil, err
	}
	period := periodOf(req.GetPeriodSeconds())
	t := brain.RevertRateTrend(evs, s.clockNow(), period)
	return &worldpb.GetRevertRateResponse{
		PeriodSeconds: seconds(period), Current: revertPeriod(t.Current), Previous: revertPeriod(t.Previous),
	}, nil
}

func revertPeriod(r brain.RevertStats) *worldpb.RevertPeriod {
	return &worldpb.RevertPeriod{Merged: pagetoken.Int32(r.Merged), Reverted: pagetoken.Int32(r.Reverted), Rate: r.Rate}
}

func seconds(d time.Duration) int64 { return int64(d / time.Second) }

// ListOpenFindings implements WorldServiceServer.
func (s *worldServer) ListOpenFindings(ctx context.Context, req *worldpb.ListOpenFindingsRequest) (*worldpb.ListOpenFindingsResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	tenant, _ := tenantOf(ctx)
	pg, err := s.pageOf(ctx, "ListOpenFindings", req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	// The key holds the tier and the belief, so a finding that changes its
	// priority between two pages can move. The page never repeats a finding of
	// its own list and never fails.
	page, next := pagetoken.Page(pg, blueteam.OpenRanked(e.Findings(), e.Hosts()), blueteam.Key)
	resp := &worldpb.ListOpenFindingsResponse{NextPageToken: next}
	for _, r := range page {
		view := &worldpb.OpenFindingView{
			Id: r.ID, Title: r.Title, ScopeId: r.ScopeID, Address: r.Address, Severity: r.Severity,
			Status: r.Status, Priority: r.Priority, PriorityRule: r.PriorityRule,
			MergeRequest: r.MergeRequest, MergeRequestUrl: urlOf(r.MergeRequest),
			TargetBelief: r.Belief, CheckKind: r.CheckKind,
		}
		s.fillPlacesAndConfidence(ctx, tenant, view)
		resp.Findings = append(resp.Findings, view)
	}
	return resp, nil
}

// fillPlacesAndConfidence reads the place and the confidence of a finding from
// the graph and from the findings table. A read that fails leaves the field
// empty and logs the failure, so one bad store does not hide the list.
func (s *worldServer) fillPlacesAndConfidence(ctx context.Context, tenant string, v *worldpb.OpenFindingView) {
	if s.blue.places != nil {
		places, err := s.blue.places(ctx, tenant, v.Id)
		switch {
		case err == nil:
			for _, p := range places {
				v.Places = append(v.Places, &worldpb.FindingPlace{Label: p.Label, Key: p.Key})
			}
		case !errors.Is(err, component.ErrFindingNotFound):
			s.logger.WarnContext(ctx, "world: finding places read failed", "finding_id", v.Id, "error", err)
		}
	}
	if s.blue.confidence != nil {
		c, ok, err := s.blue.confidence(ctx, tenant, v.Id)
		switch {
		case err != nil:
			s.logger.WarnContext(ctx, "world: finding confidence read failed", "finding_id", v.Id, "error", err)
		case ok:
			v.Confidence = c
		}
	}
}

// urlOf returns the key of a merge request when the key is a web URL, and the
// empty string otherwise.
func urlOf(key string) string {
	u, err := url.Parse(key)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return key
}

// ListActionsByGrant implements WorldServiceServer.
func (s *worldServer) ListActionsByGrant(ctx context.Context, req *worldpb.ListActionsByGrantRequest) (*worldpb.ListActionsByGrantResponse, error) {
	if _, err := s.engine(ctx); err != nil {
		return nil, err
	}
	if s.blue.actions == nil {
		return nil, status.Error(codes.Unavailable, "the audit record is not wired")
	}
	tenant, _ := tenantOf(ctx)
	to := s.clockNow()
	if req.GetTo() != nil {
		to = req.GetTo().AsTime()
	}
	from := to.Add(-24 * time.Hour)
	if req.GetFrom() != nil {
		from = req.GetFrom().AsTime()
	}
	if from.After(to) {
		return nil, status.Error(codes.InvalidArgument, "from is after to")
	}
	calls, changes, truncated, err := s.blue.actions(ctx, tenant, from, to)
	if err != nil {
		s.logger.WarnContext(ctx, "world: audit read failed", "error", err)
		return nil, status.Error(codes.Unavailable, "the audit record is not readable now")
	}
	pg, err := s.pageOf(ctx, "ListActionsByGrant", req.GetPageSize(), req.GetPageToken(),
		from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	page, next := pagetoken.Page(pg, blueteam.GroupActions(calls, changes, from, to), actionGroupKey)
	resp := &worldpb.ListActionsByGrantResponse{Truncated: truncated, NextPageToken: next}
	for _, g := range page {
		resp.Groups = append(resp.Groups, &worldpb.ActionGroup{
			GrantObject: g.Grant.Object, GrantRelation: g.Grant.Relation, Grantor: g.Grantor,
			Refused: g.Refused, Count: pagetoken.Int32(g.Count),
			First: timestamppb.New(g.First), Last: timestamppb.New(g.Last),
			Agents: g.Agents, Tools: g.Tools, AuditRecordIds: g.RecordIDs,
		})
	}
	return resp, nil
}

// ListWaitingOnPerson implements WorldServiceServer.
func (s *worldServer) ListWaitingOnPerson(ctx context.Context, req *worldpb.ListWaitingOnPersonRequest) (*worldpb.ListWaitingOnPersonResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	evs, err := s.history(ctx, e)
	if err != nil {
		return nil, err
	}
	pg, err := s.pageOf(ctx, "ListWaitingOnPerson", req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	items := blueteam.WaitingOnPerson(e.Findings(), e.DestructiveActionSnapshot(), evs, s.clockNow())
	page, next := pagetoken.Page(pg, items, waitingKey)
	resp := &worldpb.ListWaitingOnPersonResponse{NextPageToken: next}
	for _, it := range page {
		resp.Items = append(resp.Items, &worldpb.WaitingItem{
			Kind: string(it.Kind), Id: it.ID, Since: timestamppb.New(it.Since), WaitedSeconds: seconds(it.Waited),
		})
	}
	return resp, nil
}

// auditActionReader reads the audit records of ListActionsByGrant from the
// durable audit table of one tenant.
func auditActionReader(q *audit.Query) ActionAuditFunc {
	return func(ctx context.Context, tenant string, from, to time.Time) ([]audit.PgEntry, []audit.PgEntry, bool, error) {
		var truncated bool
		read := func(f audit.Filters) ([]audit.PgEntry, error) {
			var all []audit.PgEntry
			for page := range auditMaxPages {
				got, total, err := q.List(ctx, tenant, f, auditPageSize, page*auditPageSize)
				if err != nil {
					return nil, fmt.Errorf("audit list: %w", err)
				}
				all = append(all, got...)
				if len(all) >= total {
					return all, nil
				}
			}
			truncated = true
			return all, nil
		}
		calls, err := read(audit.Filters{Action: "connector.tool.call", Since: &from, Until: &to})
		if err != nil {
			return nil, nil, false, err
		}
		var changes []audit.PgEntry
		for _, action := range []string{"agent_grant_added", "agent_grant_removed"} {
			got, err := read(audit.Filters{Action: action, Until: &to})
			if err != nil {
				return nil, nil, false, err
			}
			changes = append(changes, got...)
		}
		return calls, changes, truncated, nil
	}
}

// blueTeamWorldServer gives the WorldService the stores of the blue team reads.
// Each store resolves on the call, because the daemon builds the graph querier
// and the platform database after it builds the server.
func (d *daemonImpl) blueTeamWorldServer(s *worldServer) *worldServer {
	places := func(ctx context.Context, tenant, id string) ([]component.Place, error) {
		fp, ok := any(d.graphragQuerier).(findingPlacer)
		if !ok {
			return nil, errors.New("the graph querier is not wired")
		}
		return fp.FindingPlaces(ctx, tenant, id)
	}
	confidence := func(ctx context.Context, tenant, id string) (float64, bool, error) {
		fid := types.ID(id)
		if hasRow := fid.Validate() == nil; !hasRow {
			return 0, false, nil // a World finding with no UUID has no row
		}
		rec, err := pgstore.New(func() datapool.Pool { return d.pool }).Get(ctx, tenant, fid)
		if err != nil {
			return 0, false, fmt.Errorf("read the finding record: %w", err)
		}
		if rec == nil {
			return 0, false, nil
		}
		return rec.Confidence, true, nil
	}
	actions := func(ctx context.Context, tenant string, from, to time.Time) ([]audit.PgEntry, []audit.PgEntry, bool, error) {
		if d.platformDB == nil {
			return nil, nil, false, errors.New("the platform database is not open")
		}
		return auditActionReader(audit.NewQuery(d.platformDB))(ctx, tenant, from, to)
	}
	return s.WithBlueTeamSources(places, confidence, actions)
}

// actionGroupKey orders the groups of ListActionsByGrant for paging: the
// groups that a grant allowed first, then the refused ones, each by the grant
// and the person who gave it.
func actionGroupKey(g blueteam.ActionGroup) string {
	refused := "0"
	if g.Refused {
		refused = "1"
	}
	return refused + "\x00" + g.Grant.Object + "\x00" + g.Grant.Relation + "\x00" + g.Grantor
}

// waitingKey orders the items of ListWaitingOnPerson for paging.
func waitingKey(it blueteam.WaitItem) string { return string(it.Kind) + "\x00" + it.ID }
