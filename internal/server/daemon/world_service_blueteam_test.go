// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

var blueT0 = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

func blueAt(h int) time.Time { return blueT0.Add(time.Duration(h) * time.Hour) }

func newBlueServer(t *testing.T, now time.Time) (*worldServer, *brain.Registry) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewWorldServer(reg, nil, testWorldKeys(t))
	srv.blue.now = func() time.Time { return now }
	return srv, reg
}

func submit(t *testing.T, reg *brain.Registry, tenant string, evs ...brain.Event) {
	t.Helper()
	for _, ev := range evs {
		require.NoError(t, reg.For(tenant).SubmitAndWait(context.Background(), ev))
	}
}

func TestListOpenFindings_RanksAndLeavesOutVerified(t *testing.T) {
	srv, reg := newBlueServer(t, blueAt(10))
	var placeReads, confidenceReads int
	srv.blue.places = func(_ context.Context, tenant string, ids []string) (map[string][]component.Place, error) {
		require.Equal(t, "acme", tenant)
		placeReads++
		out := map[string][]component.Place{}
		for _, id := range ids {
			out[id] = []component.Place{{Label: component.PlaceApplication, Key: "app-" + id}}
		}
		return out, nil
	}
	srv.blue.confidence = func(_ context.Context, _ string, _ []string) (map[string]float64, error) {
		confidenceReads++
		return map[string]float64{"p1": 0.9}, nil
	}
	t.Cleanup(func() {
		// One read of each store for the page, not two for each row (review m9).
		require.Equal(t, 1, placeReads)
		require.Equal(t, 1, confidenceReads)
	})
	submit(t, reg, "acme",
		brain.FindingRaised{ID: "p2", Title: "b", ScopeID: "s", Severity: "critical", Address: "h"},
		brain.FindingRaised{ID: "p1", Title: "a", ScopeID: "s", Severity: "low", Address: "h"},
		brain.FindingRaised{ID: "done", Title: "c", ScopeID: "s", Severity: "high", Address: "h", Status: brain.FindingStatusFixed},
		brain.FindingPrioritized{ID: "p2", Priority: "P2", Rule: "r2"},
		brain.FindingPrioritized{ID: "p1", Priority: "P1", Rule: "r1"},
		brain.FindingStatusChanged{ID: "p1", Status: brain.FindingStatusFixing, MergeRequest: "https://git.example/mr/1", At: blueAt(1)},
		brain.FindingStatusChanged{ID: "done", Status: brain.FindingStatusVerified, At: blueAt(1)},
	)
	// Another tenant has a finding that this caller must not see.
	submit(t, reg, "other", brain.FindingRaised{ID: "foreign", Title: "x", ScopeID: "s", Severity: "critical"})

	resp, err := srv.ListOpenFindings(worldTenantCtx("acme"), &worldpb.ListOpenFindingsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetFindings(), 2)
	first, second := resp.Findings[0], resp.Findings[1]
	require.Equal(t, "p1", first.Id)
	require.Equal(t, "p2", second.Id)
	require.Equal(t, "P1", first.Priority)
	require.Equal(t, "r1", first.PriorityRule)
	require.Equal(t, "fixing", first.Status)
	require.Equal(t, "https://git.example/mr/1", first.MergeRequestUrl)
	require.InDelta(t, 0.9, first.Confidence, 1e-9)
	require.Zero(t, second.Confidence, "no row, so no confidence")
	require.Len(t, first.Places, 1)
	require.Equal(t, "app-p1", first.Places[0].Key)
}

func TestListOpenFindings_Pages(t *testing.T) {
	srv, reg := newBlueServer(t, blueAt(10))
	for _, id := range []string{"a", "b", "c"} {
		submit(t, reg, "acme", brain.FindingRaised{ID: id, Title: id, ScopeID: "s", Severity: "high", Address: "h"})
	}
	ctx := worldTenantCtx("acme")
	var seen []string
	token := ""
	for range 5 {
		resp, err := srv.ListOpenFindings(ctx, &worldpb.ListOpenFindingsRequest{PageSize: 2, PageToken: token})
		require.NoError(t, err)
		for _, f := range resp.Findings {
			seen = append(seen, f.Id)
		}
		if token = resp.NextPageToken; token == "" {
			break
		}
	}
	require.ElementsMatch(t, []string{"a", "b", "c"}, seen)
}

func exposureRig(t *testing.T) (*worldServer, context.Context) {
	t.Helper()
	srv, reg := newBlueServer(t, blueAt(10))
	submit(t, reg, "acme",
		brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high", At: blueAt(0)},
		brain.FindingStatusChanged{ID: "f1", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", At: blueAt(1)},
		brain.MergeRequestObserved{Key: "mr-1", State: brain.MergeRequestMerged, At: blueAt(2)},
		brain.FindingStatusChanged{ID: "f1", Status: brain.FindingStatusVerified, At: blueAt(4)},
	)
	return srv, worldTenantCtx("acme")
}

func TestGetExposure(t *testing.T) {
	srv, ctx := exposureRig(t)
	one, err := srv.GetExposure(ctx, &worldpb.GetExposureRequest{FindingId: "f1"})
	require.NoError(t, err)
	require.True(t, one.Found)
	require.True(t, one.Verified)
	require.EqualValues(t, 4*3600, one.TotalSeconds)
	require.Equal(t, one.TotalSeconds, one.WaitSeconds+one.AgentSeconds)

	missing, err := srv.GetExposure(ctx, &worldpb.GetExposureRequest{FindingId: "nope"})
	require.NoError(t, err)
	require.False(t, missing.Found)
}

func TestGetExposure_NoTenant(t *testing.T) {
	srv, _ := exposureRig(t)
	_, err := srv.GetExposure(context.Background(), &worldpb.GetExposureRequest{FindingId: "f1"})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetExposureTrend(t *testing.T) {
	srv, ctx := exposureRig(t)
	trend, err := srv.GetExposureTrend(ctx, &worldpb.GetExposureTrendRequest{})
	require.NoError(t, err)
	require.EqualValues(t, 1, trend.Count)
	require.EqualValues(t, 4*3600, trend.MedianSeconds)

	// Another tenant sees none of it.
	other, err := srv.GetExposureTrend(worldTenantCtx("other"), &worldpb.GetExposureTrendRequest{})
	require.NoError(t, err)
	require.Zero(t, other.Count)
}

func TestGetExposureTrend_NoTenant(t *testing.T) {
	srv, _ := exposureRig(t)
	_, err := srv.GetExposureTrend(context.Background(), &worldpb.GetExposureTrendRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetRevertRate(t *testing.T) {
	srv, ctx := exposureRig(t)
	rate, err := srv.GetRevertRate(ctx, &worldpb.GetRevertRateRequest{})
	require.NoError(t, err)
	require.EqualValues(t, 1, rate.Current.Merged)
	require.Zero(t, rate.Current.Reverted)
}

func TestListWaitingOnPerson(t *testing.T) {
	srv, reg := newBlueServer(t, blueAt(6))
	submit(t, reg, "acme",
		brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high"},
		brain.FindingStatusChanged{ID: "f1", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", At: blueAt(1)},
		brain.FixHeadRecorded{ID: "f1", MergeRequest: "mr-1", HeadSHA: "aaaa", At: blueAt(1)},
		brain.MergeRequestObserved{Key: "mr-1", State: brain.MergeRequestRefused, At: blueAt(2)},
	)
	resp, err := srv.ListWaitingOnPerson(worldTenantCtx("acme"), &worldpb.ListWaitingOnPersonRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Items, 1)
	require.Equal(t, "merge_refused", resp.Items[0].Kind)
	require.EqualValues(t, 4*3600, resp.Items[0].WaitedSeconds)
}

// A linked fix with no head waits on a person, since the link, with the reason that no
// head was recorded.
func TestListWaitingOnPerson_NoFixHead(t *testing.T) {
	srv, reg := newBlueServer(t, blueAt(6))
	submit(t, reg, "acme",
		brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high"},
		brain.FindingStatusChanged{ID: "f1", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", At: blueAt(1)},
	)
	resp, err := srv.ListWaitingOnPerson(worldTenantCtx("acme"), &worldpb.ListWaitingOnPersonRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Items, 1)
	require.Equal(t, "no_fix_head", resp.Items[0].Kind)
	require.Equal(t, "no fix head was recorded", resp.Items[0].Reason)
	require.EqualValues(t, 5*3600, resp.Items[0].WaitedSeconds)
}

func TestListActionsByGrant(t *testing.T) {
	srv, _ := newBlueServer(t, blueAt(10))

	// No source wired is Unavailable and never an empty answer.
	_, err := srv.ListActionsByGrant(worldTenantCtx("acme"), &worldpb.ListActionsByGrantRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))

	md := func(m map[string]any) json.RawMessage { b, _ := json.Marshal(m); return b }
	srv.blue.actions = func(_ context.Context, tenant string, from, to time.Time) ([]audit.PgEntry, []audit.PgEntry, bool, error) {
		require.Equal(t, "acme", tenant)
		require.True(t, to.Equal(blueAt(5)))
		require.True(t, from.Equal(blueAt(1)))
		return []audit.PgEntry{
			{Action: "connector.tool.call", ActorID: "agent:a1", TargetID: "gitlab", CreatedAt: blueAt(2),
				Metadata: md(map[string]any{"result": "success", "details": map[string]string{"tool": "merge"}})},
			{Action: "connector.tool.call", ActorID: "agent:a2", TargetID: "gitlab", CreatedAt: blueAt(3),
				Metadata: md(map[string]any{"result": "failure", "details": map[string]string{"error": "unauthorized"}})},
		}, []audit.PgEntry{
			// The grant admin writes the tuple relation direct_execute, with the decision allow.
			{Action: "agent_grant_added", ActorID: "user:ann", TargetID: "agent:a1", Decision: "allow", CreatedAt: blueAt(0),
				Metadata: md(map[string]any{"object": authz.ConnectorComponentObject("gitlab"), "relation": "direct_execute"})},
		}, false, nil
	}
	resp, err := srv.ListActionsByGrant(worldTenantCtx("acme"), &worldpb.ListActionsByGrantRequest{
		From: timestamppb.New(blueAt(1)), To: timestamppb.New(blueAt(5)),
	})
	require.NoError(t, err)
	require.Len(t, resp.Groups, 2)
	require.Equal(t, "user:ann", resp.Groups[0].Grantor)
	require.False(t, resp.Groups[0].Refused)
	require.True(t, resp.Groups[1].Refused)
	require.Equal(t, authz.ConnectorComponentObject("gitlab"), resp.Groups[1].GrantObject)
}

func TestBlueTeamReadsRefuseACallerWithNoTenant(t *testing.T) {
	srv, _ := newBlueServer(t, blueAt(10))
	ctx := context.Background()
	_, err := srv.ListOpenFindings(ctx, &worldpb.ListOpenFindingsRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = srv.GetRevertRate(ctx, &worldpb.GetRevertRateRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = srv.ListWaitingOnPerson(ctx, &worldpb.ListWaitingOnPersonRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = srv.ListActionsByGrant(ctx, &worldpb.ListActionsByGrantRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// rangeOnlyStore refuses the read of the whole history, so a test that passes
// over it shows that the reader read only a bounded range (review M6).
type rangeOnlyStore struct {
	*braintest.MemTimelineStore
	ranges *[]string
}

func (rangeOnlyStore) LoadHistory(context.Context, string) ([]brain.Event, error) {
	return nil, errors.New("the whole history must not be read")
}

func (s rangeOnlyStore) LoadHistoryRange(ctx context.Context, tenant string, from time.Time, kinds []string) ([]brain.Event, error) {
	*s.ranges = append(*s.ranges, from.UTC().Format(time.RFC3339))
	evs, err := s.MemTimelineStore.LoadHistoryRange(ctx, tenant, from, kinds)
	if err != nil {
		return nil, fmt.Errorf("range: %w", err)
	}
	return evs, nil
}

// The four views of the blue team read a bounded range of the history: from
// the first fact of the finding on, and for the revert rate the two periods
// (review M6).
func TestBlueTeamViews_ReadABoundedHistory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var ranges []string
	store := rangeOnlyStore{MemTimelineStore: braintest.NewMemTimelineStore(), ranges: &ranges}
	reg := brain.NewRegistry(ctx, func(context.Context, string) (brain.TimelineStore, error) { return store, nil })
	srv := NewWorldServer(reg, nil, testWorldKeys(t))
	srv.blue.now = func() time.Time { return blueAt(10) }
	submit(t, reg, "acme",
		brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high", At: blueAt(2)},
		brain.FindingStatusChanged{ID: "f1", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", At: blueAt(3)},
	)
	wctx := worldTenantCtx("acme")

	_, err := srv.GetExposure(wctx, &worldpb.GetExposureRequest{FindingId: "f1"})
	require.NoError(t, err)
	_, err = srv.GetExposureTrend(wctx, &worldpb.GetExposureTrendRequest{PeriodSeconds: 3600})
	require.NoError(t, err)
	_, err = srv.GetRevertRate(wctx, &worldpb.GetRevertRateRequest{PeriodSeconds: 3600})
	require.NoError(t, err)
	_, err = srv.ListWaitingOnPerson(wctx, &worldpb.ListWaitingOnPersonRequest{})
	require.NoError(t, err)

	start := blueAt(2).Add(-historySlack).UTC().Format(time.RFC3339)
	revertFrom := blueAt(8).Add(-historySlack).UTC().Format(time.RFC3339)
	require.Equal(t, []string{start, start, revertFrom, start}, ranges)
}

// The stores of the blue team reads resolve on the call. With no graph
// querier and no platform database, each read fails, and a page of findings
// with no UUID reads no row of the findings table (review m9).
func TestBlueTeamWorldServer_TheStoresResolveOnTheCall(t *testing.T) {
	d := &daemonImpl{}
	srv := d.blueTeamWorldServer(&worldServer{})
	ctx := context.Background()
	if _, err := srv.blue.places(ctx, "acme", []string{"f1"}); err == nil {
		t.Fatal("places with no graph querier: want an error")
	}
	got, err := srv.blue.confidence(ctx, "acme", []string{"anomaly-host-3"})
	require.NoError(t, err)
	require.Empty(t, got)
	if _, _, _, err := srv.blue.actions(ctx, "acme", blueAt(0), blueAt(1)); err == nil {
		t.Fatal("actions with no platform database: want an error")
	}
}

// One old open finding, or one finding with no time, does not make a view over
// many findings read the whole history (review r13).
func TestBlueTeamViews_TheReadIsBoundedWhateverTheOldestFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var ranges []string
	store := rangeOnlyStore{MemTimelineStore: braintest.NewMemTimelineStore(), ranges: &ranges}
	reg := brain.NewRegistry(ctx, func(context.Context, string) (brain.TimelineStore, error) { return store, nil })
	srv := NewWorldServer(reg, nil, testWorldKeys(t))
	now := blueAt(10)
	srv.blue.now = func() time.Time { return now }
	submit(t, reg, "acme",
		brain.FindingRaised{ID: "no-time", Title: "t", ScopeID: "s", Severity: "high"},
		brain.FindingStatusChanged{ID: "no-time", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", At: blueAt(3)},
	)
	wctx := worldTenantCtx("acme")
	_, err := srv.GetExposureTrend(wctx, &worldpb.GetExposureTrendRequest{PeriodSeconds: 3600})
	require.NoError(t, err)
	_, err = srv.ListWaitingOnPerson(wctx, &worldpb.ListWaitingOnPersonRequest{})
	require.NoError(t, err)
	floor := now.Add(-brain.MaxViewLookback).UTC().Format(time.RFC3339)
	require.Equal(t, []string{floor, floor}, ranges)
}

// Three failed fix jobs in a row show a fix_attempts_failed wait. A retry of a
// person ends it, records the person, and lets a job claim the finding again
// (gibson#1674).
func TestResolveFixAttempts_RetryEndsTheWait(t *testing.T) {
	srv, reg := newBlueServer(t, blueAt(10))
	submit(t, reg, "acme", brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high"})
	for i, j := range []string{"j1", "j2", "j3"} {
		submit(t, reg, "acme", brain.FixAttemptFailed{ID: "f1", JobID: j, Verdict: "failed", Reason: "no", At: blueAt(i + 1)})
	}
	ctx := auth.ContextWithActingUser(worldTenantCtx("acme"), "person-1")

	waits, err := srv.ListWaitingOnPerson(ctx, &worldpb.ListWaitingOnPersonRequest{})
	require.NoError(t, err)
	require.Len(t, waits.Items, 1)
	require.Equal(t, "fix_attempts_failed", waits.Items[0].Kind)

	resp, err := srv.ResolveFixAttempts(ctx, &worldpb.ResolveFixAttemptsRequest{FindingId: "f1", Action: "retry"})
	require.NoError(t, err)
	require.EqualValues(t, 3, resp.ClearedAttempts)

	waits, err = srv.ListWaitingOnPerson(ctx, &worldpb.ListWaitingOnPersonRequest{})
	require.NoError(t, err)
	require.Empty(t, waits.Items)
	submit(t, reg, "acme", brain.FixClaimed{ID: "f1", Claim: "run-9/fix", At: blueAt(11)})
	var holder string
	reg.For("acme").ReadWorld(func(w *brain.World) { holder = w.FixClaimOf("f1") })
	require.Equal(t, "run-9/fix", holder)

	// A second retry has no wait to end.
	_, err = srv.ResolveFixAttempts(ctx, &worldpb.ResolveFixAttemptsRequest{FindingId: "f1", Action: "retry"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// The call acts only on a finding of the tenant of the caller, needs an acting
// user, and knows one action.
func TestResolveFixAttempts_Refusals(t *testing.T) {
	srv, reg := newBlueServer(t, blueAt(10))
	submit(t, reg, "acme", brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high"})
	for i, j := range []string{"j1", "j2", "j3"} {
		submit(t, reg, "acme", brain.FixAttemptFailed{ID: "f1", JobID: j, Verdict: "failed", Reason: "no", At: blueAt(i + 1)})
	}
	req := &worldpb.ResolveFixAttemptsRequest{FindingId: "f1", Action: "retry"}

	// Another tenant does not see the finding.
	_, err := srv.ResolveFixAttempts(auth.ContextWithActingUser(worldTenantCtx("other"), "person-1"), req)
	require.Equal(t, codes.NotFound, status.Code(err))
	// No acting user.
	_, err = srv.ResolveFixAttempts(worldTenantCtx("acme"), req)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	// An action that does not exist.
	_, err = srv.ResolveFixAttempts(auth.ContextWithActingUser(worldTenantCtx("acme"), "person-1"),
		&worldpb.ResolveFixAttemptsRequest{FindingId: "f1", Action: "dismiss"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	// The wait still stands.
	var blocked bool
	for _, f := range reg.For("acme").Findings() {
		blocked = blocked || f.FixAttemptsBlocked()
	}
	require.True(t, blocked)
}

// A person ends the merge_request_close_failed waits with the action
// merge_request_closed. The daemon reads each merge request on the Git host first.
// It refuses while one is open and when the read fails. It trusts the person only
// when the tenant has no connector to read with.
func TestResolveFixAttempts_MergeRequestClosed(t *testing.T) {
	seed := func(t *testing.T) (*worldServer, *brain.Registry) {
		t.Helper()
		srv, reg := newBlueServer(t, blueAt(10))
		submit(t, reg, "acme", brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high"},
			brain.FixCloseWaiting{ID: "f1", JobID: "j1", MergeRequest: "g/p!7", Waiting: true, Reason: "down", At: blueAt(1)},
			brain.FixCloseWaiting{ID: "f1", JobID: "j2", MergeRequest: "g/p!8", Waiting: true, Reason: "down", At: blueAt(2)})
		return srv, reg
	}
	actor := func() context.Context { return auth.ContextWithActingUser(worldTenantCtx("acme"), "person-1") }
	req := &worldpb.ResolveFixAttemptsRequest{FindingId: "f1", Action: "merge_request_closed"}
	waits := func(reg *brain.Registry) int {
		for _, f := range reg.For("acme").Findings() {
			return len(f.FixCloseWaits)
		}
		return -1
	}
	host := func(open, known bool, err error, seen *[]string) MergeOpenFunc {
		return func(_ context.Context, tenant, _, mr string) (bool, bool, error) {
			require.Equal(t, "acme", tenant)
			*seen = append(*seen, mr)
			return open, known, err
		}
	}

	t.Run("an open merge request refuses", func(t *testing.T) {
		srv, reg := seed(t)
		var seen []string
		_, err := srv.WithMergeOpen(host(true, true, nil, &seen)).ResolveFixAttempts(actor(), req)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Equal(t, 2, waits(reg))
	})
	t.Run("a failed read refuses", func(t *testing.T) {
		srv, reg := seed(t)
		var seen []string
		_, err := srv.WithMergeOpen(host(false, true, errors.New("down"), &seen)).ResolveFixAttempts(actor(), req)
		require.Equal(t, codes.Unavailable, status.Code(err))
		require.Equal(t, 2, waits(reg))
	})
	t.Run("closed on the host ends both waits", func(t *testing.T) {
		srv, reg := seed(t)
		var seen []string
		resp, err := srv.WithMergeOpen(host(false, true, nil, &seen)).ResolveFixAttempts(actor(), req)
		require.NoError(t, err)
		require.EqualValues(t, 2, resp.EndedWaits)
		require.ElementsMatch(t, []string{"g/p!7", "g/p!8"}, seen)
		require.Zero(t, waits(reg))
		waitsNow, err := srv.ListWaitingOnPerson(actor(), &worldpb.ListWaitingOnPersonRequest{})
		require.NoError(t, err)
		require.Empty(t, waitsNow.Items)
	})
	t.Run("no connector trusts the person", func(t *testing.T) {
		srv, reg := seed(t)
		var seen []string
		_, err := srv.WithMergeOpen(host(false, false, nil, &seen)).ResolveFixAttempts(actor(), req)
		require.NoError(t, err)
		require.Zero(t, waits(reg))
	})
	t.Run("no wait is a failed precondition", func(t *testing.T) {
		srv, reg := newBlueServer(t, blueAt(10))
		submit(t, reg, "acme", brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high"})
		_, err := srv.ResolveFixAttempts(actor(), req)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
	t.Run("a retry leaves the close waits", func(t *testing.T) {
		srv, reg := seed(t)
		for i, j := range []string{"a", "b", "c"} {
			submit(t, reg, "acme", brain.FixAttemptFailed{ID: "f1", JobID: j, Verdict: "failed", At: blueAt(3 + i)})
		}
		resp, err := srv.ResolveFixAttempts(actor(), &worldpb.ResolveFixAttemptsRequest{FindingId: "f1", Action: "retry"})
		require.NoError(t, err)
		require.EqualValues(t, 3, resp.ClearedAttempts)
		require.Equal(t, 2, waits(reg))
	})
}

// A wait that lands while the daemon reads the Git host is not in the list that the
// person closed. It survives the action, and the finding still shows it.
func TestResolveFixAttempts_AWaitThatLandsDuringTheConfirmationSurvives(t *testing.T) {
	srv, reg := newBlueServer(t, blueAt(10))
	submit(t, reg, "acme", brain.FindingRaised{ID: "f1", Title: "t", ScopeID: "s", Severity: "high"},
		brain.FixCloseWaiting{ID: "f1", JobID: "j1", MergeRequest: "g/p!7", Waiting: true, Reason: "down", At: blueAt(1)})
	srv.WithMergeOpen(func(_ context.Context, _, _, mr string) (bool, bool, error) {
		// A second failed job leaves its wait while the first read runs.
		if mr == "g/p!7" {
			submit(t, reg, "acme", brain.FixCloseWaiting{
				ID: "f1", JobID: "j2", MergeRequest: "g/p!8", Waiting: true, Reason: "down", At: blueAt(2),
			})
		}
		return false, true, nil
	})
	ctx := auth.ContextWithActingUser(worldTenantCtx("acme"), "person-1")
	resp, err := srv.ResolveFixAttempts(ctx, &worldpb.ResolveFixAttemptsRequest{
		FindingId: "f1", Action: "merge_request_closed",
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, resp.EndedWaits)
	var left []brain.FixCloseWait
	for _, f := range reg.For("acme").Findings() {
		left = f.FixCloseWaits
	}
	require.Len(t, left, 1)
	require.Equal(t, "j2", left[0].JobID)
	require.Equal(t, "g/p!8", left[0].MergeRequest)
}
