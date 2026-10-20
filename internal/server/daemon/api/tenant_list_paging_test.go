// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// The tenant list RPCs of gibson#1261 page with page_size and page_token
// (ADR-0028, rule 3). Each walk test adds rows between the pages and checks
// that every row that existed at the start comes back once. Each test also
// checks that a forged token and a token of another tenant or query give
// InvalidArgument.

func requireInvalidToken(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
}

// requireOnce fails when a row of want is missing or comes back twice, or
// when any row comes back more than once.
func requireOnce(t *testing.T, want []string, seen map[string]int) {
	t.Helper()
	for _, id := range want {
		assert.Equal(t, 1, seen[id], "row %s", id)
	}
	for id, n := range seen {
		assert.Equal(t, 1, n, "row %s", id)
	}
}

// ----- ListMissionDrafts -----

func TestListMissionDrafts_WalkWithSavesBetweenPages(t *testing.T) {
	srv := newDraftTestServer(t).WithPageKeys(testPageKeys(t))
	ctx := draftCtx()
	want := make([]string, 0, 5)
	for i := range 5 {
		resp, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{TenantId: "tenant-a", Name: fmt.Sprintf("d%d", i), CueSource: "x: 1\n"})
		require.NoError(t, err)
		want = append(want, resp.GetDraftId())
	}

	seen := map[string]int{}
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10, "the token must reach the last page")
		resp, err := srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: "tenant-a", PageSize: 2, PageToken: token})
		require.NoError(t, err)
		for _, d := range resp.GetDrafts() {
			seen[d.GetId()]++
		}
		_, err = srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{TenantId: "tenant-a", Name: "late", CueSource: "x: 1\n"})
		require.NoError(t, err)
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	for _, id := range want {
		assert.Equal(t, 1, seen[id], "draft %s", id)
	}
	for id, n := range seen {
		assert.Equal(t, 1, n, "draft %s", id)
	}
}

func TestListMissionDrafts_RefusesAForgedAndACrossTenantToken(t *testing.T) {
	srv := newDraftTestServer(t).WithPageKeys(testPageKeys(t))
	ctx := draftCtx()
	for i := range 3 {
		_, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{TenantId: "tenant-a", Name: fmt.Sprintf("d%d", i), CueSource: "x: 1\n"})
		require.NoError(t, err)
	}
	page, err := srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: "tenant-a", PageSize: 1})
	require.NoError(t, err)
	require.NotEmpty(t, page.GetNextPageToken())

	_, err = srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: "tenant-b", PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	_, err = srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: "tenant-a", PageToken: "forged.token"})
	requireInvalidToken(t, err)
}

func TestListMissionDrafts_WithoutKeysTheListFails(t *testing.T) {
	srv := newDraftTestServer(t).WithPageKeys(nil)
	_, err := srv.ListMissionDrafts(draftCtx(), &tenantv1.ListMissionDraftsRequest{TenantId: "tenant-a"})
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ----- ListUsage -----

// pagingUsageEnforcer serves the rows of one scope, and a test changes them between
// pages.
type pagingUsageEnforcer struct {
	adminBudgetEnforcer
	rows []*budget.Status
}

func (e *pagingUsageEnforcer) ListStatusByScope(context.Context, budget.Scope) ([]*budget.Status, error) {
	return e.rows, nil
}

func TestListUsage_WalkWithRowsBetweenPages(t *testing.T) {
	az := newFakeAuthorizer()
	enf := &pagingUsageEnforcer{}
	for i := range 5 {
		enf.rows = append(enf.rows, &budget.Status{SubjectID: fmt.Sprintf("u%d", 2*i+1), CurrentTokens: 10})
	}
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithAuthorizer(az).WithPageKeys(testPageKeys(t))
	srv.budgetEnforcer = enf
	ctx := adminTenantCtx(az, "acme", "owner-1")

	seen := map[string]int{}
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10)
		resp, err := srv.ListUsage(ctx, &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_USER, PageSize: 2, PageToken: token})
		require.NoError(t, err)
		for _, r := range resp.GetRows() {
			seen[r.GetSubjectId()]++
		}
		enf.rows = append(enf.rows, &budget.Status{SubjectID: fmt.Sprintf("u%d", 2*pages)}, &budget.Status{SubjectID: fmt.Sprintf("u%da", 2*pages+1)})
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	requireOnce(t, []string{"u1", "u3", "u5", "u7", "u9"}, seen)
}

func TestListUsage_RefusesAForgedAndACrossQueryToken(t *testing.T) {
	az := newFakeAuthorizer()
	enf := &pagingUsageEnforcer{rows: []*budget.Status{{SubjectID: "a"}, {SubjectID: "b"}, {SubjectID: "c"}}}
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithAuthorizer(az).WithPageKeys(testPageKeys(t))
	srv.budgetEnforcer = enf
	ctx := adminTenantCtx(az, "acme", "owner-1")
	page, err := srv.ListUsage(ctx, &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_USER, PageSize: 1})
	require.NoError(t, err)
	require.NotEmpty(t, page.GetNextPageToken())

	// Another scope, another filter, another tenant and a forged token.
	_, err = srv.ListUsage(ctx, &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_TEAM, PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	_, err = srv.ListUsage(ctx, &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_USER, SubjectFilter: "b", PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	other := adminTenantCtx(az, "globex", "owner-1")
	_, err = srv.ListUsage(other, &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_USER, PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	_, err = srv.ListUsage(ctx, &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_USER, StartTimeUnix: 5, PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	_, err = srv.ListUsage(ctx, &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_USER, EndTimeUnix: 5, PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	_, err = srv.ListUsage(ctx, &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_USER, PageToken: "forged.token"})
	requireInvalidToken(t, err)
}

func TestListUsage_ANonAdminTokenIsBoundToTheCaller(t *testing.T) {
	az := newFakeAuthorizer()
	enf := &pagingUsageEnforcer{rows: []*budget.Status{{SubjectID: "u-viewer"}, {SubjectID: "u-viewer"}}}
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithAuthorizer(az).WithPageKeys(testPageKeys(t))
	srv.budgetEnforcer = enf
	resp, err := srv.ListUsage(missionViewerCtx(), &tenantv1.ListUsageRequest{Scope: tenantv1.UsageScope_USAGE_SCOPE_USER, SubjectFilter: "somebody-else"})
	require.NoError(t, err)
	assert.Len(t, resp.GetRows(), 2, "a non-admin sees the own rows whatever the filter says")
}

func TestListUsage_UnknownScopeIsInvalid(t *testing.T) {
	az := newFakeAuthorizer()
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithAuthorizer(az).WithPageKeys(testPageKeys(t))
	_, err := srv.ListUsage(adminTenantCtx(az, "acme", "owner-1"), &tenantv1.ListUsageRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ----- ListAccess -----

func TestListAccess_WalkWithGrantsBetweenPages(t *testing.T) {
	a := newFakeAuthorizer().allow("user:"+testViewerSubject, "admin", "tenant:acme")
	providers := []string{"provider:acme/p1", "provider:acme/p3", "provider:acme/p5"}
	a.withObjects("tenant:acme#member", "can_use", "provider", providers...)
	a.withObjects("tenant:acme#member", "can_use", "model", "model:acme/m1", "model:acme/m3")
	srv := &DaemonServer{logger: testSlogLogger, authorizer: a}
	srv.WithPageKeys(testPageKeys(t))
	req := func(token string) *tenantv1.ListAccessRequest {
		return &tenantv1.ListAccessRequest{SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_TENANT, PageSize: 2, PageToken: token}
	}

	seen := map[string]int{}
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10)
		resp, err := srv.ListAccess(missionViewerCtx(), req(token))
		require.NoError(t, err)
		for _, g := range resp.GetGrants() {
			seen[g.GetTargetKind().String()+"/"+g.GetTargetId()]++
		}
		providers = append(providers, fmt.Sprintf("provider:acme/p%d", 2*pages))
		a.withObjects("tenant:acme#member", "can_use", "provider", providers...)
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	want := []string{
		"GRANT_TARGET_KIND_PROVIDER/p1", "GRANT_TARGET_KIND_PROVIDER/p3", "GRANT_TARGET_KIND_PROVIDER/p5",
		"GRANT_TARGET_KIND_MODEL/m1", "GRANT_TARGET_KIND_MODEL/m3",
	}
	requireOnce(t, want, seen)

	// The token is bound to the tenant and the subject.
	page, err := srv.ListAccess(missionViewerCtx(), req(""))
	require.NoError(t, err)
	require.NotEmpty(t, page.GetNextPageToken())
	_, err = srv.ListAccess(missionViewerCtx(), &tenantv1.ListAccessRequest{
		SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_USER, SubjectId: "alice", PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	_, err = srv.ListAccess(missionViewerCtx(), req("forged.token"))
	requireInvalidToken(t, err)
}

// ----- ListModelResolutionEvents -----

// fakeAuditQuery serves audit rows newest first, with the id as the tie
// breaker, and pages them by position as audit.Query does.
type fakeAuditQuery struct {
	rows  []audit.PgEntry
	calls int
}

func (f *fakeAuditQuery) ListAfter(_ context.Context, _ string, _ audit.Filters, after string, limit int) ([]audit.PgEntry, bool, error) {
	f.calls++
	sorted := append([]audit.PgEntry(nil), f.rows...)
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
		}
		a, _ := strconv.Atoi(sorted[i].ID)
		b, _ := strconv.Atoi(sorted[j].ID)
		return a > b
	})
	start := 0
	if after != "" {
		start = len(sorted)
		for i, r := range sorted {
			if audit.Position(r) == after {
				start = i + 1
			}
		}
	}
	end := min(start+limit, len(sorted))
	return sorted[start:end], end < len(sorted), nil
}

func resolutionRow(id int, at time.Time, slot string) audit.PgEntry {
	meta, _ := json.Marshal(audit.ModelResolutionEvent{SlotName: slot, RunID: strconv.Itoa(id)})
	return audit.PgEntry{ID: strconv.Itoa(id), TenantID: "acme", ActorID: "u1", Action: "model_resolved",
		TargetID: "anthropic/opus", Metadata: meta, CreatedAt: at}
}

func resolutionServer(t *testing.T, q auditQueryIface) *DaemonServer {
	t.Helper()
	az := newFakeAuthorizer().allow("user:"+testViewerSubject, "admin", "tenant:acme")
	srv := &DaemonServer{logger: testSlogLogger, authorizer: az}
	srv.WithAuditQuery(q).WithPageKeys(testPageKeys(t))
	return srv
}

func TestListModelResolutionEvents_WalkWithEventsBetweenPages(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	q := &fakeAuditQuery{}
	want := make([]string, 0, 5)
	for n := range 5 {
		i := n + 1
		// Rows 1 and 2 share one time, so the id breaks the tie.
		at := base.Add(time.Duration(max(i-1, 1)) * time.Second)
		q.rows = append(q.rows, resolutionRow(i, at, "planner"))
		want = append(want, strconv.Itoa(i))
	}
	srv := resolutionServer(t, q)

	seen := map[string]int{}
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10)
		resp, err := srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{PageSize: 2, PageToken: token})
		require.NoError(t, err)
		for _, e := range resp.GetEvents() {
			seen[e.GetRunId()]++
		}
		// A newer event arrives between two pages.
		q.rows = append(q.rows, resolutionRow(100+pages, base.Add(time.Hour+time.Duration(pages)*time.Second), "planner"))
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	requireOnce(t, want, seen)
}

func TestListModelResolutionEvents_SlotFilterFillsAPageAcrossBatches(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	q := &fakeAuditQuery{}
	// Newest first: three "other" rows, then two "planner" rows, then one more "other".
	slots := []string{"other", "other", "other", "planner", "planner", "other"}
	for i, s := range slots {
		q.rows = append(q.rows, resolutionRow(i+1, base.Add(time.Duration(len(slots)-i)*time.Second), s))
	}
	srv := resolutionServer(t, q)

	resp, err := srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{SlotName: "planner", PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, resp.GetEvents(), 2)
	assert.Greater(t, q.calls, 1, "the page read more than one batch")
	// One "other" row follows the second planner row. The page may point at it.
	if tok := resp.GetNextPageToken(); tok != "" {
		next, err := srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{SlotName: "planner", PageSize: 2, PageToken: tok})
		require.NoError(t, err)
		assert.Empty(t, next.GetEvents())
		assert.Empty(t, next.GetNextPageToken())
	}
}

func TestListModelResolutionEvents_RefusesAForgedAndACrossQueryToken(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	q := &fakeAuditQuery{}
	for n := range 3 {
		i := n + 1
		q.rows = append(q.rows, resolutionRow(i, base.Add(time.Duration(i)*time.Second), "planner"))
	}
	srv := resolutionServer(t, q)
	page, err := srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{PageSize: 1})
	require.NoError(t, err)
	require.NotEmpty(t, page.GetNextPageToken())

	_, err = srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{UserId: "u2", PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	_, err = srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{PageToken: "forged.token"})
	requireInvalidToken(t, err)
}

type failingAuditQuery struct{}

func (failingAuditQuery) ListAfter(context.Context, string, audit.Filters, string, int) ([]audit.PgEntry, bool, error) {
	return nil, false, fmt.Errorf("boom")
}

func TestListModelResolutionEvents_AnAuditFailureIsUnavailable(t *testing.T) {
	srv := resolutionServer(t, failingAuditQuery{})
	_, err := srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestListModelResolutionEvents_TimeFiltersAndNoBackend(t *testing.T) {
	az := newFakeAuthorizer().allow("user:"+testViewerSubject, "admin", "tenant:acme")
	srv := &DaemonServer{logger: testSlogLogger, authorizer: az}
	resp, err := srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetEvents())

	srv = resolutionServer(t, &fakeAuditQuery{})
	resp, err = srv.ListModelResolutionEvents(missionViewerCtx(), &tenantv1.ListModelResolutionEventsRequest{StartTimeUnix: 10, EndTimeUnix: 20})
	require.NoError(t, err)
	assert.Empty(t, resp.GetEvents())
}

// ----- ListOntologyExtensionProposals -----

func TestListOntologyExtensionProposals_WalkWithProposalsBetweenPages(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	e := reg.For("acme")
	labels := []string{"B", "D", "F", "H", "J"}
	for _, l := range labels {
		proposeNTimes(context.Background(), t, e, taxonomy.ProposedNodeLabel, l, 1)
	}

	seen := map[string]int{}
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10)
		resp, err := s.ListOntologyExtensionProposals(tenantCtx("acme"), &tenantv1.ListOntologyExtensionProposalsRequest{PageSize: 2, PageToken: token})
		require.NoError(t, err)
		for _, p := range resp.GetOntologyProposals() {
			seen[p.GetLabel()]++
		}
		proposeNTimes(context.Background(), t, e, taxonomy.ProposedNodeLabel, fmt.Sprintf("A%d", pages), 1)
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	for _, l := range labels {
		assert.Equal(t, 1, seen[l], "label %s", l)
	}
	for l, n := range seen {
		assert.Equal(t, 1, n, "label %s", l)
	}
}

func TestListOntologyExtensionProposals_RefusesAForgedAndACrossTenantToken(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	for _, l := range []string{"A", "B", "C"} {
		proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, l, 1)
	}
	page, err := s.ListOntologyExtensionProposals(tenantCtx("acme"), &tenantv1.ListOntologyExtensionProposalsRequest{PageSize: 1})
	require.NoError(t, err)
	require.NotEmpty(t, page.GetNextPageToken())

	_, err = s.ListOntologyExtensionProposals(tenantCtx("globex"), &tenantv1.ListOntologyExtensionProposalsRequest{PageToken: page.GetNextPageToken()})
	requireInvalidToken(t, err)
	_, err = s.ListOntologyExtensionProposals(tenantCtx("acme"), &tenantv1.ListOntologyExtensionProposalsRequest{PageToken: "forged.token"})
	requireInvalidToken(t, err)
}
