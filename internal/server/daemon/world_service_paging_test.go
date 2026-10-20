// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// worldPageCase describes one list RPC for the page walk tests.
type worldPageCase struct {
	name string
	// add puts one row with the sort key id into the tenant brain.
	add func(e *brain.Engine, id string)
	// fetch calls the RPC and returns the ids of the page and its next token.
	fetch func(ctx context.Context, srv *worldServer, size int32, token string) ([]string, string, error)
	// before is a key that sorts before the first seed row. Empty when the
	// list has no key that a new row can take before the cursor.
	before string
	// seqKeyed is true when the ids are event seq numbers, so a new row always
	// comes after the cursor.
	seqKeyed bool
}

func worldPageCases() []worldPageCase {
	return []worldPageCase{
		{
			name: "ListLabels",
			add: func(e *brain.Engine, id string) {
				e.Submit(brain.LabelApplied{TargetID: id, Verdict: brain.VerdictDismiss})
			},
			fetch: func(ctx context.Context, srv *worldServer, size int32, tok string) ([]string, string, error) {
				r, err := srv.ListLabels(ctx, &worldpb.ListLabelsRequest{PageSize: size, PageToken: tok})
				ids := make([]string, 0, len(r.GetLabels()))
				for _, l := range r.GetLabels() {
					ids = append(ids, l.GetTargetId())
				}
				return ids, r.GetNextPageToken(), err
			},
			before: "a-first",
		},
		{
			name: "ListFindings",
			add: func(e *brain.Engine, id string) {
				e.Submit(brain.FindingRaised{ID: id, Title: "t", ScopeID: "s", Severity: "high", Address: "10.0.0.1"})
			},
			fetch: func(ctx context.Context, srv *worldServer, size int32, tok string) ([]string, string, error) {
				r, err := srv.ListFindings(ctx, &worldpb.ListFindingsRequest{PageSize: size, PageToken: tok})
				ids := make([]string, 0, len(r.GetFindings()))
				for _, f := range r.GetFindings() {
					ids = append(ids, f.GetId())
				}
				return ids, r.GetNextPageToken(), err
			},
			before: "a-first",
		},
		{
			name: "ListReviewQueue",
			add: func(e *brain.Engine, id string) {
				e.Submit(brain.FindingRaised{ID: id, Title: "t", ScopeID: "s", Severity: "high", Address: "10.0.0.1"})
			},
			fetch: func(ctx context.Context, srv *worldServer, size int32, tok string) ([]string, string, error) {
				r, err := srv.ListReviewQueue(ctx, &worldpb.ListReviewQueueRequest{PageSize: size, PageToken: tok})
				ids := make([]string, 0, len(r.GetItems()))
				for _, it := range r.GetItems() {
					ids = append(ids, it.GetTargetId())
				}
				return ids, r.GetNextPageToken(), err
			},
			before: "a-first",
		},
		{
			name: "ListMissions",
			add: func(e *brain.Engine, id string) {
				e.Submit(brain.MissionStarted{ID: id, Goal: "goal"})
			},
			fetch: func(ctx context.Context, srv *worldServer, size int32, tok string) ([]string, string, error) {
				r, err := srv.ListMissions(ctx, &worldpb.ListMissionsRequest{PageSize: size, PageToken: tok})
				ids := make([]string, 0, len(r.GetMissions()))
				for _, m := range r.GetMissions() {
					ids = append(ids, m.GetId())
				}
				return ids, r.GetNextPageToken(), err
			},
			before: "a-first",
		},
		{
			name: "ListHosts",
			add: func(e *brain.Engine, id string) {
				e.Submit(brain.HostObserved{ScopeID: "s", Address: id, OpenPorts: []int{22}})
			},
			fetch: func(ctx context.Context, srv *worldServer, size int32, tok string) ([]string, string, error) {
				r, err := srv.ListHosts(ctx, &worldpb.ListHostsRequest{PageSize: size, PageToken: tok})
				ids := make([]string, 0, len(r.GetHosts()))
				for _, h := range r.GetHosts() {
					ids = append(ids, h.GetAddress())
				}
				return ids, r.GetNextPageToken(), err
			},
			before: "a-first",
		},
		{
			name: "ListLlmCalls",
			add: func(e *brain.Engine, id string) {
				e.Submit(brain.LlmCallObserved{CallID: id, Model: "m", PromptTokens: 1, CompletionTokens: 1})
			},
			fetch: func(ctx context.Context, srv *worldServer, size int32, tok string) ([]string, string, error) {
				r, err := srv.ListLlmCalls(ctx, &worldpb.ListLlmCallsRequest{PageSize: size, PageToken: tok})
				ids := make([]string, 0, len(r.GetLlmCalls()))
				for _, c := range r.GetLlmCalls() {
					ids = append(ids, c.GetCallId())
				}
				return ids, r.GetNextPageToken(), err
			},
			before: "a-first",
		},
		{
			name: "ListOpenBets",
			add: func(e *brain.Engine, id string) {
				e.Submit(brain.HypothesisObserved{ScopeID: "s", Claim: "claim " + id, HypothesisID: id})
			},
			fetch: func(ctx context.Context, srv *worldServer, size int32, tok string) ([]string, string, error) {
				r, err := srv.ListOpenBets(ctx, &worldpb.ListOpenBetsRequest{PageSize: size, PageToken: tok})
				ids := make([]string, 0, len(r.GetBets()))
				for _, b := range r.GetBets() {
					ids = append(ids, b.GetHypothesisId())
				}
				return ids, r.GetNextPageToken(), err
			},
			before: "a-first",
		},
		{
			name: "GetTimeline",
			add: func(e *brain.Engine, id string) {
				e.Submit(brain.HostObserved{ScopeID: "s", Address: id, OpenPorts: []int{22}})
			},
			fetch: func(ctx context.Context, srv *worldServer, size int32, tok string) ([]string, string, error) {
				r, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{PageSize: size, PageToken: tok})
				ids := make([]string, 0, len(r.GetEvents()))
				for _, ev := range r.GetEvents() {
					ids = append(ids, strconv.FormatUint(ev.GetSeq(), 10))
				}
				return ids, r.GetNextPageToken(), err
			},
			seqKeyed: true,
		},
	}
}

// listAll reads the whole list with one big page.
func (c worldPageCase) listAll(ctx context.Context, t *testing.T, srv *worldServer) []string {
	t.Helper()
	ids, _, err := c.fetch(ctx, srv, 1000, "")
	require.NoError(t, err)
	return ids
}

// await polls until the list holds want rows.
func (c worldPageCase) await(ctx context.Context, t *testing.T, srv *worldServer, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(c.listAll(ctx, t, srv)) >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the list did not reach %d rows", c.name, want)
}

func newWorldPageServer(t *testing.T) (*worldServer, *brain.Registry) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	return NewWorldServer(reg, nil, testWorldKeys(t)), reg
}

// testWorldKeys returns the page token keys of a test server. Two servers of
// one test share the master KEK, like two replicas of the daemon.
func testWorldKeys(t *testing.T) *pagetoken.Keys {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	keys, err := pagetoken.NewKeys(kek)
	require.NoError(t, err)
	return keys
}

func worldTenantCtx(id string) context.Context {
	return auth.WithTenant(context.Background(), auth.MustNewTenantID(id))
}

// Rows that arrive between two pages never make a row come twice or not at
// all. Each row that the client could see at the first page comes back once.
func TestWorldService_PageWalkWithInsertsBetweenPages(t *testing.T) {
	for _, c := range worldPageCases() {
		t.Run(c.name, func(t *testing.T) {
			srv, reg := newWorldPageServer(t)
			ctx := worldTenantCtx("acme")
			e := reg.For("acme")

			seed := []string{"r10", "r20", "r30", "r40", "r50"}
			for _, id := range seed {
				c.add(e, id)
			}
			c.await(ctx, t, srv, len(seed))
			original := c.listAll(ctx, t, srv)
			require.Len(t, original, len(seed))

			page1, tok, err := c.fetch(ctx, srv, 2, "")
			require.NoError(t, err)
			require.Len(t, page1, 2)
			require.NotEmpty(t, tok)

			// Rows arrive between the pages: two after the cursor and, when
			// the list has a key order, one before it.
			late := []string{"r60", "r70"}
			if c.before != "" {
				late = append(late, c.before)
			}
			for _, id := range late {
				c.add(e, id)
			}
			c.await(ctx, t, srv, len(seed)+len(late))

			got := append([]string(nil), page1...)
			pages := 1
			for tok != "" {
				var ids []string
				ids, tok, err = c.fetch(ctx, srv, 2, tok)
				require.NoError(t, err)
				require.NotEmpty(t, ids, "a page with a token must hold rows")
				got = append(got, ids...)
				pages++
				require.Less(t, pages, 20, "the walk does not end")
			}

			count := map[string]int{}
			for _, id := range got {
				count[id]++
			}
			for id, n := range count {
				require.Equal(t, 1, n, "row %q came %d times", id, n)
			}
			for _, id := range original {
				require.Equal(t, 1, count[id], "row %q of the first page walk is missing", id)
			}
			if c.seqKeyed {
				// The new events have a seq after the cursor, so they come too.
				require.Len(t, got, len(seed)+len(late))
			} else {
				for _, id := range []string{"r60", "r70"} {
					require.Equal(t, 1, count[id], "late row %q after the cursor is missing", id)
				}
				require.Zero(t, count[c.before], "a row before the cursor must not come on a later page")
			}
		})
	}
}

// A walk with no change gives every row once, and the last page has no token.
func TestWorldService_PageWalkGivesEachRowOnce(t *testing.T) {
	for _, c := range worldPageCases() {
		t.Run(c.name, func(t *testing.T) {
			srv, reg := newWorldPageServer(t)
			ctx := worldTenantCtx("acme")
			for i := range 7 {
				c.add(reg.For("acme"), "row-"+strconv.Itoa(i))
			}
			c.await(ctx, t, srv, 7)
			want := c.listAll(ctx, t, srv)

			var got []string
			tok := ""
			for range 10 {
				ids, next, err := c.fetch(ctx, srv, 3, tok)
				require.NoError(t, err)
				got = append(got, ids...)
				if next == "" {
					break
				}
				tok = next
			}
			require.Equal(t, want, got)
		})
	}
}

// A token that someone edited, a token from another tenant, a token from
// another RPC and a token that is not a token all give InvalidArgument.
func TestWorldService_ForgedOrForeignTokenIsInvalidArgument(t *testing.T) {
	for _, c := range worldPageCases() {
		t.Run(c.name, func(t *testing.T) {
			srv, reg := newWorldPageServer(t)
			acme := worldTenantCtx("acme")
			other := worldTenantCtx("other")
			for i := range 4 {
				c.add(reg.For("acme"), "row-"+strconv.Itoa(i))
				c.add(reg.For("other"), "row-"+strconv.Itoa(i))
			}
			c.await(acme, t, srv, 4)
			c.await(other, t, srv, 4)

			_, tok, err := c.fetch(acme, srv, 2, "")
			require.NoError(t, err)
			require.NotEmpty(t, tok)

			forged := tok[:len(tok)-2] + "AA"
			if forged == tok {
				forged = tok[:len(tok)-2] + "BB"
			}
			for name, bad := range map[string]struct {
				ctx   context.Context
				token string
			}{
				"cross-tenant": {other, tok},
				"edited":       {acme, forged},
				"garbage":      {acme, "not-a-token"},
				"no signature": {acme, tok[:len(tok)/2]},
			} {
				_, _, err := c.fetch(bad.ctx, srv, 2, bad.token)
				require.Equal(t, codes.InvalidArgument, status.Code(err), name)
			}
		})
	}
}

// A token of one RPC does not open another list.
func TestWorldService_TokenOfAnotherRPCIsInvalidArgument(t *testing.T) {
	srv, reg := newWorldPageServer(t)
	ctx := worldTenantCtx("acme")
	cases := worldPageCases()
	for i := range 4 {
		for _, c := range cases {
			c.add(reg.For("acme"), "row-"+strconv.Itoa(i))
		}
	}
	for _, c := range cases {
		c.await(ctx, t, srv, 4)
	}
	_, tok, err := cases[0].fetch(ctx, srv, 2, "")
	require.NoError(t, err)
	for _, c := range cases[1:] {
		_, _, err := c.fetch(ctx, srv, 2, tok)
		require.Equal(t, codes.InvalidArgument, status.Code(err), c.name)
	}
}

// A timeline token of one mission does not open the slice of another mission.
func TestWorldService_TimelineTokenIsBoundToTheMission(t *testing.T) {
	srv, reg := newWorldPageServer(t)
	ctx := worldTenantCtx("acme")
	e := reg.For("acme")
	e.Submit(brain.MissionStarted{ID: "A", Goal: "a"})
	e.Submit(brain.WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "tool", Target: "nmap"})
	e.Submit(brain.WorkCompleted{ID: "wa1", Result: "ok"})
	e.Submit(brain.MissionStarted{ID: "B", Goal: "b"})

	var tok string
	require.Eventually(t, func() bool {
		r, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{MissionId: "A", PageSize: 1})
		tok = r.GetNextPageToken()
		return err == nil && tok != ""
	}, 5*time.Second, 5*time.Millisecond)

	_, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{MissionId: "B", PageSize: 1, PageToken: tok})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{PageSize: 1, PageToken: tok})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// A signed token whose cursor is not a seq gives InvalidArgument, not a panic.
func TestWorldService_TimelineTokenWithABadSeq(t *testing.T) {
	srv, _ := newWorldPageServer(t)
	ctx := worldTenantCtx("acme")
	pg, err := srv.pageOf(ctx, "GetTimeline", 2, "", "", "no-run")
	require.NoError(t, err)
	tok := pg.Token("not-a-number", true)
	_, err = srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{PageSize: 2, PageToken: tok})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// A cursor past the end of the timeline gives an empty last page.
func TestWorldService_TimelineCursorPastTheEnd(t *testing.T) {
	srv, reg := newWorldPageServer(t)
	ctx := worldTenantCtx("acme")
	reg.For("acme").Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.1", OpenPorts: []int{22}})
	require.Eventually(t, func() bool {
		r, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{})
		return err == nil && len(r.GetEvents()) == 1
	}, 5*time.Second, 5*time.Millisecond)

	pg, err := srv.pageOf(ctx, "GetTimeline", 2, "", "", "no-run")
	require.NoError(t, err)
	tok := pg.Token("99", true)
	r, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{PageSize: 2, PageToken: tok})
	require.NoError(t, err)
	require.Empty(t, r.GetEvents())
	require.Empty(t, r.GetNextPageToken())
}

// The default page size is 100 and a page never holds more than the cap.
func TestWorldService_DefaultPageSize(t *testing.T) {
	srv, reg := newWorldPageServer(t)
	ctx := worldTenantCtx("acme")
	c := worldPageCases()[0] // labels
	for i := range pagetoken.DefaultSize + 5 {
		c.add(reg.For("acme"), "row-"+strconv.Itoa(1000+i))
	}
	c.await(ctx, t, srv, pagetoken.DefaultSize+5)
	r, err := srv.ListLabels(ctx, &worldpb.ListLabelsRequest{})
	require.NoError(t, err)
	require.Len(t, r.GetLabels(), pagetoken.DefaultSize)
	require.NotEmpty(t, r.GetNextPageToken())
}

// Two replicas that share the master KEK read each other tokens.
func TestWorldService_SharedKeyOpensTokensAcrossReplicas(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	a := NewWorldServer(reg, nil, testWorldKeys(t))
	b := NewWorldServer(reg, nil, testWorldKeys(t))

	tctx := worldTenantCtx("acme")
	c := worldPageCases()[0]
	for i := range 4 {
		c.add(reg.For("acme"), "row-"+strconv.Itoa(i))
	}
	c.await(tctx, t, a, 4)
	_, tok, err := c.fetch(tctx, a, 2, "")
	require.NoError(t, err)
	ids, _, err := c.fetch(tctx, b, 2, tok)
	require.NoError(t, err)
	require.Equal(t, []string{"row-2", "row-3"}, ids)

	// A replica with another master KEK refuses the token.
	other := make([]byte, 32)
	keys, err := pagetoken.NewKeys(other)
	require.NoError(t, err)
	_, _, err = c.fetch(tctx, NewWorldServer(reg, nil, keys), 2, tok)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// A new run of a mission changes the slice that GetTimeline pages. A token of
// the old run gives InvalidArgument, and a walk of the new run starts again.
func TestWorldService_TimelineTokenOfAnOldRunIsInvalidArgument(t *testing.T) {
	srv, reg := newWorldPageServer(t)
	ctx := worldTenantCtx("acme")
	e := reg.For("acme")
	e.Submit(brain.MissionProjected{ID: "A", Goal: "a", RunID: "run-1", Nodes: []brain.WorkNode{{ID: "n1"}}})
	e.Submit(brain.MissionStarted{ID: "A", Goal: "a", RunID: "run-1"})
	e.Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.1", MissionID: "A", MissionRunID: "run-1"})

	var tok string
	require.Eventually(t, func() bool {
		r, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{MissionId: "A", PageSize: 1})
		tok = r.GetNextPageToken()
		return err == nil && tok != ""
	}, 5*time.Second, 5*time.Millisecond)

	// Run 1 pages on while nothing else happens.
	_, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{MissionId: "A", PageSize: 1, PageToken: tok})
	require.NoError(t, err)

	// Run 2 starts: the slice now holds run 2 only.
	e.Submit(brain.MissionProjected{ID: "A", Goal: "a", RunID: "run-2", Nodes: []brain.WorkNode{{ID: "n1"}}})
	require.Eventually(t, func() bool {
		_, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{MissionId: "A", PageSize: 1, PageToken: tok})
		return status.Code(err) == codes.InvalidArgument
	}, 5*time.Second, 5*time.Millisecond, "a token of run 1 must stop working when run 2 starts")

	// The client starts again and walks run 2.
	r, err := srv.GetTimeline(ctx, &worldpb.GetTimelineRequest{MissionId: "A", PageSize: 1})
	require.NoError(t, err)
	require.Len(t, r.GetEvents(), 1)
}
