// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/observability/lokilogs"
	logspb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/logs/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// pagedLogsQuerier holds total lines, newest first, and returns at most
// q.Limit of them, as Loki does.
type pagedLogsQuerier struct{ total int }

func (p pagedLogsQuerier) lines(limit int) []lokilogs.Entry {
	n := min(limit, p.total)
	out := make([]lokilogs.Entry, 0, n)
	for i := range n {
		out = append(out, lokilogs.Entry{UnixNanos: int64(p.total - i)})
	}
	return out
}

func (p pagedLogsQuerier) QueryMissionLogs(_ context.Context, q lokilogs.MissionQuery) ([]lokilogs.Entry, error) {
	return p.lines(q.Limit), nil
}

func (p pagedLogsQuerier) QueryDaemonLogs(_ context.Context, q lokilogs.DaemonQuery) ([]lokilogs.Entry, error) {
	return p.lines(q.Limit), nil
}

// TestLogsService_PagesWalkEveryEntryOnce proves page_size and page_token
// (ADR-0028 rule 3) for both queries: the pages hold 5 entries, 5 entries,
// then the last 2, with no repeat and no gap.
func TestLogsService_PagesWalkEveryEntryOnce(t *testing.T) {
	srv := NewLogsServer(pagedLogsQuerier{total: 12}, nil)
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	walk := func(t *testing.T, fetch func(token string) ([]*logspb.LogEntry, string, error)) {
		t.Helper()
		var seen []int64
		token := ""
		for range 10 {
			entries, next, err := fetch(token)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			for _, e := range entries {
				seen = append(seen, e.GetUnixNanos())
			}
			if next == "" {
				break
			}
			token = next
		}
		if len(seen) != 12 {
			t.Fatalf("saw %d entries, want 12: %v", len(seen), seen)
		}
		for i, ns := range seen {
			if want := int64(12 - i); ns != want {
				t.Fatalf("entry %d = %d, want %d (a repeat or a gap)", i, ns, want)
			}
		}
	}

	t.Run("mission", func(t *testing.T) {
		walk(t, func(token string) ([]*logspb.LogEntry, string, error) {
			r, err := srv.QueryMissionLogs(ctx, &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 5, PageToken: token})
			return r.GetEntries(), r.GetNextPageToken(), err
		})
	})
	t.Run("daemon", func(t *testing.T) {
		walk(t, func(token string) ([]*logspb.LogEntry, string, error) {
			r, err := srv.QueryDaemonLogs(ctx, &logspb.QueryDaemonLogsRequest{PageSize: 5, PageToken: token})
			return r.GetEntries(), r.GetNextPageToken(), err
		})
	})
}

func TestLogsService_BadPageTokenIsInvalidArgument(t *testing.T) {
	srv := NewLogsServer(pagedLogsQuerier{total: 3}, nil)
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	if _, err := srv.QueryMissionLogs(ctx, &logspb.QueryMissionLogsRequest{MissionId: "m1", PageToken: "not-a-token"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("mission: code = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := srv.QueryDaemonLogs(ctx, &logspb.QueryDaemonLogsRequest{PageToken: "not-a-token"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("daemon: code = %v, want InvalidArgument", status.Code(err))
	}
}
