// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/observability/lokilogs"
	logspb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/logs/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

var testLogsKey = bytes.Repeat([]byte{7}, logsCursorKeyLen)

// lokiFake behaves like Loki for the three things that matter to paging:
// start is inclusive, end is exclusive, the newest lines come first, and a
// query returns at most lokilogs.MaxLimit lines. hook runs before each query,
// so a test can add lines between two pages.
type lokiFake struct {
	lines []lokilogs.Entry
	hook  func(*lokiFake)
	calls []int // the Limit of each query
}

func (f *lokiFake) query(start, end time.Time, limit int) []lokilogs.Entry {
	if f.hook != nil {
		f.hook(f)
	}
	f.calls = append(f.calls, limit)
	if limit <= 0 || limit > lokilogs.MaxLimit {
		limit = lokilogs.MaxLimit
	}
	var out []lokilogs.Entry
	for _, e := range f.lines {
		if !start.IsZero() && e.UnixNanos < start.UnixNano() {
			continue
		}
		if !end.IsZero() && e.UnixNanos >= end.UnixNano() {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].UnixNanos != out[j].UnixNanos {
			return out[i].UnixNanos > out[j].UnixNanos
		}
		return out[i].Line < out[j].Line
	})
	return out[:min(limit, len(out))]
}

func (f *lokiFake) QueryMissionLogs(_ context.Context, q lokilogs.MissionQuery) ([]lokilogs.Entry, error) {
	return f.query(q.Start, q.End, q.Limit), nil
}

func (f *lokiFake) QueryDaemonLogs(_ context.Context, q lokilogs.DaemonQuery) ([]lokilogs.Entry, error) {
	return f.query(q.Start, q.End, q.Limit), nil
}

// seedLines makes n lines in the last few minutes. Every third pair shares a
// nanosecond, so the walk crosses ties.
func seedLines(n int, now time.Time) []lokilogs.Entry {
	out := make([]lokilogs.Entry, 0, n)
	for i := range n {
		ns := now.Add(-time.Duration(i/2+1) * time.Millisecond).UnixNano()
		out = append(out, lokilogs.Entry{UnixNanos: ns, Line: fmt.Sprintf("line-%05d", i)})
	}
	return out
}

func logsCtx(tenant string) context.Context {
	return auth.WithTenant(context.Background(), auth.MustNewTenantID(tenant))
}

// TestLogsService_WalkReturnsEveryLineOnce proves gibson#1252: 1500 lines are
// more than one Loki query returns, new lines arrive between the pages, and the
// walk still returns each of the 1500 lines exactly once, for both queries.
func TestLogsService_WalkReturnsEveryLineOnce(t *testing.T) {
	type fetchFn func(srv logspb.LogsServiceServer, token string) ([]*logspb.LogEntry, string, error)
	fetchers := map[string]fetchFn{
		"mission": func(srv logspb.LogsServiceServer, token string) ([]*logspb.LogEntry, string, error) {
			r, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 400, PageToken: token})
			return r.GetEntries(), r.GetNextPageToken(), err
		},
		"daemon": func(srv logspb.LogsServiceServer, token string) ([]*logspb.LogEntry, string, error) {
			r, err := srv.QueryDaemonLogs(logsCtx("acme"), &logspb.QueryDaemonLogsRequest{PageSize: 400, PageToken: token})
			return r.GetEntries(), r.GetNextPageToken(), err
		},
	}
	for name, fetch := range fetchers {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			f := &lokiFake{lines: seedLines(1500, now)}
			want := map[string]bool{}
			for _, e := range f.lines {
				want[e.Line] = true
			}
			arrived := 0
			f.hook = func(f *lokiFake) {
				// A page is fetched: new lines have arrived since the last one.
				if len(f.calls) > 0 {
					for range 25 {
						arrived++
						f.lines = append(f.lines, lokilogs.Entry{
							UnixNanos: now.Add(time.Duration(arrived) * time.Second).UnixNano(),
							Line:      fmt.Sprintf("new-%03d", arrived),
						})
					}
				}
			}
			srv := NewLogsServer(f, testLogsKey, nil)

			seen := map[string]int{}
			token := ""
			for range 20 {
				entries, next, err := fetch(srv, token)
				if err != nil {
					t.Fatalf("fetch: %v", err)
				}
				for _, e := range entries {
					seen[e.GetLine()]++
				}
				if next == "" {
					break
				}
				token = next
			}
			for line := range want {
				if seen[line] != 1 {
					t.Fatalf("line %s seen %d times, want exactly once", line, seen[line])
				}
			}
			for line, n := range seen {
				if !want[line] {
					t.Fatalf("line %s arrived after the first page and must not appear (seen %d)", line, n)
				}
			}
			for _, limit := range f.calls {
				if limit > 400+2 {
					t.Errorf("a page query asked Loki for %d lines; each page must cost about one page", limit)
				}
			}
		})
	}
}

// TestLogsService_RefusesAForgedToken: a token only works for the tenant and
// the query that it was issued for, and an edited token is refused.
func TestLogsService_RefusesAForgedToken(t *testing.T) {
	now := time.Now().UTC()
	f := &lokiFake{lines: seedLines(50, now)}
	srv := NewLogsServer(f, testLogsKey, nil)

	first, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10})
	if err != nil || first.GetNextPageToken() == "" {
		t.Fatalf("first page: token %q, err %v", first.GetNextPageToken(), err)
	}
	token := first.GetNextPageToken()

	if _, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, PageToken: token}); err != nil {
		t.Fatalf("the token must work for its own query: %v", err)
	}

	edited := []byte(token)
	edited[0] ^= 1
	cases := map[string]func() error{
		"another tenant": func() error {
			_, err := srv.QueryMissionLogs(logsCtx("evil"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, PageToken: token})
			return err
		},
		"another mission": func() error {
			_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m2", PageSize: 10, PageToken: token})
			return err
		},
		"another query": func() error {
			_, err := srv.QueryDaemonLogs(logsCtx("acme"), &logspb.QueryDaemonLogsRequest{PageSize: 10, PageToken: token})
			return err
		},
		"another time range": func() error {
			_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, StartUnixNanos: 5, PageToken: token})
			return err
		},
		"an edited token": func() error {
			_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, PageToken: string(edited)})
			return err
		},
		"a made-up token": func() error {
			_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageToken: "AAAA.BBBB"})
			return err
		},
		"a token of another key": func() error {
			other := NewLogsServer(f, bytes.Repeat([]byte{9}, logsCursorKeyLen), nil)
			_, err := other.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, PageToken: token})
			return err
		},
	}
	for name, run := range cases {
		if code := status.Code(run()); code != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, code)
		}
	}
}

func TestDeriveLogsCursorKey(t *testing.T) {
	if _, err := deriveLogsCursorKey([]byte("short")); err == nil {
		t.Fatal("a short master KEK must be refused")
	}
	a, err := deriveLogsCursorKey(bytes.Repeat([]byte{1}, 32))
	if err != nil || len(a) != logsCursorKeyLen {
		t.Fatalf("derive: %v, len %d", err, len(a))
	}
	b, _ := deriveLogsCursorKey(bytes.Repeat([]byte{1}, 32))
	if !bytes.Equal(a, b) {
		t.Fatal("the same master KEK must give the same key on every replica")
	}
}

func TestLogsService_TooManyTiesIsRefused(t *testing.T) {
	now := time.Now().UTC().UnixNano()
	var lines []lokilogs.Entry
	for i := range 1200 {
		lines = append(lines, lokilogs.Entry{UnixNanos: now, Line: fmt.Sprintf("tie-%04d", i)})
	}
	srv := NewLogsServer(&lokiFake{lines: lines}, testLogsKey, nil)
	token := ""
	var err error
	for range 5 {
		var r *logspb.QueryMissionLogsResponse
		r, err = srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 500, PageToken: token})
		if err != nil || r.GetNextPageToken() == "" {
			break
		}
		token = r.GetNextPageToken()
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "share one timestamp") {
		t.Fatalf("err = %v, want FailedPrecondition about ties", err)
	}
}
