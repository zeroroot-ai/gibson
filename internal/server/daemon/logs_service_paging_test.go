// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
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
	// Loki picks the lines of a tie group that fill the limit in its own
	// order. This fake uses the reverse of the order that the client sorts by,
	// so a page that ends inside a tie group loses lines and repeats others.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].UnixNanos != out[j].UnixNanos {
			return out[i].UnixNanos > out[j].UnixNanos
		}
		return out[i].Line > out[j].Line
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
	cases := map[string]func() codes.Code{
		"another tenant": func() codes.Code {
			_, err := srv.QueryMissionLogs(logsCtx("evil"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, PageToken: token})
			return status.Code(err)
		},
		"another mission": func() codes.Code {
			_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m2", PageSize: 10, PageToken: token})
			return status.Code(err)
		},
		"another query": func() codes.Code {
			_, err := srv.QueryDaemonLogs(logsCtx("acme"), &logspb.QueryDaemonLogsRequest{PageSize: 10, PageToken: token})
			return status.Code(err)
		},
		"another time range": func() codes.Code {
			_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, StartUnixNanos: 5, PageToken: token})
			return status.Code(err)
		},
		"an edited token": func() codes.Code {
			_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, PageToken: string(edited)})
			return status.Code(err)
		},
		"a made-up token": func() codes.Code {
			_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageToken: "AAAA.BBBB"})
			return status.Code(err)
		},
		"a token of another key": func() codes.Code {
			other := NewLogsServer(f, bytes.Repeat([]byte{9}, logsCursorKeyLen), nil)
			_, err := other.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 10, PageToken: token})
			return status.Code(err)
		},
	}
	for name, run := range cases {
		if code := run(); code != codes.InvalidArgument {
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
	lines := make([]lokilogs.Entry, 0, 1200)
	for i := range 1200 {
		lines = append(lines, lokilogs.Entry{UnixNanos: now, Line: fmt.Sprintf("tie-%04d", i)})
	}
	srv := NewLogsServer(&lokiFake{lines: lines}, testLogsKey, nil)
	_, err := srv.QueryMissionLogs(logsCtx("acme"), &logspb.QueryMissionLogsRequest{MissionId: "m1", PageSize: 500})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "share one timestamp") {
		t.Fatalf("err = %v, want FailedPrecondition about ties", err)
	}
}

// A tie group that spans the page edge is moved whole to the next page, and a
// group that fills a page is read with a larger Loki limit.
func TestLogsService_TieGroupAtThePageEdge(t *testing.T) {
	base := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	at := func(ms int) int64 { return base.Add(time.Duration(ms) * time.Millisecond).UnixNano() }
	f := &lokiFake{lines: []lokilogs.Entry{
		{UnixNanos: at(1), Line: "a"},
		{UnixNanos: at(2), Line: "b1"}, {UnixNanos: at(2), Line: "b2"}, {UnixNanos: at(2), Line: "b3"},
		{UnixNanos: at(3), Line: "c"},
	}}
	srv := NewLogsServer(f, testLogsKey, nil)

	var got []string
	token := ""
	for range 10 {
		r, err := srv.QueryDaemonLogs(logsCtx("acme"), &logspb.QueryDaemonLogsRequest{
			PageSize: 2, PageToken: token, StartUnixNanos: base.UnixNano() - 1,
		})
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		for _, e := range r.GetEntries() {
			got = append(got, e.GetLine())
		}
		if r.GetNextPageToken() == "" {
			break
		}
		token = r.GetNextPageToken()
	}
	sort.Strings(got)
	if want := "a b1 b2 b3 c"; strings.Join(got, " ") != want {
		t.Fatalf("lines = %v, want each of %q exactly once", got, want)
	}
}

type stubKeyProvider struct {
	key []byte
	err error
}

func (s stubKeyProvider) GetEncryptionKey(context.Context) ([]byte, error) { return s.key, s.err }
func (stubKeyProvider) Name() string                                       { return "stub" }
func (stubKeyProvider) Health(context.Context) types.HealthStatus          { return types.HealthStatus{} }
func (stubKeyProvider) Close() error                                       { return nil }

// The daemon refuses to start LogsService without a master KEK it can use.
func TestLogsCursorKeyFromProvider(t *testing.T) {
	ctx := context.Background()
	if _, err := logsCursorKeyFromProvider(ctx, nil); err == nil {
		t.Error("no key provider must be refused")
	}
	if _, err := logsCursorKeyFromProvider(ctx, stubKeyProvider{err: errors.New("vault down")}); err == nil {
		t.Error("a KEK read failure must be refused")
	}
	if _, err := logsCursorKeyFromProvider(ctx, stubKeyProvider{key: []byte("short")}); err == nil {
		t.Error("a short KEK must be refused")
	}
	key, err := logsCursorKeyFromProvider(ctx, stubKeyProvider{key: bytes.Repeat([]byte{3}, 32)})
	if err != nil || len(key) != logsCursorKeyLen {
		t.Fatalf("key: len %d, err %v", len(key), err)
	}
}

func TestNewLogsServer_RefusesAShortKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a short cursor key must panic at construction")
		}
	}()
	NewLogsServer(&lokiFake{}, []byte("short"), nil)
}

func TestLogsPageSize(t *testing.T) {
	for in, want := range map[int32]int{0: 100, -4: 100, 25: 25, 5000: lokilogs.MaxLimit} {
		if got := logsPageSize(in); got != want {
			t.Errorf("logsPageSize(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestDecodeLogsCursor_RefusesATokenWithNoSignature(t *testing.T) {
	if _, err := decodeLogsCursor(testLogsKey, logsQueryScope{}, "nodothere"); err == nil {
		t.Error("a token with no signature part must be refused")
	}
}
