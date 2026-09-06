// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// user_state_signup_progress_test.go — bounds on the pre-authentication
// signup-progress store.
//
// SetSignupProgress runs before any identity exists and keys on an attempt_id
// the caller invents, so there is no subject to scope a key to. What is left
// is bounding what an unattributable caller can occupy: how long a document
// lives, how large it is, and how many can exist at once.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// newSignupProgressServer wires a DaemonServer over miniredis and hands back
// the miniredis handle, so tests can read the TTL Redis actually recorded
// rather than the one the handler intended.
func newSignupProgressServer(t *testing.T) (*DaemonServer, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	srv := &DaemonServer{logger: testSlogLogger}
	srv.WithUserStateRedis(client)
	return srv, mr
}

func setProgress(t *testing.T, srv *DaemonServer, attemptID string, ttlSeconds int32) error {
	t.Helper()
	_, err := srv.SetSignupProgress(context.Background(), &tenantv1.SetSignupProgressRequest{
		AttemptId:  attemptID,
		TtlSeconds: ttlSeconds,
		Progress:   &tenantv1.SignupProgressState{Step: "card"},
	})
	return err
}

// attemptID builds a distinct well-formed UUID per index. The handler only
// checks the shape, which is the point: shape is all an unauthenticated caller
// has to satisfy, so the cap cannot rely on ids being hard to produce.
func attemptID(i int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
}

// TestSetSignupProgress_TTLIsClamped is the finding itself: ttl_seconds was
// taken verbatim, so the caller decided how long its document stayed resident
// in a Redis the rest of the platform shares.
func TestSetSignupProgress_TTLIsClamped(t *testing.T) {
	cases := []struct {
		name       string
		ttlSeconds int32
		want       time.Duration
	}{
		{"absent means the default", 0, signupProgressDefTTL},
		{"negative means the default", -1, signupProgressDefTTL},
		{"a sane value is honoured", 120, 2 * time.Minute},
		{"the maximum is honoured", int32(signupProgressMaxTTL / time.Second), signupProgressMaxTTL},
		{"over the maximum is clamped", 30 * 24 * 3600, signupProgressMaxTTL},
		{"the largest int32 is clamped", 1<<31 - 1, signupProgressMaxTTL},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, mr := newSignupProgressServer(t)
			id := attemptID(i)
			require.NoError(t, setProgress(t, srv, id, tc.ttlSeconds))

			got := mr.TTL(signupProgressKey(id))
			require.Equal(t, tc.want, got, "ttl_seconds=%d", tc.ttlSeconds)
			require.LessOrEqual(t, got, signupProgressMaxTTL,
				"no caller-supplied value may exceed the cap")
			require.Positive(t, got, "the document must always expire on its own")
		})
	}
}

// TestSetSignupProgress_PayloadIsBounded — the document is caller-supplied and
// goes into shared memory, so its size is capped too.
func TestSetSignupProgress_PayloadIsBounded(t *testing.T) {
	srv, _ := newSignupProgressServer(t)
	_, err := srv.SetSignupProgress(context.Background(), &tenantv1.SetSignupProgressRequest{
		AttemptId: attemptID(1),
		Progress:  &tenantv1.SignupProgressState{Step: strings.Repeat("x", signupProgressMaxBytes+1)},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"an oversized progress document must be refused")
}

// TestSetSignupProgress_OutstandingAttemptsAreBounded is the other half of the
// TTL cap. Bounding a document's lifetime is worth little if a caller can
// create arbitrarily many of them, and shape-checked UUIDs are free to
// produce. Past the cap the oldest documents go, so a burst costs its own
// entries rather than the store.
func TestSetSignupProgress_OutstandingAttemptsAreBounded(t *testing.T) {
	srv, mr := newSignupProgressServer(t)

	// Fill to the cap, then push a handful more.
	const over = 5
	for i := range signupProgressMaxOutstanding + over {
		require.NoError(t, setProgress(t, srv, attemptID(i), 0))
	}

	live := 0
	for i := range signupProgressMaxOutstanding + over {
		if mr.Exists(signupProgressKey(attemptID(i))) {
			live++
		}
	}
	require.LessOrEqual(t, live, signupProgressMaxOutstanding,
		"the number of live progress documents must be capped")

	// The most recent writes survive; the oldest are the ones dropped.
	newest := attemptID(signupProgressMaxOutstanding + over - 1)
	require.True(t, mr.Exists(signupProgressKey(newest)), "the newest write must survive eviction")
	require.False(t, mr.Exists(signupProgressKey(attemptID(0))), "the oldest write must be the one evicted")
}

// TestSetSignupProgress_StillRoundTripsUnderTheCap is the control: the bounds
// must not break the flow they protect.
func TestSetSignupProgress_StillRoundTripsUnderTheCap(t *testing.T) {
	srv, _ := newSignupProgressServer(t)
	id := attemptID(7)
	require.NoError(t, setProgress(t, srv, id, 60))

	resp, err := srv.GetSignupProgress(context.Background(), &tenantv1.GetSignupProgressRequest{AttemptId: id})
	require.NoError(t, err)
	require.True(t, resp.GetFound())
	require.Equal(t, "card", resp.GetProgress().GetStep())
}

// TestSetSignupProgress_IndexMaintenanceIsBestEffort — the cap is enforced
// after the write is acknowledged, so a Redis that cannot maintain the index
// must cost eviction ordering, not the caller's request.
func TestSetSignupProgress_IndexMaintenanceIsBestEffort(t *testing.T) {
	// A closed miniredis is not a broken Redis the client agrees on: a pooled
	// connection or a retry can still carry the first command, so the
	// assertion below raced. A unix socket that does not exist fails to dial
	// every time, and MaxRetries -1 turns off the client's own retries.
	client := goredis.NewClient(&goredis.Options{
		Network:    "unix",
		Addr:       filepath.Join(t.TempDir(), "there-is-no-redis.sock"),
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = client.Close() })
	srv := &DaemonServer{logger: testSlogLogger}
	srv.WithUserStateRedis(client)

	err := trimSignupProgressIndex(context.Background(), client, time.Now())
	require.Error(t, err, "the worker must report a broken index rather than swallow it")

	// And the wrapper turns that into a log line, not a failure.
	require.NotPanics(t, func() {
		srv.trimSignupProgress(context.Background(), client, time.Now())
	})
}

// TestTrimSignupProgressIndex_NoOpUnderTheCap pins the early exits: below the
// cap there is nothing to evict, and the index is left alone.
func TestTrimSignupProgressIndex_NoOpUnderTheCap(t *testing.T) {
	srv, mr := newSignupProgressServer(t)
	require.NoError(t, setProgress(t, srv, attemptID(1), 0))

	require.NoError(t, trimSignupProgressIndex(context.Background(), srv.userStateRedis, time.Now()))
	require.True(t, mr.Exists(signupProgressKey(attemptID(1))),
		"a document well under the cap must not be evicted")
}
