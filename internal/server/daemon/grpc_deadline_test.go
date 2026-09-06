// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// The edge no longer bounds gRPC (ADR-0063), so these assertions are the only
// thing keeping a unary handler bounded at all. Each one fails if the
// interceptor stops doing its job, rather than merely exercising it.

func TestUnaryDeadlineInterceptor_BoundsAHandlerThatOverruns(t *testing.T) {
	t.Parallel()

	interceptor := newUnaryDeadlineInterceptor(50 * time.Millisecond)

	// A handler that never returns on its own. Without the interceptor this
	// blocks until the test binary's own deadline, which is the production
	// failure this guards: nothing upstream gives up either.
	handler := func(ctx context.Context, _ any) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	// Run it off the test goroutine so a MISSING deadline fails this test in a
	// second rather than blocking until the package timeout. When the
	// interceptor is removed, the handler above waits forever — that is the
	// production failure being guarded, and a guard that hangs is a poor guard.
	done := make(chan error, 1)
	go func() {
		_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("handler context should have hit its deadline, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler was never bounded: no deadline reached it, so nothing would ever end this call")
	}
}

func TestUnaryDeadlineInterceptor_CallerDeadlineWinsWhenSooner(t *testing.T) {
	t.Parallel()

	// The interceptor's budget is generous; the caller's is tight. The caller
	// must win, or a client asking for 5s would silently get the server's 60s.
	interceptor := newUnaryDeadlineInterceptor(10 * time.Second)

	var seen time.Duration
	handler := func(ctx context.Context, _ any) (any, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatal("handler saw no deadline at all")
		}
		seen = time.Until(dl)
		return "ok", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler); err != nil {
		t.Fatalf("handler returned %v", err)
	}
	if seen > time.Second {
		t.Fatalf("interceptor overrode the caller's tighter deadline: handler saw %s", seen)
	}
}

func TestUnaryDeadlineInterceptor_ZeroFallsBackToTheDefault(t *testing.T) {
	t.Parallel()

	// A misconfigured zero must not mean "no deadline". That would reintroduce
	// exactly the unbounded-unary hole this interceptor exists to close.
	interceptor := newUnaryDeadlineInterceptor(0)

	var seen time.Duration
	handler := func(ctx context.Context, _ any) (any, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatal("zero duration produced a handler context with no deadline")
		}
		seen = time.Until(dl)
		return nil, nil
	}

	if _, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler); err != nil {
		t.Fatalf("handler returned %v", err)
	}
	if seen < 30*time.Second || seen > defaultUnaryDeadline {
		t.Fatalf("expected the %s default, handler saw %s", defaultUnaryDeadline, seen)
	}
}

func TestResolveUnaryDeadline(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		in         time.Duration
		want       time.Duration
		wantReason bool
	}{
		{"unset takes the default", 0, defaultUnaryDeadline, false},
		{"negative is not silently honoured", -5 * time.Second, defaultUnaryDeadline, true},
		{"below the floor is raised", 100 * time.Millisecond, minUnaryDeadline, true},
		{"above the ceiling is lowered", time.Hour, maxUnaryDeadline, true},
		{"a sane value is kept", 30 * time.Second, 30 * time.Second, false},
		{"the floor itself is kept", minUnaryDeadline, minUnaryDeadline, false},
		{"the ceiling itself is kept", maxUnaryDeadline, maxUnaryDeadline, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, reason := resolveUnaryDeadline(c.in)
			if got != c.want {
				t.Fatalf("resolveUnaryDeadline(%s) = %s, want %s", c.in, got, c.want)
			}
			// An adjustment the operator cannot see is a configuration that
			// silently disagrees with itself.
			if c.wantReason && reason == "" {
				t.Fatalf("%s was adjusted to %s with no reason given", c.in, got)
			}
			if !c.wantReason && reason != "" {
				t.Fatalf("%s was honoured but reported %q", c.in, reason)
			}
		})
	}
}
