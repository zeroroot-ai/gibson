package transport

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"time"

	"connectrpc.com/connect"
)

const (
	// DefaultMaxAttempts is the default maximum number of attempts for a
	// retryable call (1 initial + 4 retries).
	DefaultMaxAttempts = 5

	// DefaultBaseDelay is the initial retry delay before jitter.
	DefaultBaseDelay = 100 * time.Millisecond

	// DefaultMaxDelay caps the per-attempt sleep so callers are not blocked
	// indefinitely on a degraded backend.
	DefaultMaxDelay = 5 * time.Second
)

// RetryPolicy configures the client retry behaviour.
type RetryPolicy struct {
	// MaxAttempts is the total number of call attempts (including the first).
	// Zero means DefaultMaxAttempts.
	MaxAttempts int

	// BaseDelay is the initial backoff duration before jitter. Zero means
	// DefaultBaseDelay.
	BaseDelay time.Duration

	// MaxDelay caps the per-attempt backoff. Zero means DefaultMaxDelay.
	MaxDelay time.Duration

	// TestClock is substituted in tests to avoid real sleeps. Leave nil in
	// production; the real clock is used automatically.
	TestClock clockIface
}

// clockIface exists so tests can inject a fake clock without depending on an
// external library from production paths.
type clockIface interface {
	Sleep(ctx context.Context, d time.Duration) error
}

// realClock sleeps using time.Sleep and returns ctx.Err() if the context is
// cancelled during the sleep.
type realClock struct{}

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retryableCode returns true for ConnectRPC status codes that are safe to
// retry: Unavailable and DeadlineExceeded indicate transient backend problems;
// all other codes are treated as terminal (the server made a decision).
func retryableCode(c connect.Code) bool {
	return c == connect.CodeUnavailable || c == connect.CodeDeadlineExceeded
}

// retryClientInterceptor returns a connect.Interceptor that retries failed
// calls using exponential back-off with full-jitter.
//
// Retry decisions are made on connect.CodeUnavailable and
// connect.CodeDeadlineExceeded; all other codes are returned immediately.
// Each sleep is bounded by MaxDelay and respects context cancellation.
func retryClientInterceptor(policy RetryPolicy) connect.Interceptor {
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = DefaultMaxAttempts
	}
	if policy.BaseDelay <= 0 {
		policy.BaseDelay = DefaultBaseDelay
	}
	if policy.MaxDelay <= 0 {
		policy.MaxDelay = DefaultMaxDelay
	}
	clk := policy.TestClock
	if clk == nil {
		clk = realClock{}
	}

	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			var lastErr error
			for attempt := range policy.MaxAttempts {
				if attempt > 0 {
					delay := jitteredDelay(policy.BaseDelay, policy.MaxDelay, attempt)
					if err := clk.Sleep(ctx, delay); err != nil {
						// Context cancelled during backoff — return the
						// last RPC error so callers see the real cause,
						// not a context error that obscures the root cause.
						if lastErr != nil {
							return nil, lastErr
						}
						return nil, connect.NewError(connect.CodeCanceled, err)
					}
				}

				resp, err := next(ctx, req)
				if err == nil {
					return resp, nil
				}
				lastErr = err

				var cerr *connect.Error
				if !errors.As(err, &cerr) || !retryableCode(cerr.Code()) {
					return nil, err
				}
				// Retryable — continue to next attempt.
			}
			return nil, lastErr
		}
	})
}

// jitteredDelay computes full-jitter exponential backoff:
//
//	sleep = random(0, min(maxDelay, baseDelay * 2^attempt))
//
// "Full jitter" (as defined in the AWS backoff blog) spreads retries across
// the window so multiple simultaneous callers do not all hammer the backend at
// the same instant.
func jitteredDelay(base, maxDelay time.Duration, attempt int) time.Duration {
	cap := float64(base) * math.Pow(2, float64(attempt-1))
	if d := time.Duration(cap); d > maxDelay {
		cap = float64(maxDelay)
	}
	return time.Duration(rand.Float64() * cap) //nolint:gosec // full-jitter; crypto not required
}
