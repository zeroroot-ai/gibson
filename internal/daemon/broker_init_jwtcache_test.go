package daemon

// broker_init_jwtcache_test.go — tests for the JWTCache wrapping of
// d.vaultJWTSource in initBrokerStack.
//
// Spec: gibson#321.

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/secrets/jwtsource"
)

// countingJWTSource is a JWTSource that counts how many times Token is called.
// It returns a static token so callers succeed.
type countingJWTSource struct {
	calls atomic.Int64
	token string
}

func (s *countingJWTSource) Token(_ context.Context, _ string) (string, error) {
	s.calls.Add(1)
	// Return a synthetic JWT with a far-future exp so the cache's
	// refresh goroutine sleeps for a long time and doesn't interfere.
	// The exp field is Unix epoch seconds. 9999999999 is year 2286.
	return s.token, nil
}

// TestBrokerInit_JWTCacheWrapsSource verifies that after the cache is started
// (simulated by calling JWTCache.Start directly), subsequent Token calls
// do NOT call the underlying source — they read from the cache.
//
// We test JWTCache directly here rather than exercising the full initBrokerStack
// because wiring the entire broker stack requires Postgres, Redis, and a key
// provider, none of which are available in unit tests. The initBrokerStack
// wiring is verified structurally by the build passing and by the integration
// test suite; this test exercises the cache contract the production code relies on.
func TestBrokerInit_JWTCacheWrapsSource(t *testing.T) {
	t.Parallel()

	const audience = "vault-audience"

	// A minimal JWT: header.payload.signature where payload has a far-future exp.
	// base64url({"alg":"none"}).base64url({"exp":9999999999}).sig
	const syntheticJWT = "eyJhbGciOiJub25lIn0.eyJleHAiOjk5OTk5OTk5OTl9.sig"

	src := &countingJWTSource{token: syntheticJWT}

	cache := jwtsource.NewJWTCache(src, audience, nil)

	// Nil logger path: JWTCache should accept a nil logger gracefully.
	// (In production d.logger.Slog() is always non-nil; nil here exercises
	// the guard in the background refresh-loop warning log.)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := cache.Start(ctx)
	require.NoError(t, err, "JWTCache.Start must succeed with a working source")

	// Start() performed one synchronous fetch.
	assert.Equal(t, int64(1), src.calls.Load(), "Start should call source exactly once")

	// Subsequent Token calls must NOT call the source — they return the cached value.
	tok1, err := cache.Token(ctx, audience)
	require.NoError(t, err)
	assert.Equal(t, syntheticJWT, tok1)
	assert.Equal(t, int64(1), src.calls.Load(), "Token after Start must read from cache, not call source")

	tok2, err := cache.Token(ctx, audience)
	require.NoError(t, err)
	assert.Equal(t, syntheticJWT, tok2)
	assert.Equal(t, int64(1), src.calls.Load(), "repeated Token calls must still read from cache")

	// Confirm the cache satisfies the JWTSource interface (structural check).
	var _ jwtsource.JWTSource = cache
}

// TestBrokerInit_DisabledSourceSkipsCache verifies that when the source is
// DisabledJWTSource, the broker init code's type-assertion guard can correctly
// identify it so the cache is skipped.
//
// The guard in initBrokerStack is:
//
//	if _, isDisabled := d.vaultJWTSource.(jwtsource.DisabledJWTSource); !isDisabled { … }
//
// This test exercises that assertion through the JWTSource interface, mirroring
// the production code path.
func TestBrokerInit_DisabledSourceSkipsCache(t *testing.T) {
	t.Parallel()

	// Assign the DisabledJWTSource to the interface — exactly as daemon.New does.
	var src jwtsource.JWTSource = jwtsource.DisabledJWTSource{}
	_, isDisabled := src.(jwtsource.DisabledJWTSource)
	assert.True(t, isDisabled,
		"DisabledJWTSource must be detectable via type assertion on the JWTSource interface "+
			"so initBrokerStack can skip starting the cache")
}
