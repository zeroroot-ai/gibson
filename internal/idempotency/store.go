// Package idempotency implements a daemon-side dedup store for the
// `idempotency_key` field convention defined by platform-sdk's
// CONVENTIONS.md (added in platform-sdk#2; PRD zero-day-ai/.github#101).
//
// Mutating RPCs that carry a non-empty `idempotency_key` field are
// deduplicated by the gRPC server interceptor in
// internal/daemon/interceptor_idempotency.go: on first execution the
// (response or terminal error) is cached under
//
//	idempotency:{tenant}:{method}:{key}
//
// with a configurable TTL (default 24h). Subsequent calls within the
// TTL receive the same cached outcome without re-executing the handler.
//
// Race condition: two callers can present the same key concurrently.
// The Redis-backed implementation uses SET NX to plant a "pending"
// sentinel as soon as the handler starts; the second caller observes
// the sentinel and brief-polls for the real response. This keeps
// "concurrent same-key produces one execution" honest within a single
// pod and across replicas (Redis is the synchronisation point).
package idempotency

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
)

// CachedResponse is the structured outcome of a previously-executed
// mutating RPC. Exactly one of Response / TerminalError is populated.
//
//   - Response carries the proto response message, packed as Any so the
//     interceptor can re-emit the typed bytes on the wire for the
//     duplicate caller.
//   - TerminalError carries the gRPC status of a permanent failure;
//     replaying a permanent failure on every retry is part of the
//     dedup contract (we do not silently retry on a known-bad input).
type CachedResponse struct {
	Response      *anypb.Any
	TerminalError *TerminalError
}

// TerminalError is the cacheable form of a permanent gRPC failure. We
// store the canonical status code + message; transient codes
// (Unavailable / DeadlineExceeded / etc.) MUST NOT be cached — the
// interceptor filters them out before calling Set.
type TerminalError struct {
	// Code is the numeric value of google.golang.org/grpc/codes.Code.
	// Stored as int32 so the wire encoding is stable independent of
	// the grpc-go version.
	Code int32
	// Message is the user-visible error message (already scrubbed by
	// the upstream error-scrub interceptor).
	Message string
}

// ErrNotFound is returned by Store.Get when no cached response exists
// for the given (tenant, method, key) triple.
var ErrNotFound = errors.New("idempotency: cache miss")

// Store is the interface every dedup backend must satisfy. Concrete
// implementations:
//   - RedisStore (production)
//   - inMemoryStore (unit-test default; see store_inmem.go)
//
// Implementations MUST be safe for concurrent use from many goroutines.
type Store interface {
	// Get returns a previously-cached CachedResponse for the given
	// (tenant, method, key) triple. Returns (nil, false, nil) on cache
	// miss (ErrNotFound is reserved for backend errors that look like
	// misses — most callers should use the bool).
	//
	// When the implementation supports a "pending" sentinel (Redis
	// SET NX), Get may briefly block waiting for a concurrent caller's
	// in-flight execution to complete; the timeout for that wait is
	// implementation-defined (Redis: 5s).
	Get(ctx context.Context, tenant, method, key string) (cached *CachedResponse, found bool, err error)

	// Set stores the (tenant, method, key) → cached response mapping
	// with the supplied TTL. Implementations MUST overwrite any
	// "pending" sentinel atomically so a concurrent Get sees the real
	// response on its next poll.
	Set(ctx context.Context, tenant, method, key string, cached *CachedResponse, ttl time.Duration) error

	// MarkPending plants a sentinel indicating that an execution is
	// in flight for this (tenant, method, key). Returns (true, nil)
	// when the sentinel was planted (caller proceeds to execute the
	// handler); returns (false, nil) when a sentinel or real cached
	// response already exists (caller should re-Get to fetch it).
	//
	// The sentinel TTL is the supplied pendingTTL; it should be
	// large enough to bound the longest plausible handler execution
	// but small enough that a crashed handler doesn't permanently
	// block the key (suggested: 30s).
	MarkPending(ctx context.Context, tenant, method, key string, pendingTTL time.Duration) (planted bool, err error)
}

// DefaultTTL is the cache lifetime for successful responses and
// terminal errors when the caller does not specify a per-call override.
// 24h matches the convention documented in platform-sdk CONVENTIONS.md.
const DefaultTTL = 24 * time.Hour

// DefaultPendingTTL bounds how long a single in-flight handler can
// hold the dedup sentinel before another caller is allowed to
// re-execute. Long enough to cover all current Create/Run/Update/Start
// handlers (the slowest, RunMission startup, is ~5s today); short
// enough that a crashed daemon doesn't pin a key for a day.
const DefaultPendingTTL = 30 * time.Second

// MaxWaitForPending is the upper bound on how long Store.Get blocks
// when it observes a "pending" sentinel before giving up and returning
// (nil, false, nil). The interceptor falls back to re-execution on
// timeout — preferable to hanging the caller indefinitely.
const MaxWaitForPending = 5 * time.Second
