// Package brain — TimelineStore: the durable-append seam for the per-tenant
// event Timeline (ADR-0011, gibson#1112/#1113).
package brain

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by stub methods declared for interface
// completeness but implemented in a later slice (#1117).
var ErrNotImplemented = errors.New("brain: not implemented (pending slice)")

// TimelineStore is the durable-log abstraction the brain writes through
// (ADR-0011). The brain package depends only on this interface — no Redis
// types leak into internal/engine/brain.
//
// # Serialisation contract
//
// Events are encoded as JSON envelopes:
//
//	{"kind":"<Event.Kind()>","payload":<json of concrete type>}
//
// The "kind" field drives type reconstruction on replay (slice #1114). Every
// concrete brain.Event type is registered in timeline_codec.go. The codec is
// the ONLY place that maps kind → Go type; Reduce is the ONLY place that maps
// kind → World mutation.
//
// # Stream key scheme
//
//	gibson:timeline:<tenantID>
//
// Per-tenant isolation is structural: each Redis client is already bound to
// a dedicated logical DB (redisPerTenant), so the key carries the tenant id
// as a human-readable label only — cross-tenant key collision is impossible
// on the wire.
//
// # No blind trim
//
// The durable Timeline stream is NEVER blind-trimmed (the old MAXLEN ~10000
// cap is NOT applied). Trimming is snapshot-driven only (WriteSnapshot /
// TrimTo), so the full ordered log is preserved until a snapshot covers it
// (ADR-0011 decision 3b).
type TimelineStore interface {
	// Append durably persists one event at the end of the tenant's Timeline
	// stream and returns the stream sequence ID assigned by the store (e.g.
	// "1751234567890-0" for Redis Streams). Thread-safe; called from the
	// single tick goroutine under Engine.mu.
	Append(ctx context.Context, tenant string, ev Event) (seq string, err error)

	// LoadForReplay returns the ordered slice of events from the tenant's
	// durable Timeline, starting after afterSeq (pass "" to load from the
	// beginning of the stream). Used by slice #1114 (hydrate-on-startup).
	// The returned events are ready to fold via Reduce.
	//
	// Implementations should read in batches internally; callers receive a
	// flat slice.
	LoadForReplay(ctx context.Context, tenant string, afterSeq string) ([]Event, error)

	// WriteSnapshot persists a serialised World snapshot for the tenant and
	// returns an opaque snapshot handle. The handle is passed to TrimTo to
	// prune the Timeline prefix the snapshot covers.
	//
	// Implemented in slice #1117. Stub: returns ("", ErrNotImplemented).
	WriteSnapshot(ctx context.Context, tenant string, snap WorldSnapshot) (handle string, err error)

	// LoadSnapshot loads the latest World snapshot for the tenant. Returns
	// (nil, nil) when no snapshot exists yet.
	//
	// Implemented in slice #1117. Stub: returns (nil, nil).
	LoadSnapshot(ctx context.Context, tenant string) (*WorldSnapshot, error)

	// TrimTo removes Timeline entries that precede the snapshot identified by
	// handle. Must only be called with a valid handle returned by WriteSnapshot.
	//
	// Implemented in slice #1117. Stub: returns ErrNotImplemented.
	TrimTo(ctx context.Context, tenant string, handle string) error
}

// WorldSnapshot is the serialised form of a tenant World at a point in the
// Timeline. Opaque to this slice; shape is finalised in slice #1117.
type WorldSnapshot struct {
	// AtSeq is the Timeline sequence ID of the last event folded into this
	// snapshot. TrimTo prunes events up to and including AtSeq.
	AtSeq string
	// Data carries the serialised World bytes (encoding TBD by #1117).
	Data []byte
}
