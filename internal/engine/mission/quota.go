package mission

import "context"

// QuotaCounter is the narrow interface used to maintain per-tenant
// concurrent-mission counters. Spec plans-and-quotas-simplification: INCR
// fires when execution begins (queued → running), DECR fires when the
// mission reaches a terminal state. Implemented by *component.QuotaManager.
// Consumed by the daemon mission manager (nil-safe).
type QuotaCounter interface {
	IncrementMissionCount(ctx context.Context) error
	DecrementMissionCount(ctx context.Context) error
}
