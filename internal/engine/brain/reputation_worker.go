// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"sort"
	"sync"
	"time"
)

// reputation_worker.go is gibson#267's reputation WRITE loop: the production
// caller that makes a settled bet update the matching technique×environment
// reputation (AC2). It reacts to a settled bet and recomputes that reputation
// from the full, already-folded settled-bet history via
// Engine.UpdateReputation (reputation.go).
//
// It is the tap + off-tick-drain pattern WireVoIPlanner already uses, and for
// the same hard reason: Engine.UpdateReputation reads BetSettlements() (a
// read-locking accessor) and writes through WorldBeliefSubstrate (which Submits
// a NodeBeliefSet event), so it MUST NOT run under the tick's write lock.
// Recomputing imperatively right after Engine.SettleBetX would be wrong anyway:
// a settlement Submits its event asynchronously (ADR-0101), so the recompute
// would miss the very bet that triggered it. Draining OFF the tick, after the
// settlement has folded, is what lets the recompute see it.
//
// A technique×environment reputation is always exactly rebuildable from the
// settled-bet history (reputation.go), so the writes this worker Submits
// (NodeBeliefSet) re-fold identically on replay, and the tap — like every tap —
// never fires on replay (ADR-0109). Live and replay therefore agree.

// techniqueEnv is the (technique, environment) key a settled bet's reputation
// is addressed by (ADR-0129) — environment is the bet's ScopeID, the same
// coordinate every other observation in this package partitions identity by.
type techniqueEnv struct {
	technique string
	scopeID   string
}

// ReputationWorker buffers the technique×environment key of each settled bet
// (live, in-tick) and recomputes that reputation off the tick.
type ReputationWorker struct {
	eng       *Engine
	substrate BeliefSubstrate

	mu      sync.Mutex
	pending map[techniqueEnv]struct{}
}

// NewReputationWorker builds a worker. substrate is typically a
// WorldBeliefSubstrate bound to the same eng (the reputation write must land on
// the same belief store GetReputation/voi_plan read), the same convention
// NewVoIWorker follows.
func NewReputationWorker(eng *Engine, substrate BeliefSubstrate) *ReputationWorker {
	return &ReputationWorker{eng: eng, substrate: substrate, pending: map[techniqueEnv]struct{}{}}
}

// Tap is the engine subscriber (in-tick, no I/O): buffer the settled bet's
// technique×environment key. All three settlement paths (predicate, exhaustion,
// HITL) now carry a Technique (bet_settlement.go), so a settled bet of any
// method updates reputation. A settlement with no recorded technique is skipped
// here — it keys no technique×environment node, the same "surfaced, not hidden"
// gap ComputeReputation already skips.
func (rw *ReputationWorker) Tap(ev Event) {
	var key techniqueEnv
	switch e := ev.(type) {
	case BetSettledTrue:
		key = techniqueEnv{technique: e.Technique, scopeID: e.ScopeID}
	case BetSettledFalse:
		key = techniqueEnv{technique: e.Technique, scopeID: e.ScopeID}
	case BetSettledByHITL:
		key = techniqueEnv{technique: e.Technique, scopeID: e.ScopeID}
	default:
		return
	}
	if key.technique == "" {
		return
	}
	rw.mu.Lock()
	rw.pending[key] = struct{}{}
	rw.mu.Unlock()
}

// Drain recomputes every buffered technique×environment reputation off the
// tick, in deterministic (technique, scope) order. Returns the number
// recomputed.
//
// Each key is recomputed from the engine's full, already-folded settled-bet
// history: the Tap fired AFTER Reduce folded the settlement, and this Drain
// runs after that tick, so Engine.UpdateReputation always sees the bet that
// triggered it (the recompute-from-history contract reputation.go documents).
func (rw *ReputationWorker) Drain(ctx context.Context) int {
	rw.mu.Lock()
	buffered := rw.pending
	rw.pending = map[techniqueEnv]struct{}{}
	rw.mu.Unlock()

	keys := make([]techniqueEnv, 0, len(buffered))
	for key := range buffered {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].technique != keys[j].technique {
			return keys[i].technique < keys[j].technique
		}
		return keys[i].scopeID < keys[j].scopeID
	})

	for _, key := range keys {
		// A failed reputation write never kills a mission: the settled bet
		// stands, and the next settlement on this key recomputes it in full
		// (UpdateReputation is a full overwrite, never a blend), so a transient
		// miss self-heals — the same failure stance VoIWorker.plan takes.
		_, _ = rw.eng.UpdateReputation(ctx, key.technique, key.scopeID, rw.substrate)
	}
	return len(keys)
}

// WireReputation installs gibson#267's reputation write loop against eng: a live
// tap buffers each settled bet's technique×environment key, and an off-tick
// drain loop recomputes that reputation via Engine.UpdateReputation. Mirrors
// WireVoIPlanner/WireSliceBelief's ticker pattern exactly. interval <= 0 uses
// TickInterval.
func WireReputation(ctx context.Context, eng *Engine, interval time.Duration) *ReputationWorker {
	if interval <= 0 {
		interval = TickInterval
	}
	worker := NewReputationWorker(eng, NewWorldBeliefSubstrate(eng))
	eng.Subscribe(worker.Tap)

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				// context.WithoutCancel: the final drain must still run after
				// ctx is done, but must not inherit ctx's already-fired
				// cancellation, or UpdateReputation's own substrate calls would
				// fail immediately on ctx.Err() (contextcheck) — the same
				// shutdown-drain WireVoIPlanner performs.
				worker.Drain(context.WithoutCancel(ctx))
				return
			case <-t.C:
				worker.Drain(ctx)
			}
		}
	}()

	return worker
}
