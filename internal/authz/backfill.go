// Package authz — backfill scaffold for resource-parent tuples.
//
// This file provides BackfillResourceParents — a resumable, idempotent routine
// that writes FGA `parent` tuples linking every tenant-scoped resource (mission,
// run, target, mission_definition, finding) to its owning tenant. The new FGA
// object types are defined in model.fga (see spec
// phase-1-daemon-critical-exfil-fixes, Task 4).
//
// Phase 1 ships the scaffold guarded off by the feature flag
// `fga_resource_objects_v2`. The per-resource iteration bodies return
// ErrBackfillNotImplemented for each resource kind; the enclosing control flow
// (flag guard, per-kind loop, cursor persistence, metric emission, error
// accumulation) is fully implemented so Phase 2 only has to fill the iterator
// callbacks (see spec Task 18).
//
// Design notes:
//
//   - Idempotent: every tuple is a `parent` tuple; FGA writes are already
//     idempotent (duplicate writes are no-ops) and the resume token ensures
//     re-runs skip already-processed ranges even when the FGA store is shared.
//   - Resumable: the cursor is persisted to Redis under
//     `gibson:backfill:resource_parents:cursor:{resource_kind}` every
//     `BackfillDeps.CheckpointEvery` items (default 1000). An interrupted run
//     restarts from the last persisted cursor.
//   - Never per-request: this file does NOT emit tuples on read/check paths.
//     Tuples come from (a) resource Create handlers (Phase 2 provisioning) and
//     (b) this backfill.
//   - No daemon-layer imports: the function takes interface-typed dependencies
//     so the authz package stays at the bottom of the import graph.
package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// BackfillFeatureFlag is the exact string that must be passed as the
// featureFlag argument to BackfillResourceParents for iteration bodies to run.
// Any other value (including "") causes the function to return immediately
// with an empty report and nil error. Phase 1 ships without any caller passing
// this string; Phase 2 wires it in.
const BackfillFeatureFlag = "fga_resource_objects_v2"

// ErrBackfillNotImplemented is returned by the per-kind iteration callbacks
// that Phase 2 will fill in. Phase 1 surfaces these in the report's per-kind
// Errors counter without aborting the whole backfill.
var ErrBackfillNotImplemented = errors.New("authz: backfill iterator not yet implemented for this resource kind (Phase 2)")

// ResourceKind identifies one of the tenant-parented FGA object types that
// the backfill writes tuples for. Phase 1 covers five kinds; `component`
// lives in the existing `component` type which already carries tenant scope
// via direct_execute on tenant#member and is intentionally excluded here.
type ResourceKind string

const (
	ResourceKindMission           ResourceKind = "mission"
	ResourceKindRun               ResourceKind = "run"
	ResourceKindTarget            ResourceKind = "target"
	ResourceKindMissionDefinition ResourceKind = "mission_definition"
	ResourceKindFinding           ResourceKind = "finding"
)

// AllBackfillResourceKinds is the ordered list the backfill iterates over.
// Order is stable so tests can assert on it and so metrics emit in a
// predictable sequence.
var AllBackfillResourceKinds = []ResourceKind{
	ResourceKindMission,
	ResourceKindRun,
	ResourceKindTarget,
	ResourceKindMissionDefinition,
	ResourceKindFinding,
}

// defaultCheckpointEvery is the default number of processed items between
// cursor persistence writes.
const defaultCheckpointEvery = 1000

// cursorKeyPrefix is the Redis key prefix used for per-resource-kind resume
// cursors. The full key is `gibson:backfill:resource_parents:cursor:<kind>`.
const cursorKeyPrefix = "gibson:backfill:resource_parents:cursor:"

// TupleWriter is the narrow slice of Authorizer the backfill needs. A real
// authz.Authorizer satisfies this; test doubles can stub just Write.
type TupleWriter interface {
	Write(ctx context.Context, tuples []Tuple) error
}

// CursorStore persists and retrieves per-resource-kind resume cursors.
// The daemon wires a Redis-backed implementation; tests use an in-memory stub.
type CursorStore interface {
	// Get returns the saved cursor for the given key, or ("", nil) if absent.
	// A non-nil error indicates a transport failure.
	Get(ctx context.Context, key string) (string, error)

	// Set writes the cursor under the given key. Overwrites any prior value.
	Set(ctx context.Context, key, value string) error
}

// ResourceIterator walks every resource of a single kind in the daemon's
// backing store. The walker is called once per item; returning a non-nil
// error from walker halts iteration for that kind and surfaces the error
// in the per-kind Errors counter.
//
// The cursor parameter is the caller-supplied resume token (empty string
// on first call). On each CheckpointEvery-th walker invocation, the
// iterator callback is expected to return a non-empty cursor via its
// `nextCursor` return so the backfill can persist it. When iteration
// completes (no more items), the callback returns (nextCursor="", done=true).
//
// Phase 1 returns ErrBackfillNotImplemented from every ResourceIterator
// registered for a kind; Phase 2 wires real store iterators.
type ResourceIterator func(
	ctx context.Context,
	cursor string,
	walker func(tenantID, resourceID string) error,
) (nextCursor string, done bool, err error)

// BackfillDeps is the dependency bundle for BackfillResourceParents.
// Every field must be set except Iterators — an unset iterator for a kind
// causes that kind to be skipped with an "iterator_missing" error count.
type BackfillDeps struct {
	// Writer is the FGA tuple writer used to emit `parent` tuples.
	Writer TupleWriter

	// Cursors persists per-kind resume tokens.
	Cursors CursorStore

	// Iterators maps resource kind to its store walker. Phase 1 leaves this
	// empty by convention (flag is off anyway); Phase 2 populates it.
	Iterators map[ResourceKind]ResourceIterator

	// Metrics are the Prometheus counters for per-kind scanned / written /
	// errors. Use NewBackfillMetrics to construct; pass the same instance
	// across calls so counters accumulate.
	Metrics *BackfillMetrics

	// CheckpointEvery is the number of processed items between cursor
	// persistence writes. Zero means use defaultCheckpointEvery (1000).
	CheckpointEvery int
}

// BackfillMetrics holds the Prometheus counters emitted by the backfill.
// Construct via NewBackfillMetrics so the counters are initialised with the
// right names/help text. Register with a prometheus.Registerer separately
// (Phase 2 wires registration alongside iterator population).
type BackfillMetrics struct {
	// Scanned counts every resource the iterator yields to the walker,
	// labeled by resource_kind.
	Scanned *prometheus.CounterVec

	// Written counts every `parent` tuple successfully written to FGA,
	// labeled by resource_kind.
	Written *prometheus.CounterVec

	// Errors counts per-kind failures — iterator errors, writer errors,
	// cursor-persistence errors. Low-cardinality on purpose; the per-error
	// detail is in logs.
	Errors *prometheus.CounterVec
}

// NewBackfillMetrics constructs the CounterVec trio with their canonical
// gibson_fga_backfill_* names. The constructor does not auto-register;
// callers pass the collectors to a prometheus.Registerer.
func NewBackfillMetrics() *BackfillMetrics {
	return &BackfillMetrics{
		Scanned: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_fga_backfill_scanned_total",
				Help: "Total resources scanned by the FGA resource-parent backfill, by kind",
			},
			[]string{"resource_kind"},
		),
		Written: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_fga_backfill_written_total",
				Help: "Total parent tuples written by the FGA resource-parent backfill, by kind",
			},
			[]string{"resource_kind"},
		),
		Errors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_fga_backfill_errors_total",
				Help: "Total per-kind failures in the FGA resource-parent backfill",
			},
			[]string{"resource_kind"},
		),
	}
}

// Collectors returns the prometheus.Collector slice so callers can
// register the metrics in bulk.
func (m *BackfillMetrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.Scanned, m.Written, m.Errors}
}

// BackfillKindReport is the per-resource-kind tally returned from one
// invocation of BackfillResourceParents.
type BackfillKindReport struct {
	Scanned     int    // items yielded by the iterator to the walker
	Written     int    // parent tuples successfully written to FGA
	Skipped     int    // items skipped (e.g. missing tenant_id — Phase 2)
	Errors      int    // per-item failures (write / validation / iterator)
	ResumeToken string // final cursor for this kind (empty if iteration completed)
}

// BackfillReport aggregates per-kind tallies across one run.
type BackfillReport struct {
	// ByKind is keyed on the ResourceKind strings from AllBackfillResourceKinds.
	// When BackfillResourceParents returns with the feature flag off, ByKind
	// is an empty map and Errors/Written/Scanned are all zero.
	ByKind map[ResourceKind]*BackfillKindReport

	// FlagDisabled is true when the function short-circuited because the
	// feature flag did not match BackfillFeatureFlag.
	FlagDisabled bool
}

// newEmptyReport constructs a zero-initialised report with per-kind entries
// for every known kind. Callers mutate it in place.
func newEmptyReport() *BackfillReport {
	r := &BackfillReport{
		ByKind: make(map[ResourceKind]*BackfillKindReport, len(AllBackfillResourceKinds)),
	}
	for _, k := range AllBackfillResourceKinds {
		r.ByKind[k] = &BackfillKindReport{}
	}
	return r
}

// BackfillResourceParents scans every resource in the daemon's stores and
// writes FGA `parent` tuples linking resource -> owning tenant. It is
// idempotent (FGA writes are no-op on duplicates) and resumable (per-kind
// cursor persisted in Redis every deps.CheckpointEvery items).
//
// Guarded by featureFlag: if featureFlag != BackfillFeatureFlag the function
// returns (report, nil) immediately with report.FlagDisabled=true and
// zero counters. Phase 1 ships with no caller passing the flag; Phase 2
// Task 18 enables it.
//
// Error semantics: transient per-item failures (writer error, iterator
// error on a single page) increment the kind's Errors counter but DO NOT
// abort the run — the backfill continues with the next kind. A nil
// deps.Writer or deps.Cursors returns a typed argument error without
// running any iteration.
func BackfillResourceParents(ctx context.Context, featureFlag string, deps BackfillDeps) (*BackfillReport, error) {
	// Flag guard — default path in Phase 1.
	if featureFlag != BackfillFeatureFlag {
		return &BackfillReport{
			ByKind:       map[ResourceKind]*BackfillKindReport{},
			FlagDisabled: true,
		}, nil
	}

	// Dependency validation runs only when the flag is set so the Phase 1
	// flag-off default cannot fail on unconfigured deps.
	if deps.Writer == nil {
		return nil, newInvalidArgumentError("BackfillResourceParents: deps.Writer must not be nil when feature flag is enabled")
	}
	if deps.Cursors == nil {
		return nil, newInvalidArgumentError("BackfillResourceParents: deps.Cursors must not be nil when feature flag is enabled")
	}
	if deps.Metrics == nil {
		return nil, newInvalidArgumentError("BackfillResourceParents: deps.Metrics must not be nil when feature flag is enabled")
	}

	checkpointEvery := deps.CheckpointEvery
	if checkpointEvery <= 0 {
		checkpointEvery = defaultCheckpointEvery
	}

	report := newEmptyReport()

	for _, kind := range AllBackfillResourceKinds {
		kindReport := report.ByKind[kind]
		cursorKey := cursorKeyPrefix + string(kind)

		iter, ok := deps.Iterators[kind]
		if !ok || iter == nil {
			// Phase 1: iterators unwired. Record as a non-fatal per-kind
			// error so observability surfaces the pending wiring; Phase 2
			// will populate deps.Iterators.
			kindReport.Errors++
			deps.Metrics.Errors.WithLabelValues(string(kind)).Inc()
			continue
		}

		// Load prior resume cursor for this kind, if any.
		cursor, err := deps.Cursors.Get(ctx, cursorKey)
		if err != nil {
			kindReport.Errors++
			deps.Metrics.Errors.WithLabelValues(string(kind)).Inc()
			continue
		}

		// The walker is the shared per-item callback. It writes the
		// parent tuple, increments counters, and checkpoints the cursor
		// every checkpointEvery successful writes.
		var walkerMu sync.Mutex // guards kindReport under concurrent iterators (Phase 2 safety)
		sinceCheckpoint := 0

		walker := func(tenantID, resourceID string) error {
			walkerMu.Lock()
			defer walkerMu.Unlock()

			kindReport.Scanned++
			deps.Metrics.Scanned.WithLabelValues(string(kind)).Inc()

			if tenantID == "" || resourceID == "" {
				// Fail-soft: log via counter and skip. Phase 2 may
				// choose to quarantine these — Phase 1 just counts.
				kindReport.Skipped++
				return nil
			}

			tuple := Tuple{
				User:     "tenant:" + tenantID,
				Relation: "parent",
				Object:   string(kind) + ":" + resourceID,
			}
			if werr := deps.Writer.Write(ctx, []Tuple{tuple}); werr != nil {
				kindReport.Errors++
				deps.Metrics.Errors.WithLabelValues(string(kind)).Inc()
				return werr
			}

			kindReport.Written++
			deps.Metrics.Written.WithLabelValues(string(kind)).Inc()

			sinceCheckpoint++
			if sinceCheckpoint >= checkpointEvery {
				sinceCheckpoint = 0
				// Persist the in-progress cursor. A persistence
				// failure counts as a soft error and does not abort
				// iteration; the next checkpoint will retry.
				if serr := deps.Cursors.Set(ctx, cursorKey, kindReport.ResumeToken); serr != nil {
					kindReport.Errors++
					deps.Metrics.Errors.WithLabelValues(string(kind)).Inc()
				}
			}
			return nil
		}

		nextCursor, done, iterErr := iter(ctx, cursor, walker)
		kindReport.ResumeToken = nextCursor

		if iterErr != nil {
			// Phase 1: Iterators for each kind return
			// ErrBackfillNotImplemented; recorded as a per-kind error.
			kindReport.Errors++
			deps.Metrics.Errors.WithLabelValues(string(kind)).Inc()
		}

		// Always persist the final cursor so a partial pass can resume.
		// On done=true with no iterator error, clear the cursor so the
		// next run starts from the beginning rather than at EOF.
		finalCursor := nextCursor
		if done && iterErr == nil {
			finalCursor = ""
			kindReport.ResumeToken = ""
		}
		if serr := deps.Cursors.Set(ctx, cursorKey, finalCursor); serr != nil {
			kindReport.Errors++
			deps.Metrics.Errors.WithLabelValues(string(kind)).Inc()
		}
	}

	return report, nil
}

// RedisCursorStore adapts a redis.UniversalClient to the CursorStore
// interface. The daemon wires this; tests use an in-memory stub.
type RedisCursorStore struct {
	Client redis.UniversalClient
}

// Get implements CursorStore.
func (r *RedisCursorStore) Get(ctx context.Context, key string) (string, error) {
	if r == nil || r.Client == nil {
		return "", fmt.Errorf("RedisCursorStore: client not configured")
	}
	val, err := r.Client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return val, nil
}

// Set implements CursorStore. The cursor has no TTL — it persists across
// daemon restarts so a half-completed backfill resumes at the last
// checkpoint.
func (r *RedisCursorStore) Set(ctx context.Context, key, value string) error {
	if r == nil || r.Client == nil {
		return fmt.Errorf("RedisCursorStore: client not configured")
	}
	return r.Client.Set(ctx, key, value, 0).Err()
}
