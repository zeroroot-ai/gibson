package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubTupleWriter records every Write call for assertion. Thread-safe so the
// tests can safely run under `go test -race`.
type stubTupleWriter struct {
	mu      sync.Mutex
	written []Tuple
	failOn  map[string]bool // Object -> force error
}

func (s *stubTupleWriter) Write(_ context.Context, tuples []Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tuples {
		if s.failOn != nil && s.failOn[t.Object] {
			return fmt.Errorf("stub: forced write failure for %s", t.Object)
		}
		s.written = append(s.written, t)
	}
	return nil
}

func (s *stubTupleWriter) snapshot() []Tuple {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Tuple, len(s.written))
	copy(out, s.written)
	return out
}

// memCursorStore is an in-memory CursorStore double.
type memCursorStore struct {
	mu    sync.Mutex
	data  map[string]string
	getCt int
	setCt int
}

func newMemCursorStore() *memCursorStore {
	return &memCursorStore{data: map[string]string{}}
}

func (m *memCursorStore) Get(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCt++
	return m.data[key], nil
}

func (m *memCursorStore) Set(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setCt++
	m.data[key] = value
	return nil
}

// TestBackfillResourceParents_FlagDisabled asserts that the Phase 1 default
// path — feature flag off — returns an empty report without invoking the
// writer, cursor store, or any iterator.
func TestBackfillResourceParents_FlagDisabled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		flag string
	}{
		{"empty flag", ""},
		{"wrong flag", "some_other_flag"},
		{"close-but-not-exact", "fga_resource_objects_v1"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := &stubTupleWriter{}
			cursors := newMemCursorStore()
			metrics := NewBackfillMetrics()

			// Iterator would panic if called — prove it is NOT called.
			iter := func(_ context.Context, _ string, _ func(string, string) error) (string, bool, error) {
				t.Fatal("iterator invoked while flag is disabled")
				return "", false, nil
			}

			deps := BackfillDeps{
				Writer:  writer,
				Cursors: cursors,
				Metrics: metrics,
				Iterators: map[ResourceKind]ResourceIterator{
					ResourceKindMission: iter,
					ResourceKindRun:     iter,
				},
			}

			report, err := BackfillResourceParents(context.Background(), tc.flag, deps)
			require.NoError(t, err)
			require.NotNil(t, report)
			assert.True(t, report.FlagDisabled)
			assert.Empty(t, report.ByKind, "report.ByKind must be empty when flag is off")
			assert.Empty(t, writer.snapshot(), "no tuples may be written when flag is off")
			assert.Zero(t, cursors.getCt, "cursor.Get must not be called when flag is off")
			assert.Zero(t, cursors.setCt, "cursor.Set must not be called when flag is off")
		})
	}
}

// TestBackfillResourceParents_FlagOnSingleResourcePerKind verifies that with
// the feature flag enabled and a working iterator for each kind, the
// backfill writes exactly the expected tuples and increments metrics.
func TestBackfillResourceParents_FlagOnSingleResourcePerKind(t *testing.T) {
	t.Parallel()

	writer := &stubTupleWriter{}
	cursors := newMemCursorStore()
	metrics := NewBackfillMetrics()

	// Per-kind iterator that yields exactly one synthetic resource and
	// signals done. Resource ID embeds the kind so assertions are easy.
	makeIter := func(kind ResourceKind) ResourceIterator {
		return func(_ context.Context, cursor string, walker func(string, string) error) (string, bool, error) {
			// Assert initial cursor is the empty string (no prior run).
			if cursor != "" {
				return "", false, fmt.Errorf("unexpected cursor %q for kind %s", cursor, kind)
			}
			if err := walker("tenant-a", string(kind)+"-1"); err != nil {
				return "", false, err
			}
			return "", true, nil
		}
	}

	iters := map[ResourceKind]ResourceIterator{}
	for _, k := range AllBackfillResourceKinds {
		iters[k] = makeIter(k)
	}

	deps := BackfillDeps{
		Writer:          writer,
		Cursors:         cursors,
		Metrics:         metrics,
		Iterators:       iters,
		CheckpointEvery: 100, // not exercised in this test; one item per kind
	}

	report, err := BackfillResourceParents(context.Background(), BackfillFeatureFlag, deps)
	require.NoError(t, err)
	require.NotNil(t, report)
	require.False(t, report.FlagDisabled)
	require.Len(t, report.ByKind, len(AllBackfillResourceKinds))

	for _, k := range AllBackfillResourceKinds {
		r := report.ByKind[k]
		require.NotNil(t, r, "kind %s missing from report", k)
		assert.Equal(t, 1, r.Scanned, "kind %s scanned", k)
		assert.Equal(t, 1, r.Written, "kind %s written", k)
		assert.Equal(t, 0, r.Errors, "kind %s errors", k)
		assert.Equal(t, 0, r.Skipped, "kind %s skipped", k)
		assert.Equal(t, "", r.ResumeToken, "kind %s cursor cleared on done", k)
	}

	// Tuple assertions: one parent tuple per kind, shape
	// (user=tenant:tenant-a, relation=parent, object=<kind>:<kind>-1).
	got := writer.snapshot()
	require.Len(t, got, len(AllBackfillResourceKinds))
	seen := map[string]bool{}
	for _, tp := range got {
		seen[tp.Object] = true
		assert.Equal(t, "tenant:tenant-a", tp.User)
		assert.Equal(t, "parent", tp.Relation)
	}
	for _, k := range AllBackfillResourceKinds {
		key := string(k) + ":" + string(k) + "-1"
		assert.True(t, seen[key], "missing tuple for %s", key)
	}

	// Cursor store must have been touched once per kind on Get (initial
	// load) and once per kind on Set (final persist).
	assert.Equal(t, len(AllBackfillResourceKinds), cursors.getCt)
	assert.Equal(t, len(AllBackfillResourceKinds), cursors.setCt)
	// Final cursor for every kind should be empty (done=true clears).
	for _, k := range AllBackfillResourceKinds {
		assert.Equal(t, "", cursors.data[cursorKeyPrefix+string(k)], "kind %s cursor", k)
	}
}

// TestBackfillResourceParents_ResumeToken exercises the cursor path: the
// first invocation of the iterator returns a cursor + done=false; the
// backfill persists the cursor, and the second invocation starts from that
// cursor and then signals done.
func TestBackfillResourceParents_ResumeToken(t *testing.T) {
	t.Parallel()

	writer := &stubTupleWriter{}
	cursors := newMemCursorStore()
	metrics := NewBackfillMetrics()

	// Iterator that yields different behaviour depending on the cursor.
	// Only wired for kind=mission so the other kinds short-circuit via
	// missing-iterator error; we're only asserting on mission here.
	type callLog struct {
		cursorIn string
	}
	var (
		logMu sync.Mutex
		calls []callLog
	)

	missionIter := func(_ context.Context, cursor string, walker func(string, string) error) (string, bool, error) {
		logMu.Lock()
		calls = append(calls, callLog{cursorIn: cursor})
		logMu.Unlock()

		switch cursor {
		case "":
			// First call: yield one item, return a resume cursor, not done.
			if err := walker("tenant-a", "m1"); err != nil {
				return "", false, err
			}
			return "page-2", false, nil
		case "page-2":
			// Resume call: yield one more item, then done.
			if err := walker("tenant-a", "m2"); err != nil {
				return "", false, err
			}
			return "", true, nil
		default:
			return "", false, fmt.Errorf("unexpected cursor %q", cursor)
		}
	}

	deps := BackfillDeps{
		Writer:  writer,
		Cursors: cursors,
		Metrics: metrics,
		Iterators: map[ResourceKind]ResourceIterator{
			ResourceKindMission: missionIter,
		},
	}

	// First run — should persist the "page-2" resume token.
	report1, err := BackfillResourceParents(context.Background(), BackfillFeatureFlag, deps)
	require.NoError(t, err)
	require.False(t, report1.FlagDisabled)
	missionReport1 := report1.ByKind[ResourceKindMission]
	require.NotNil(t, missionReport1)
	assert.Equal(t, 1, missionReport1.Scanned)
	assert.Equal(t, 1, missionReport1.Written)
	assert.Equal(t, "page-2", missionReport1.ResumeToken, "ResumeToken must carry the in-progress cursor back to caller")

	// Cursor store must hold the in-progress cursor under the canonical key.
	assert.Equal(t, "page-2", cursors.data[cursorKeyPrefix+string(ResourceKindMission)])

	// Second run — iterator is called with cursor="page-2" and completes.
	report2, err := BackfillResourceParents(context.Background(), BackfillFeatureFlag, deps)
	require.NoError(t, err)
	missionReport2 := report2.ByKind[ResourceKindMission]
	require.NotNil(t, missionReport2)
	assert.Equal(t, 1, missionReport2.Scanned)
	assert.Equal(t, 1, missionReport2.Written)
	assert.Equal(t, "", missionReport2.ResumeToken, "cursor cleared on done=true")

	// Final cursor in the store is cleared after a complete pass.
	assert.Equal(t, "", cursors.data[cursorKeyPrefix+string(ResourceKindMission)])

	// Verify the iterator was called twice: first with "" and then with
	// "page-2". Any additional calls would indicate a control-flow bug.
	logMu.Lock()
	defer logMu.Unlock()
	require.Len(t, calls, 2)
	assert.Equal(t, "", calls[0].cursorIn)
	assert.Equal(t, "page-2", calls[1].cursorIn)

	// Tuples written across both runs.
	got := writer.snapshot()
	require.Len(t, got, 2)
	for _, tp := range got {
		assert.Equal(t, "tenant:tenant-a", tp.User)
		assert.Equal(t, "parent", tp.Relation)
	}
}

// TestBackfillResourceParents_NotImplementedIteratorIsSoftFailure verifies
// that a Phase-1-style iterator that returns ErrBackfillNotImplemented
// produces a per-kind error tally without aborting the other kinds.
func TestBackfillResourceParents_NotImplementedIteratorIsSoftFailure(t *testing.T) {
	t.Parallel()

	writer := &stubTupleWriter{}
	cursors := newMemCursorStore()
	metrics := NewBackfillMetrics()

	notImpl := func(_ context.Context, _ string, _ func(string, string) error) (string, bool, error) {
		return "", false, ErrBackfillNotImplemented
	}

	ok := func(_ context.Context, _ string, walker func(string, string) error) (string, bool, error) {
		return "", true, walker("tenant-x", "f1")
	}

	iters := map[ResourceKind]ResourceIterator{}
	for _, k := range AllBackfillResourceKinds {
		if k == ResourceKindFinding {
			iters[k] = ok
		} else {
			iters[k] = notImpl
		}
	}

	deps := BackfillDeps{
		Writer:    writer,
		Cursors:   cursors,
		Metrics:   metrics,
		Iterators: iters,
	}

	report, err := BackfillResourceParents(context.Background(), BackfillFeatureFlag, deps)
	require.NoError(t, err)
	require.NotNil(t, report)

	// Every not-impl kind counts one error; finding succeeds.
	for _, k := range AllBackfillResourceKinds {
		r := report.ByKind[k]
		require.NotNil(t, r)
		if k == ResourceKindFinding {
			assert.Equal(t, 1, r.Scanned, "finding scanned")
			assert.Equal(t, 1, r.Written, "finding written")
			assert.Equal(t, 0, r.Errors, "finding errors")
		} else {
			assert.Equal(t, 1, r.Errors, "kind %s: not-impl => 1 error", k)
			assert.Equal(t, 0, r.Written, "kind %s: no writes on not-impl", k)
		}
	}

	// Exactly one tuple written: the successful finding one.
	got := writer.snapshot()
	require.Len(t, got, 1)
	assert.Equal(t, "tenant:tenant-x", got[0].User)
	assert.Equal(t, "parent", got[0].Relation)
	assert.Equal(t, "finding:f1", got[0].Object)
}

// TestBackfillResourceParents_MissingIteratorIsSoftFailure verifies that a
// kind with no registered iterator is counted as an error (Phase 1 default).
func TestBackfillResourceParents_MissingIteratorIsSoftFailure(t *testing.T) {
	t.Parallel()

	writer := &stubTupleWriter{}
	cursors := newMemCursorStore()
	metrics := NewBackfillMetrics()

	deps := BackfillDeps{
		Writer:    writer,
		Cursors:   cursors,
		Metrics:   metrics,
		Iterators: map[ResourceKind]ResourceIterator{}, // empty
	}

	report, err := BackfillResourceParents(context.Background(), BackfillFeatureFlag, deps)
	require.NoError(t, err)
	require.NotNil(t, report)

	for _, k := range AllBackfillResourceKinds {
		r := report.ByKind[k]
		require.NotNil(t, r)
		assert.Equal(t, 1, r.Errors, "kind %s should have 1 error for missing iterator", k)
	}
	assert.Empty(t, writer.snapshot())
}

// TestBackfillResourceParents_NilDepsAreRejected verifies that feeding the
// function nil Writer / Cursors / Metrics with the flag ON produces a typed
// argument error rather than nil-deref.
func TestBackfillResourceParents_NilDepsAreRejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		deps BackfillDeps
	}{
		{"nil writer", BackfillDeps{Writer: nil, Cursors: newMemCursorStore(), Metrics: NewBackfillMetrics()}},
		{"nil cursors", BackfillDeps{Writer: &stubTupleWriter{}, Cursors: nil, Metrics: NewBackfillMetrics()}},
		{"nil metrics", BackfillDeps{Writer: &stubTupleWriter{}, Cursors: newMemCursorStore(), Metrics: nil}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			report, err := BackfillResourceParents(context.Background(), BackfillFeatureFlag, tc.deps)
			require.Error(t, err)
			assert.Nil(t, report)
			assert.True(t, errors.Is(err, ErrInvalidArgument), "expected ErrInvalidArgument sentinel; got %v", err)
		})
	}
}

// TestBackfillResourceParents_CheckpointPersistsCursor verifies that the
// checkpointEvery knob causes a cursor persistence write mid-iteration.
func TestBackfillResourceParents_CheckpointPersistsCursor(t *testing.T) {
	t.Parallel()

	writer := &stubTupleWriter{}
	cursors := newMemCursorStore()
	metrics := NewBackfillMetrics()

	// The iterator yields five items under a single call, then done.
	fiveItemIter := func(_ context.Context, _ string, walker func(string, string) error) (string, bool, error) {
		for i := 0; i < 5; i++ {
			if err := walker("tenant-q", fmt.Sprintf("m%d", i)); err != nil {
				return "", false, err
			}
		}
		return "", true, nil
	}

	iters := map[ResourceKind]ResourceIterator{
		ResourceKindMission: fiveItemIter,
	}

	deps := BackfillDeps{
		Writer:          writer,
		Cursors:         cursors,
		Metrics:         metrics,
		Iterators:       iters,
		CheckpointEvery: 2, // triggers a checkpoint Set at items 2 and 4
	}

	report, err := BackfillResourceParents(context.Background(), BackfillFeatureFlag, deps)
	require.NoError(t, err)
	require.NotNil(t, report)

	missionReport := report.ByKind[ResourceKindMission]
	require.NotNil(t, missionReport)
	assert.Equal(t, 5, missionReport.Scanned)
	assert.Equal(t, 5, missionReport.Written)

	// Set should have been called exactly 3 times for kind=mission:
	// two mid-iteration checkpoints (items 2, 4) plus the final Set to
	// clear the cursor on done. Other kinds have no iterator registered,
	// so the missing-iterator continue path skips their cursor Get/Set
	// entirely.
	assert.Equal(t, 3, cursors.setCt)
	assert.Equal(t, "", cursors.data[cursorKeyPrefix+string(ResourceKindMission)])
}

// TestNewBackfillMetrics_Collectors spot-checks the metrics constructor so
// callers can rely on Collectors() returning all three vectors in a stable
// order.
func TestNewBackfillMetrics_Collectors(t *testing.T) {
	t.Parallel()
	m := NewBackfillMetrics()
	require.NotNil(t, m)
	require.NotNil(t, m.Scanned)
	require.NotNil(t, m.Written)
	require.NotNil(t, m.Errors)
	require.Len(t, m.Collectors(), 3)
}
