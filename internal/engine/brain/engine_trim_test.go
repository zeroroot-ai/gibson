// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// The in-memory Timeline of a long-lived engine stays below the snapshot
// cadence across many snapshots, and the full history stays in the store
// (gibson#730).
func TestEngine_InMemoryTimelineStaysBounded(t *testing.T) {
	const cadence = 10
	store := &memTimelineStore{}
	e := NewEngine("t").WithStore(store).WithSnapshotCadence(cadence)

	const events = 1000
	for i := range events {
		e.Submit(HostObserved{ScopeID: "s", Address: fmt.Sprintf("10.0.%d.%d", i/250, i%250)})
		e.Tick()
		require.Less(t, e.Timeline.Len(), cadence, "after event %d", i)
		require.Less(t, store.remaining(), cadence+1, "after event %d", i)
	}

	history, err := e.History(context.Background())
	require.NoError(t, err)
	require.Len(t, history, events, "the store keeps the full history")
	require.Len(t, e.Hosts(), events, "the World holds each event")
}

// trimFailStore fails each trim, so the stream and its history stay as they are.
type trimFailStore struct{ memTimelineStore }

func (*trimFailStore) TrimTo(context.Context, string, string) error {
	return errors.New("the history write failed")
}

// When the store trim fails, the in-memory Timeline keeps its events.
func TestEngine_FailedTrimKeepsTheInMemoryTimeline(t *testing.T) {
	store := &trimFailStore{}
	e := NewEngine("t").WithStore(store).WithSnapshotCadence(2)
	for i := range 5 {
		e.Submit(HostObserved{ScopeID: "s", Address: fmt.Sprintf("10.0.0.%d", i)})
	}
	require.Equal(t, 5, e.Tick())
	require.Equal(t, 5, e.Timeline.Len())
	require.Equal(t, 5, store.remaining())
}

// An engine with no store never trims: its Timeline is its full history.
func TestEngine_WithNoStoreKeepsEachEvent(t *testing.T) {
	e := NewEngine("t").WithSnapshotCadence(2)
	for i := range 7 {
		e.Submit(HostObserved{ScopeID: "s", Address: fmt.Sprintf("10.0.0.%d", i)})
	}
	e.Tick()
	require.Equal(t, 7, e.Timeline.Len())
}
