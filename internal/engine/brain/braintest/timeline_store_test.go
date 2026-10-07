// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintest

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

type memEvent struct{ N int }

func (memEvent) Kind() string { return "mem.event" }

// The store keeps the stream in order, repeats the seq of the most recent
// key, and refuses an append with no key.
func TestMemTimelineStore_AppendAndReplay(t *testing.T) {
	ctx := context.Background()
	s := NewMemTimelineStore()
	if _, err := s.Append(ctx, "t", "", memEvent{N: 0}); !errors.Is(err, errEmptyKey) {
		t.Fatalf("an append with no key: err = %v, want errEmptyKey", err)
	}
	seq1, err := s.Append(ctx, "t", "k1", memEvent{N: 1})
	if err != nil || seq1 != "1" {
		t.Fatalf("first append = %q, %v", seq1, err)
	}
	again, err := s.Append(ctx, "t", "k1", memEvent{N: 1})
	if err != nil || again != seq1 {
		t.Fatalf("a repeat of the most recent key = %q, %v; want %q", again, err, seq1)
	}
	seq2, err := s.Append(ctx, "t", "k2", memEvent{N: 2})
	if err != nil || seq2 != "2" {
		t.Fatalf("second append = %q, %v", seq2, err)
	}

	all, err := s.LoadForReplay(ctx, "t", "")
	if err != nil || len(all) != 2 {
		t.Fatalf("replay from the start = %v, %v; want 2 events", all, err)
	}
	after, err := s.LoadForReplay(ctx, "t", seq1)
	if err != nil || len(after) != 1 || after[0].(memEvent).N != 2 {
		t.Fatalf("replay after %q = %v, %v; want the second event", seq1, after, err)
	}
	if _, err := s.LoadForReplay(ctx, "t", "x"); err == nil {
		t.Fatal("a seq that is not a number must be refused")
	}
}

// A trim moves the events up to the handle into the history, and the
// history read returns the trimmed events before the stream.
func TestMemTimelineStore_TrimAndHistory(t *testing.T) {
	ctx := context.Background()
	s := NewMemTimelineStore()
	for i := 1; i <= 3; i++ {
		if _, err := s.Append(ctx, "t", "k"+string(rune('0'+i)), memEvent{N: i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := s.TrimTo(ctx, "t", "bad"); err == nil {
		t.Fatal("a handle that is not a number must be refused")
	}
	if err := s.TrimTo(ctx, "t", "2"); err != nil {
		t.Fatalf("TrimTo: %v", err)
	}
	stream, err := s.LoadForReplay(ctx, "t", "")
	if err != nil || len(stream) != 1 || stream[0].(memEvent).N != 3 {
		t.Fatalf("stream after the trim = %v, %v; want the third event only", stream, err)
	}
	history, err := s.LoadHistory(ctx, "t")
	if err != nil || len(history) != 3 {
		t.Fatalf("history = %v, %v; want all three events", history, err)
	}
	for i, ev := range history {
		if ev.(memEvent).N != i+1 {
			t.Fatalf("history[%d] = %v; want event %d", i, ev, i+1)
		}
	}
}

// The store keeps one snapshot, and reports none before the first write.
func TestMemTimelineStore_Snapshot(t *testing.T) {
	ctx := context.Background()
	s := NewMemTimelineStore()
	if snap, err := s.LoadSnapshot(ctx, "t"); err != nil || snap != nil {
		t.Fatalf("snapshot before a write = %v, %v; want none", snap, err)
	}
	handle, err := s.WriteSnapshot(ctx, "t", brain.WorldSnapshot{AtSeq: "7"})
	if err != nil || handle != "7" {
		t.Fatalf("WriteSnapshot = %q, %v; want the seq as the handle", handle, err)
	}
	snap, err := s.LoadSnapshot(ctx, "t")
	if err != nil || snap == nil || snap.AtSeq != "7" {
		t.Fatalf("LoadSnapshot = %+v, %v; want the written snapshot", snap, err)
	}
}

// The factory gives each tenant one store, and the same store on a second
// call.
func TestStoreFactory_OneStorePerTenant(t *testing.T) {
	ctx := context.Background()
	factory := StoreFactory()
	a1, err := factory(ctx, "a")
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	a2, _ := factory(ctx, "a")
	b, _ := factory(ctx, "b")
	if a1 != a2 {
		t.Fatal("a second call for one tenant must return the same store")
	}
	if a1 == b {
		t.Fatal("two tenants must not share a store")
	}
}
