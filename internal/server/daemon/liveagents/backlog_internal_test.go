// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package liveagents

import (
	"testing"
	"time"
)

// newBoundedState builds an instance with small backlog bounds, so the ring
// logic is tested without a public knob (the bounds are fixed constants).
func newBoundedState(chunks, bytes int) *instanceState {
	return &instanceState{
		subs:          make(map[int]chan Event),
		subBuf:        1,
		backlogChunks: chunks,
		backlogBytes:  bytes,
	}
}

func seqsOf(evs []Event) []uint64 {
	out := make([]uint64, 0, len(evs))
	for _, ev := range evs {
		out = append(out, ev.Seq)
	}
	return out
}

func TestBacklog_DropsOldestByChunkCount(t *testing.T) {
	st := newBoundedState(2, 1<<20)
	for i := range 5 {
		st.publish([]byte{byte('a' + i)})
	}
	backlog, _, cancel := st.addSubscriber(0)
	cancel()
	if got := seqsOf(backlog); len(got) != 2 || got[0] != 4 || got[1] != 5 {
		t.Fatalf("backlog seqs = %v; want [4 5]", got)
	}
	if string(backlog[0].Data) != "d" || string(backlog[1].Data) != "e" {
		t.Fatalf("backlog data = %q %q; want d e", backlog[0].Data, backlog[1].Data)
	}
}

func TestBacklog_DropsOldestByBytes(t *testing.T) {
	st := newBoundedState(1024, 10)
	st.publish([]byte("aaaa"))    // 4
	st.publish([]byte("bbbb"))    // 8
	st.publish([]byte("cccc"))    // 12 > 10: drops aaaa
	st.publish([]byte("ddddddd")) // 15 > 10: drops bbbb, then cccc -> 7
	backlog, _, cancel := st.addSubscriber(0)
	cancel()
	if got := seqsOf(backlog); len(got) != 1 || got[0] != 4 {
		t.Fatalf("backlog seqs = %v; want [4]", got)
	}
	// One oversized chunk always stays: the newest event is never dropped.
	st.publish([]byte("0123456789ABCDEF"))
	backlog, _, cancel = st.addSubscriber(0)
	cancel()
	if got := seqsOf(backlog); len(got) != 1 || got[0] != 5 {
		t.Fatalf("backlog seqs after oversized = %v; want [5]", got)
	}
}

func TestBacklog_DefaultBoundsAreSane(t *testing.T) {
	if defaultBacklogChunks < 256 || defaultBacklogBytes < 64<<10 {
		t.Fatalf("defaults chunks=%d bytes=%d; want a useful tail", defaultBacklogChunks, defaultBacklogBytes)
	}
	st := newBoundedState(defaultBacklogChunks, defaultBacklogBytes)
	st.publish([]byte("x"))
	if st.backlog[0].At.IsZero() || st.backlog[0].At.After(time.Now()) {
		t.Fatalf("At = %v; want a receipt time", st.backlog[0].At)
	}
}
