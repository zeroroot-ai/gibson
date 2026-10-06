// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package braintest holds test doubles for the brain package. A brain engine
// requires a durable TimelineStore (ADR-0163), so a test outside the brain
// package gives it the in-memory store of this package.
package braintest

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// errEmptyKey is the error of an Append with no idempotency key.
var errEmptyKey = errors.New("braintest: an append needs an idempotency key")

type entry struct {
	seq int
	ev  brain.Event
}

// MemTimelineStore is an in-memory brain.TimelineStore. It keeps an ordered
// stream, one snapshot and the history that a trim removes, so it obeys the
// same contract as the Redis store. It ignores the tenant argument: use one
// store for each tenant.
type MemTimelineStore struct {
	mu      sync.Mutex
	events  []entry
	history []brain.Event
	next    int
	lastKey string
	snap    brain.WorldSnapshot
	hasSnap bool
}

var _ brain.TimelineStore = (*MemTimelineStore)(nil)

// NewMemTimelineStore returns an empty in-memory store.
func NewMemTimelineStore() *MemTimelineStore { return &MemTimelineStore{} }

// Append adds ev at the end of the stream. A repeat of the most recent key
// writes nothing and returns the seq of that append.
func (s *MemTimelineStore) Append(_ context.Context, _, key string, ev brain.Event) (string, error) {
	if key == "" {
		return "", errEmptyKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == s.lastKey {
		return strconv.Itoa(s.next), nil
	}
	s.next++
	s.lastKey = key
	s.events = append(s.events, entry{seq: s.next, ev: ev})
	return strconv.Itoa(s.next), nil
}

// LoadForReplay returns the events of the stream after afterSeq.
func (s *MemTimelineStore) LoadForReplay(_ context.Context, _, afterSeq string) ([]brain.Event, error) {
	after, err := parseSeq(afterSeq)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []brain.Event
	for _, e := range s.events {
		if e.seq > after {
			out = append(out, e.ev)
		}
	}
	return out, nil
}

// LoadHistory returns the trimmed events, then the stream.
func (s *MemTimelineStore) LoadHistory(_ context.Context, _ string) ([]brain.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]brain.Event(nil), s.history...)
	for _, e := range s.events {
		out = append(out, e.ev)
	}
	return out, nil
}

// WriteSnapshot keeps snap as the one snapshot. The handle is snap.AtSeq.
func (s *MemTimelineStore) WriteSnapshot(_ context.Context, _ string, snap brain.WorldSnapshot) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap = snap
	s.hasSnap = true
	return snap.AtSeq, nil
}

// LoadSnapshot returns the snapshot, or nil when there is none.
func (s *MemTimelineStore) LoadSnapshot(_ context.Context, _ string) (*brain.WorldSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasSnap {
		return nil, nil
	}
	cp := s.snap
	return &cp, nil
}

// TrimTo moves each event up to the handle from the stream to the history.
func (s *MemTimelineStore) TrimTo(_ context.Context, _, handle string) error {
	upTo, err := parseSeq(handle)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	for _, e := range s.events {
		if e.seq > upTo {
			kept = append(kept, e)
		} else {
			s.history = append(s.history, e.ev)
		}
	}
	s.events = kept
	return nil
}

// StoreFactory returns a brain.StoreFactory that gives each tenant its own
// in-memory store. A second call for one tenant returns the same store, so an
// engine that the registry builds again hydrates from the history of the first.
func StoreFactory() brain.StoreFactory {
	var mu sync.Mutex
	stores := map[string]*MemTimelineStore{}
	return func(_ context.Context, tenant string) (brain.TimelineStore, error) {
		mu.Lock()
		defer mu.Unlock()
		s, ok := stores[tenant]
		if !ok {
			s = NewMemTimelineStore()
			stores[tenant] = s
		}
		return s, nil
	}
}

func parseSeq(seq string) (int, error) {
	if seq == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(seq)
	if err != nil {
		return 0, fmt.Errorf("braintest: the seq %q is not a number: %w", seq, err)
	}
	return n, nil
}
