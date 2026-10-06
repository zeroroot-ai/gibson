// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audittest holds test doubles for the audit package. Only tests
// import it.
package audittest

import (
	"context"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
)

// Recorder stands in for the durable Postgres writer in a test. It keeps
// each event that an AuditLogger hands to it.
type Recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

var _ audit.DurableWriter = (*Recorder)(nil)

// WriteSync keeps the event, as Log does.
func (r *Recorder) WriteSync(_ context.Context, event audit.Event) error {
	r.Log(event)
	return nil
}

// Log keeps the event.
func (r *Recorder) Log(event audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

// Events returns a copy of the events that the Recorder holds.
func (r *Recorder) Events() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}
