// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audittest holds test doubles for the operator audit package. Only
// tests import it.
package audittest

import (
	"context"
	"sync"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
)

// Sink stands in for the daemon in a test. It keeps each record in order.
// When Err is set, it refuses each record and keeps none.
type Sink struct {
	mu     sync.Mutex
	events []audit.Event
	// Err is the error that EmitAuditEvent returns. Nil accepts each record.
	Err error
	// OnEmit, when set, runs for each accepted record. A test uses it to
	// see the order of a record and of the change that follows it.
	OnEmit func(audit.Event)
}

var _ audit.Sink = (*Sink)(nil)

// EmitAuditEvent keeps ev, or returns Err.
func (s *Sink) EmitAuditEvent(_ context.Context, ev audit.Event) error {
	s.mu.Lock()
	if s.Err != nil {
		err := s.Err
		s.mu.Unlock()
		return err
	}
	s.events = append(s.events, ev)
	onEmit := s.OnEmit
	s.mu.Unlock()
	if onEmit != nil {
		onEmit(ev)
	}
	return nil
}

// Events returns a copy of the records that the Sink holds.
func (s *Sink) Events() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

// Emitter returns a SagaEmitter over s.
func (s *Sink) Emitter(t testing.TB) *audit.SagaEmitter {
	t.Helper()
	e, err := audit.NewSagaEmitter(s)
	if err != nil {
		t.Fatalf("NewSagaEmitter: %v", err)
	}
	return e
}
