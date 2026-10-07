// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audittest

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
)

// The sink keeps each record in order, runs OnEmit for each one, and keeps
// none when Err is set.
func TestSink_KeepsRecordsInOrder(t *testing.T) {
	ctx := context.Background()
	s := &Sink{}
	var seen []string
	s.OnEmit = func(ev audit.Event) { seen = append(seen, ev.Action) }
	for _, a := range []string{"a", "b"} {
		if err := s.EmitAuditEvent(ctx, audit.Event{Action: a}); err != nil {
			t.Fatalf("emit %s: %v", a, err)
		}
	}
	got := s.Events()
	if len(got) != 2 || got[0].Action != "a" || got[1].Action != "b" {
		t.Fatalf("events = %+v", got)
	}
	if len(seen) != 2 {
		t.Fatalf("OnEmit ran %d times, want 2", len(seen))
	}
	got[0].Action = "changed"
	if s.Events()[0].Action != "a" {
		t.Fatal("Events must return a copy")
	}

	down := errors.New("down")
	refusing := &Sink{Err: down}
	if err := refusing.EmitAuditEvent(ctx, audit.Event{Action: "c"}); !errors.Is(err, down) {
		t.Fatalf("a refusing sink: err = %v", err)
	}
	if len(refusing.Events()) != 0 {
		t.Fatal("a refusing sink must keep no record")
	}
	if e := refusing.Emitter(t); e == nil {
		t.Fatal("Emitter must return an emitter over the sink")
	}
}
