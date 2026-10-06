// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
)

// The emitter has no default sink: with no sink there is no emitter.
func TestNewSagaEmitter_RequiresASink(t *testing.T) {
	e, err := audit.NewSagaEmitter(nil)
	if !errors.Is(err, audit.ErrNoSink) || e != nil {
		t.Fatalf("NewSagaEmitter(nil) = %v, %v; want nil, ErrNoSink", e, err)
	}
	var nilEmitter *audit.SagaEmitter
	if err := nilEmitter.Record(context.Background(), audit.Event{}); !errors.Is(err, audit.ErrNoSink) {
		t.Fatalf("Record on a nil emitter = %v, want ErrNoSink", err)
	}
}

// Record sends the record with no result. RecordFailure sends the second
// record with the result "failure" and the reason, bounded in length.
func TestSagaEmitter_RecordAndFailure(t *testing.T) {
	sink := &audittest.Sink{}
	e := sink.Emitter(t)
	ev := audit.Event{Action: audit.ActionSagaStep, TenantID: "acme", TargetType: "tenant", TargetID: "acme", Result: "stale", Reason: "stale"}
	if err := e.Record(context.Background(), ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := e.RecordFailure(context.Background(), ev, errors.New(strings.Repeat("x", 600))); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	got := sink.Events()
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2", len(got))
	}
	if got[0].Result != "" || got[0].Reason != "" {
		t.Errorf("first record = %+v, want no result and no reason", got[0])
	}
	if got[1].Result != audit.ResultFailure || !strings.HasSuffix(got[1].Reason, "...[truncated]") || len(got[1].Reason) > 600 {
		t.Errorf("failure record = result %q, reason length %d", got[1].Result, len(got[1].Reason))
	}
}

// A refused record is an error that names the target.
func TestSagaEmitter_RefusedRecordIsAnError(t *testing.T) {
	down := errors.New("daemon down")
	e := (&audittest.Sink{Err: down}).Emitter(t)
	err := e.Record(context.Background(), audit.Event{Action: audit.ActionSagaStep, TargetType: "tenant", TargetID: "acme"})
	if !errors.Is(err, down) || !strings.Contains(err.Error(), `"acme"`) {
		t.Fatalf("Record = %v, want the sink error with the target", err)
	}
}
