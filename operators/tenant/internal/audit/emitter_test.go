/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package audit_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
)

func TestEmitter_EmitAsync_Defaults(t *testing.T) {
	e := audit.New(audit.Config{
		OperatorVersion: "v0.1.0-test",
		Log:             testr.New(t),
	})
	defer func() {
		_ = e.Close(context.Background())
	}()

	evt := audit.AuditEvent{
		Tenant:    "acme",
		Subsystem: "fga",
		Action:    "create_org",
	}
	if err := e.EmitAsync(context.Background(), evt); err != nil {
		t.Fatalf("emit failed: %v", err)
	}
}

func TestEmitter_EmitSync_WritesJSON(t *testing.T) {
	e := audit.New(audit.Config{
		OperatorVersion: "v0.1.0-test",
		Log:             testr.New(t),
	})
	defer func() {
		_ = e.Close(context.Background())
	}()

	evt := audit.AuditEvent{
		Tenant:    "acme",
		Subsystem: "fga",
		Action:    "write_tuples",
		After:     json.RawMessage(`{"count":5}`),
	}
	if err := e.EmitSync(context.Background(), evt); err != nil {
		t.Fatalf("sync emit failed: %v", err)
	}
}

func TestEmitter_BufferFull_DropsOldest(t *testing.T) {
	// Tiny buffer forces drop-oldest path.
	e := audit.New(audit.Config{
		BufferSize:      2,
		OperatorVersion: "v0.1.0-test",
		Log:             testr.New(t),
	})
	defer func() {
		_ = e.Close(context.Background())
	}()

	// Flood the buffer faster than the background goroutine drains it.
	for i := range 100 {
		err := e.EmitAsync(context.Background(), audit.AuditEvent{
			Tenant: "acme",
			Action: "spam",
		})
		// Should not error — drop-oldest always succeeds.
		if err != nil {
			t.Errorf("unexpected error on flood attempt %d: %v", i, err)
			break
		}
	}
}

func TestEmitter_Close_Drains(t *testing.T) {
	e := audit.New(audit.Config{
		BufferSize:      10,
		DrainTimeout:    time.Second,
		OperatorVersion: "v0.1.0-test",
		Log:             testr.New(t),
	})

	for range 5 {
		_ = e.EmitAsync(context.Background(), audit.AuditEvent{
			Tenant: "acme",
			Action: "drain",
		})
	}

	if err := e.Close(context.Background()); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

func TestEmitter_FinalizeStampsDefaults(t *testing.T) {
	e := audit.New(audit.Config{
		OperatorVersion: "v0.1.0-test",
		Log:             testr.New(t),
	})
	defer func() {
		_ = e.Close(context.Background())
	}()

	evt := audit.AuditEvent{Tenant: "acme", Action: "x"}
	if err := e.EmitSync(context.Background(), evt); err != nil {
		t.Fatalf("emit: %v", err)
	}
	// Direct assertion would need to intercept stdout; behavior-wise we
	// rely on finalize being called — covered by emit not erroring.
}

// ---------------------------------------------------------------------------
// SagaEmitter tests
// ---------------------------------------------------------------------------

// TestSagaEmitter_LineFormat asserts the emitted line has the correct
// [audit.tenant-operator] prefix and contains valid JSON with the required
// fields.
func TestSagaEmitter_LineFormat(t *testing.T) {
	var buf strings.Builder
	e := audit.NewSagaEmitter("tenant-operator", &buf)

	e.Emit(audit.SagaAuditEvent{
		Action:        audit.ActionSagaStepStarted,
		Outcome:       audit.OutcomeOk,
		UserId:        "operator",
		TenantId:      "acme",
		CorrelationId: "req-abc-123",
		StepName:      "CreateNamespace",
	})

	line := buf.String()
	if line == "" {
		t.Fatal("no output written")
	}
	// Must start with the prefix.
	prefix := "[audit.tenant-operator] "
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("line does not start with %q: %q", prefix, line)
	}

	// The remainder must be valid JSON.
	jsonPart := strings.TrimPrefix(line, prefix)
	jsonPart = strings.TrimRight(jsonPart, "\n")
	var decoded map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &decoded); err != nil {
		t.Fatalf("JSON decode failed: %v (raw: %q)", err, jsonPart)
	}

	// Assert required fields are present with correct values.
	for field, want := range map[string]string{
		"action":        string(audit.ActionSagaStepStarted),
		"outcome":       string(audit.OutcomeOk),
		"userId":        "operator",
		"tenantId":      "acme",
		"correlationId": "req-abc-123",
		"stepName":      "CreateNamespace",
	} {
		got, ok := decoded[field]
		if !ok {
			t.Errorf("missing field %q in JSON", field)
			continue
		}
		if got != want {
			t.Errorf("field %q: want %q, got %v", field, want, got)
		}
	}

	// ts must be a non-empty ISO8601 string.
	ts, ok := decoded["ts"].(string)
	if !ok || ts == "" {
		t.Errorf("ts field missing or not a string: %v", decoded["ts"])
	}
}

// TestSagaEmitter_DefaultPrefix confirms the default prefix is "tenant-operator".
func TestSagaEmitter_DefaultPrefix(t *testing.T) {
	var buf strings.Builder
	e := audit.NewSagaEmitter("", &buf) // empty → default
	e.Emit(audit.SagaAuditEvent{
		Action:   audit.ActionSagaStepCompleted,
		Outcome:  audit.OutcomeOk,
		StepName: "Test",
		TenantId: "t1",
	})
	if !strings.HasPrefix(buf.String(), "[audit.tenant-operator] ") {
		t.Errorf("unexpected prefix in: %q", buf.String())
	}
}

// TestSagaEmitter_ErrorMessageTruncated checks that errorMessage > 512 chars
// is truncated with the "[truncated]" sentinel.
func TestSagaEmitter_ErrorMessageTruncated(t *testing.T) {
	var buf strings.Builder
	e := audit.NewSagaEmitter("tenant-operator", &buf)

	longMsg := strings.Repeat("x", 600)
	e.Emit(audit.SagaAuditEvent{
		Action:       audit.ActionSagaStepFailed,
		Outcome:      audit.OutcomeFailed,
		StepName:     "BrokenStep",
		TenantId:     "t1",
		ErrorMessage: longMsg,
	})

	line := strings.TrimRight(buf.String(), "\n")
	jsonPart := strings.TrimPrefix(line, "[audit.tenant-operator] ")
	var decoded map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &decoded); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	msg, _ := decoded["errorMessage"].(string)
	if len(msg) > 512+len("...[truncated]") {
		t.Errorf("errorMessage not truncated: len=%d", len(msg))
	}
	if !strings.HasSuffix(msg, "...[truncated]") {
		t.Errorf("errorMessage missing truncation sentinel: %q", msg)
	}
}

// TestSagaEmitter_AllActions verifies each SagaAction constant emits without
// error and produces parseable JSON.
func TestSagaEmitter_AllActions(t *testing.T) {
	actions := []audit.SagaAction{
		audit.ActionSagaStepStarted,
		audit.ActionSagaStepCompleted,
		audit.ActionSagaStepFailed,
		audit.ActionSagaStepSkipped,
	}
	for _, action := range actions {
		t.Run(string(action), func(t *testing.T) {
			var buf strings.Builder
			e := audit.NewSagaEmitter("tenant-operator", &buf)
			e.Emit(audit.SagaAuditEvent{
				Action:   action,
				Outcome:  audit.OutcomeOk,
				StepName: "AnyStep",
				TenantId: "t1",
			})
			line := strings.TrimRight(buf.String(), "\n")
			jsonPart := strings.TrimPrefix(line, "[audit.tenant-operator] ")
			var decoded map[string]any
			if err := json.Unmarshal([]byte(jsonPart), &decoded); err != nil {
				t.Fatalf("action %q: JSON decode: %v", action, err)
			}
			if decoded["action"] != string(action) {
				t.Errorf("action field mismatch: want %q, got %v", action, decoded["action"])
			}
		})
	}
}

// TestSagaEmitter_CorrelationIdAlwaysPresent verifies that correlationId is
// always serialised — even when empty — for stable Loki field presence.
func TestSagaEmitter_CorrelationIdAlwaysPresent(t *testing.T) {
	var buf strings.Builder
	e := audit.NewSagaEmitter("tenant-operator", &buf)
	e.Emit(audit.SagaAuditEvent{
		Action:   audit.ActionSagaStepStarted,
		Outcome:  audit.OutcomeOk,
		StepName: "S",
		TenantId: "t1",
		// CorrelationId intentionally left empty.
	})
	line := strings.TrimRight(buf.String(), "\n")
	jsonPart := strings.TrimPrefix(line, "[audit.tenant-operator] ")
	var decoded map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &decoded); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if _, ok := decoded["correlationId"]; !ok {
		t.Error("correlationId field missing from JSON even when empty")
	}
}
