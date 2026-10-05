// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"
)

// TestCallbackManager_SetToolCallSink proves the manager-level setter reaches
// the underlying callback service (ADR-0120, gibson#271) — the same wiring
// contract as SetLLMCallSink, exercised here before Start() (construction
// alone is enough: NewCallbackServerWithRegistry builds the service eagerly).
func TestCallbackManager_SetToolCallSink(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{ListenAddress: "127.0.0.1:0"}, slog.Default())

	var got ToolCallRecord
	var gotTenant string
	m.SetToolCallSink(func(_ context.Context, tenant string, call ToolCallRecord) {
		gotTenant = tenant
		got = call
	})

	if m.server == nil || m.server.service == nil {
		t.Fatal("manager must construct its server/service eagerly")
	}
	if m.server.service.toolCallSink == nil {
		t.Fatal("SetToolCallSink must reach the underlying callback service")
	}
	m.server.service.toolCallSink(context.Background(), "acme", ToolCallRecord{ToolCallID: "tc1"})
	if gotTenant != "acme" || got.ToolCallID != "tc1" {
		t.Fatalf("sink did not receive the call: tenant=%q call=%+v", gotTenant, got)
	}
}

// TestCallbackManager_SetToolCallSink_NilServerIsNoOp proves the setter is
// safe to call on a manager with no server (defensive guard, same shape as
// the other Set* methods).
func TestCallbackManager_SetToolCallSink_NilServerIsNoOp(_ *testing.T) {
	m := &CallbackManager{logger: slog.Default()}
	m.SetToolCallSink(func(context.Context, string, ToolCallRecord) {})
}
