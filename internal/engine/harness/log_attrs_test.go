// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

// logAttrsCases is the shared table for both Log implementations. Every
// level is exercised so the switch arms are covered, plus the unknown-level
// default and the empty/nil field maps (the len(fields) capacity edge).
var logAttrsCases = []struct {
	name   string
	level  string
	fields map[string]any
}{
	{"debug", "debug", map[string]any{"a": 1}},
	{"info", "info", map[string]any{"a": 1, "b": "two"}},
	{"warn", "warn", map[string]any{"a": 1}},
	{"error", "error", map[string]any{"a": 1}},
	{"unknown level falls through to default", "trace", map[string]any{"a": 1}},
	{"empty fields", "info", map[string]any{}},
	{"nil fields", "info", nil},
}

// captureLogger returns a JSON-handler logger writing into buf at the most
// verbose level, so debug records are not dropped before assertion.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestDefaultAgentHarness_Log covers DefaultAgentHarness.Log, which builds
// one slog.Any per field (gibson#1444 — it previously built an interleaved
// key, value slice with a len(fields)*2 capacity).
func TestDefaultAgentHarness_Log(t *testing.T) {
	for _, tc := range logAttrsCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := &DefaultAgentHarness{logger: captureLogger(&buf)}

			h.Log(tc.level, "hello", tc.fields)

			assertLoggedFields(t, buf.Bytes(), tc.fields)
		})
	}
}

// TestMiddlewareHarness_Log covers the MiddlewareHarness.Log counterpart,
// which already used slog.Any but over-reserved capacity by 2x.
func TestMiddlewareHarness_Log(t *testing.T) {
	for _, tc := range logAttrsCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := NewMiddlewareHarness(&loggerOnlyHarness{logger: captureLogger(&buf)}, nil)

			h.Log(tc.level, "hello", tc.fields)

			assertLoggedFields(t, buf.Bytes(), tc.fields)
		})
	}
}

// assertLoggedFields checks that exactly one record was emitted carrying the
// message and every field as a top-level attribute. This is what pins the
// "one slog.Any per field" shape: an interleaved slice sized wrong, or a
// dropped field, changes this JSON.
func assertLoggedFields(t *testing.T, out []byte, fields map[string]any) {
	t.Helper()
	if len(out) == 0 {
		t.Fatal("expected a log record, got none")
	}
	var rec map[string]any
	if err := json.Unmarshal(out, &rec); err != nil {
		t.Fatalf("log record is not valid JSON (%v): %s", err, out)
	}
	if rec["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", rec["msg"])
	}
	for k := range fields {
		if _, ok := rec[k]; !ok {
			t.Errorf("field %q missing from record: %s", k, out)
		}
	}
}

// loggerOnlyHarness embeds the package's no-op AgentHarness and overrides
// just Logger(), so MiddlewareHarness.Log writes somewhere observable.
type loggerOnlyHarness struct {
	noopInnerHarness
	logger *slog.Logger
}

func (h *loggerOnlyHarness) Logger() *slog.Logger { return h.logger }
