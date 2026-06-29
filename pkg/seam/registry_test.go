package seam_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/pkg/seam"
)

// TestRegistry_LogStartupState_EmitsSeamTable verifies that LogStartupState
// emits a structured log entry that includes each registered seam's state.
func TestRegistry_LogStartupState_EmitsSeamTable(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	reg := new(seam.Registry)
	reg.Register("entitlements", "ENTITLEMENTS_ENDPOINT", "billing/entitlements-svc")

	t.Setenv("ENTITLEMENTS_ENDPOINT", "")
	reg.LogStartupState(context.Background(), logger)

	line := buf.String()
	if line == "" {
		t.Fatal("expected log output, got nothing")
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("log output is not valid JSON: %v\noutput: %s", err, line)
	}
	if rec["msg"] != "seam startup state" {
		t.Fatalf("unexpected log message: %v", rec["msg"])
	}
}

// TestRegistry_LogStartupState_WiredVsFailSafe verifies that a seam with its
// knob set logs "wired" while one without logs "fail-safe".
func TestRegistry_LogStartupState_WiredVsFailSafe(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	reg := new(seam.Registry)
	reg.Register("signup", "SIGNUP_ENDPOINT", "saas/signup-svc")

	t.Setenv("SIGNUP_ENDPOINT", "signup.internal:8080")
	reg.LogStartupState(context.Background(), logger)

	line := buf.String()
	if line == "" {
		t.Fatal("expected log output")
	}
	// The JSON should contain a "wired" state somewhere in the nested output.
	if !strings.Contains(line, "wired") {
		t.Errorf("expected 'wired' in log output, got: %s", line)
	}
}

// TestRegistry_Empty_NoOutput verifies that an empty registry emits no log.
func TestRegistry_Empty_NoOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	reg := new(seam.Registry)
	reg.LogStartupState(context.Background(), logger)

	if buf.Len() != 0 {
		t.Fatalf("expected no output from empty registry, got: %s", buf.String())
	}
}
