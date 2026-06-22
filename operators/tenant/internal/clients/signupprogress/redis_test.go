/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package signupprogress

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newClient spins up a miniredis instance and returns a ready-to-use
// Client wrapping it, plus the *miniredis.Miniredis for assertions on
// the wire-encoded value.
func newClient(t *testing.T) (*RedisClient, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	c := NewRedisClientFromRedis(rdb, 5*time.Minute, DefaultKeyPrefix)
	return c, mr
}

// readJSON pulls a value out of miniredis and unmarshals it.
func readJSON(t *testing.T, mr *miniredis.Miniredis, key string) Progress {
	t.Helper()
	raw, err := mr.Get(key)
	if err != nil {
		t.Fatalf("miniredis Get %q: %v", key, err)
	}
	var p Progress
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("Unmarshal Progress: %v; raw=%q", err, raw)
	}
	return p
}

// TestNewRedisClient_EmptyAddrReturnsNil renamed +
// behavior-inverted in the one-code-path epic (deploy#199): an empty
// Addr now returns an error rather than the previous (nil, nil)
// "degraded" sentinel. See TestNewRedisClient_EmptyAddr_Errors below.

func TestAdvance_WritesInflightProgress(t *testing.T) {
	t.Parallel()
	c, mr := newClient(t)
	ctx := context.Background()

	if err := c.Advance(ctx, "attempt-1", StepProvisioningSecretsBackend); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	got := readJSON(t, mr, DefaultKeyPrefix+"attempt-1")
	if got.Step != StepProvisioningSecretsBackend {
		t.Fatalf("expected step=%q, got %q", StepProvisioningSecretsBackend, got.Step)
	}
	if got.TerminalState != TerminalNone {
		t.Fatalf("expected non-terminal, got terminalState=%q", got.TerminalState)
	}
	if got.Error != nil {
		t.Fatalf("expected no error payload, got %+v", got.Error)
	}
	if got.StepStartedAt <= 0 {
		t.Fatalf("expected stepStartedAt > 0, got %d", got.StepStartedAt)
	}
}

func TestComplete_WritesTerminalOK(t *testing.T) {
	t.Parallel()
	c, mr := newClient(t)
	ctx := context.Background()

	if err := c.Complete(ctx, "attempt-2", StepProvisioningSecretsBackend); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got := readJSON(t, mr, DefaultKeyPrefix+"attempt-2")
	if got.TerminalState != TerminalOK {
		t.Fatalf("expected terminalState=%q, got %q", TerminalOK, got.TerminalState)
	}
}

func TestFail_WritesTerminalFailedWithErrorPayload(t *testing.T) {
	t.Parallel()
	c, mr := newClient(t)
	ctx := context.Background()

	const msg = "We couldn't provision your secrets backend."
	if err := c.Fail(
		ctx, "attempt-3", StepProvisioningSecretsBackend,
		CodeSecretsNamespaceFailed, msg,
	); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	got := readJSON(t, mr, DefaultKeyPrefix+"attempt-3")
	if got.TerminalState != TerminalFailed {
		t.Fatalf("expected terminalState=%q, got %q", TerminalFailed, got.TerminalState)
	}
	if got.Error == nil {
		t.Fatal("expected error payload, got nil")
	}
	if got.Error.Code != CodeSecretsNamespaceFailed {
		t.Fatalf("expected code=%q, got %q", CodeSecretsNamespaceFailed, got.Error.Code)
	}
	if got.Error.UserMessage != msg {
		t.Fatalf("expected userMessage=%q, got %q", msg, got.Error.UserMessage)
	}
}

func TestEmptyAttemptIDIsNoop(t *testing.T) {
	t.Parallel()
	c, mr := newClient(t)
	ctx := context.Background()

	for _, op := range []func() error{
		func() error { return c.Advance(ctx, "", StepProvisioningSecretsBackend) },
		func() error { return c.Complete(ctx, "", StepProvisioningSecretsBackend) },
		func() error {
			return c.Fail(ctx, "", StepProvisioningSecretsBackend, CodeSecretsNamespaceFailed, "msg")
		},
	} {
		if err := op(); err != nil {
			t.Fatalf("expected nil error for empty attempt id, got %v", err)
		}
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("expected no keys written for empty attempt id, got %v", keys)
	}
}

func TestPublishOverwritesPreviousValue(t *testing.T) {
	t.Parallel()
	c, mr := newClient(t)
	ctx := context.Background()

	if err := c.Advance(ctx, "attempt-4", StepProvisioningSecretsBackend); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	if err := c.Complete(ctx, "attempt-4", StepProvisioningSecretsBackend); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got := readJSON(t, mr, DefaultKeyPrefix+"attempt-4")
	if got.TerminalState != TerminalOK {
		t.Fatalf("expected last write (Complete) to win, got %q", got.TerminalState)
	}
}

func TestPublishSetsTTL(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	c := NewRedisClientFromRedis(rdb, 30*time.Second, DefaultKeyPrefix)

	ctx := context.Background()
	if err := c.Advance(ctx, "attempt-ttl", StepProvisioningSecretsBackend); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	ttl := mr.TTL(DefaultKeyPrefix + "attempt-ttl")
	// miniredis returns the TTL as a Duration; allow a small slack window
	// for clock drift even though miniredis is in-process.
	if ttl <= 0 || ttl > 30*time.Second {
		t.Fatalf("expected TTL in (0, 30s], got %s", ttl)
	}
}

func TestPing_HappyPath(t *testing.T) {
	t.Parallel()
	c, _ := newClient(t)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// TestNewRedisClient_EmptyAddr_Errors pins the one-code-path contract
// (deploy#199): an empty Addr returns an error rather than a (nil, nil)
// "degraded" sentinel. The previous NoopClient fallback is deleted.
func TestNewRedisClient_EmptyAddr_Errors(t *testing.T) {
	t.Parallel()
	c, err := NewRedisClient(Config{Addr: ""})
	if err == nil {
		t.Fatalf("NewRedisClient(Addr=\"\") returned err=nil, want non-nil; client=%v", c)
	}
	if c != nil {
		t.Fatalf("NewRedisClient(Addr=\"\") returned non-nil client; want nil. client=%v", c)
	}
}

// TestProgressJSONShape pins the wire shape that the dashboard's
// ProvisioningProgress TypeScript interface consumes. Field names and
// presence rules MUST match `app/(public)/signup/types.ts`.
func TestProgressJSONShape(t *testing.T) {
	t.Parallel()

	// In-flight: no terminalState, no error.
	inflight := Progress{
		Step:          StepProvisioningSecretsBackend,
		StepStartedAt: 1700000000000,
	}
	raw, err := json.Marshal(inflight)
	if err != nil {
		t.Fatalf("Marshal inflight: %v", err)
	}
	const wantInflight = `{"step":"provisioning_secrets_backend","stepStartedAt":1700000000000}`
	if string(raw) != wantInflight {
		t.Fatalf("inflight wire shape:\n got %q\nwant %q", string(raw), wantInflight)
	}

	// Failed: includes error payload.
	failed := Progress{
		Step:          StepProvisioningSecretsBackend,
		StepStartedAt: 1700000000000,
		TerminalState: TerminalFailed,
		Error: &ProgressError{
			Code:        CodeSecretsNamespaceFailed,
			UserMessage: "msg",
		},
	}
	raw, err = json.Marshal(failed)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	const wantFailed = `{"step":"provisioning_secrets_backend","stepStartedAt":1700000000000,"terminalState":"failed","error":{"code":"SECRETS_NAMESPACE_FAILED","userMessage":"msg"}}`
	if string(raw) != wantFailed {
		t.Fatalf("failed wire shape:\n got %q\nwant %q", string(raw), wantFailed)
	}
}
