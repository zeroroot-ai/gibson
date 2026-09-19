// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package helpers

import (
	"context"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/metadata"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestResolveSPIFFESocket is the gibson#14 fixture: a mounted socket
// directory that carries api.sock selects mTLS, a mounted directory with no
// socket is an error rather than a silent plaintext dial, the environment
// wins, and no mount at all is the one plaintext case.
func TestResolveSPIFFESocket(t *testing.T) {
	dir := t.TempDir()

	if got, err := resolveSPIFFESocket("unix:///elsewhere/x.sock", dir); err != nil || got != "unix:///elsewhere/x.sock" {
		t.Fatalf("env: got %q %v", got, err)
	}
	if _, err := resolveSPIFFESocket("", dir); err == nil {
		t.Fatal("a mounted directory with no socket must not fall back to plaintext")
	}
	if err := os.WriteFile(filepath.Join(dir, "api.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveSPIFFESocket("", dir); err != nil || got != "unix://"+filepath.Join(dir, "api.sock") {
		t.Fatalf("api.sock: got %q %v", got, err)
	}
	if got, err := resolveSPIFFESocket("", filepath.Join(dir, "absent")); err != nil || got != "" {
		t.Fatalf("no mount: got %q %v, want plaintext", got, err)
	}
}

// TestWithTenantHeader: the tenant a test puts on the context reaches the
// wire as x-gibson-identity-tenant, and a context with no tenant adds no
// header.
func TestWithTenantHeader(t *testing.T) {
	ctx := withTenantHeader(auth.ContextWithTenantString(context.Background(), "acme"))
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok || len(md.Get(auth.HeaderTenant)) != 1 || md.Get(auth.HeaderTenant)[0] != "acme" {
		t.Fatalf("outgoing metadata = %v", md)
	}
	if _, ok := metadata.FromOutgoingContext(withTenantHeader(context.Background())); ok {
		t.Fatal("a context with no tenant must add no metadata")
	}
}

// TestWaitForTerminal_StreamErrorIsTerminal: a stream_error ends the wait
// with the event itself, so the caller sees the daemon's status instead of a
// closed stream.
func TestWaitForTerminal_StreamErrorIsTerminal(t *testing.T) {
	ch := make(chan MissionEvent, 2)
	ch <- MissionEvent{EventType: "node_started"}
	ch <- MissionEvent{EventType: "stream_error", Error: "rpc error: code = Internal desc = failed to start mission: target not found"}
	close(ch)
	terminal, collected, err := WaitForTerminal(context.Background(), ch, time.Second)
	if err != nil {
		t.Fatalf("WaitForTerminal: %v", err)
	}
	if terminal.EventType != "stream_error" || len(collected) != 2 {
		t.Fatalf("terminal = %+v collected = %d", terminal, len(collected))
	}
	closed := make(chan MissionEvent)
	close(closed)
	if _, _, err := WaitForTerminal(context.Background(), closed, time.Second); err != ErrStreamClosed {
		t.Fatalf("closed channel: %v", err)
	}
}
