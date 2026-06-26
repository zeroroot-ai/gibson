// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestNewClient_RequiresAddr asserts the input-validation guard fires.
//
// Construction-level guards are tested at the unit level because they're
// reached before any I/O — the full mTLS handshake path is covered by the
// kind-up-smoke end-to-end signup test (PRD tenant-operator#76, Module 8).
func TestNewClient_RequiresAddr(t *testing.T) {
	_, err := NewClient(context.Background(), Options{
		DaemonSVID: "spiffe://zeroroot.ai/platform/daemon",
	})
	if err == nil {
		t.Fatal("expected error when Addr is empty, got nil")
	}
	if !strings.Contains(err.Error(), "Addr is required") {
		t.Errorf("error message should mention Addr; got %q", err.Error())
	}
}

// TestNewClient_RequiresDaemonSVID asserts the SVID guard fires.
func TestNewClient_RequiresDaemonSVID(t *testing.T) {
	_, err := NewClient(context.Background(), Options{
		Addr: "gibson-workloads:50051",
	})
	if err == nil {
		t.Fatal("expected error when DaemonSVID is empty, got nil")
	}
	if !strings.Contains(err.Error(), "DaemonSVID is required") {
		t.Errorf("error message should mention DaemonSVID; got %q", err.Error())
	}
}

// TestNewClient_RejectsUnparseableSVID asserts the SVID is validated as a
// SPIFFE ID (not just a non-empty string). A malformed SVID in chart values
// — the bug class this guard targets — fails fast at operator startup, not
// at mid-saga.
func TestNewClient_RejectsUnparseableSVID(t *testing.T) {
	_, err := NewClient(context.Background(), Options{
		Addr:       "gibson-workloads:50051",
		DaemonSVID: "this-is-not-a-spiffe-id",
	})
	if err == nil {
		t.Fatal("expected error when DaemonSVID is not a parseable SPIFFE ID, got nil")
	}
	if !strings.Contains(err.Error(), "not a parseable SPIFFE ID") {
		t.Errorf("error message should explain parse failure; got %q", err.Error())
	}
}

// TestNewClient_SocketUnavailable asserts that pointing at a non-existent
// SPIRE Workload API socket produces a clear error wrapped with the package
// prefix when the caller's context expires — the saga's transient retry
// policy honors this. go-spiffe retries internally; the deadline is the
// caller's contract.
func TestNewClient_SocketUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := NewClient(ctx, Options{
		Addr:              "gibson-workloads:50051",
		DaemonSVID:        "spiffe://zeroroot.ai/platform/daemon",
		WorkloadAPISocket: "unix:///tmp/this-socket-does-not-exist-" + t.Name(),
	})
	if err == nil {
		t.Fatal("expected error when SPIRE socket is unavailable, got nil")
	}
	// The error must carry the package prefix so callers (and the saga's
	// log filters) can identify the layer.
	if !strings.Contains(err.Error(), "daemon-transport:") {
		t.Errorf("error should carry daemon-transport: prefix; got %q", err.Error())
	}
	// Defensive — wrapping nil would mask real bugs in the constructor.
	if errors.Is(err, nil) {
		t.Errorf("wrapped error must not be nil")
	}
}

// TestClient_CloseNilSafe asserts Close is idempotent on a never-constructed
// Client (Go zero value). The operator's shutdown path defers Close before
// the constructor has necessarily succeeded; double-Close must not panic.
func TestClient_CloseNilSafe(t *testing.T) {
	var c *Client
	if err := c.Close(); err != nil {
		t.Errorf("Close on nil Client should be no-op; got %v", err)
	}
	c2 := &Client{}
	if err := c2.Close(); err != nil {
		t.Errorf("Close on zero-value Client should be no-op; got %v", err)
	}
	// Second call must also be safe.
	if err := c2.Close(); err != nil {
		t.Errorf("second Close on zero-value Client should be no-op; got %v", err)
	}
}
