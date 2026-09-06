// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package grpckeepalive

import (
	"testing"
	"time"
)

// The number Envoy is configured with, in
// helm/gibson-workloads/files/envoy/envoy.yaml, on the clusters that reach both
// daemon listeners. Restated here so a change to either side that breaks the
// pairing fails a test rather than a mission.
const envoyPingInterval = 10 * time.Second

func TestEnforcementPolicyAdmitsTheIntervalEnvoyActuallyUses(t *testing.T) {
	t.Parallel()

	got := EnforcementPolicy()

	// This is the whole bug. grpc-go's default MinTime is 5 minutes; Envoy PINGs
	// every 10 seconds. Two strikes and the server sends GOAWAY too_many_pings,
	// which kills every in-flight mission stream on that connection.
	if got.MinTime >= envoyPingInterval {
		t.Fatalf("MinTime %s does not admit Envoy PINGs at %s — the server will "+
			"answer GOAWAY too_many_pings and tear down live mission streams",
			got.MinTime, envoyPingInterval)
	}

	// A client with no active RPC must still be allowed to PING, or it cannot
	// discover a connection the network already dropped. The SDK dials once and
	// keeps the channel warm, so this is the normal state, not an edge case.
	if !got.PermitWithoutStream {
		t.Fatal("PermitWithoutStream is false: an idle client that PINGs would be " +
			"struck, and the SDK holds idle channels open by design")
	}
}

func TestPingTimeoutStaysUnderTheInterval(t *testing.T) {
	t.Parallel()

	p := ServerParameters()
	if p.Timeout >= p.Time {
		t.Fatalf("Timeout %s >= Time %s: a PING would still be outstanding when "+
			"the next one falls due", p.Timeout, p.Time)
	}
}

func TestBothOptionsAreConstructed(t *testing.T) {
	t.Parallel()

	// grpc.ServerOption is opaque, so this cannot read the values back — the two
	// tests above assert those. What it catches is a listener installing nothing:
	// a nil option would leave both listeners silently on grpc-go's defaults,
	// which is the state that sent GOAWAY and killed mission streams.
	if Params() == nil {
		t.Fatal("Params returned nil: the listener would install no keepalive parameters")
	}
	if Enforcement() == nil {
		t.Fatal("Enforcement returned nil: the listener would fall back to grpc-go MinTime 5m")
	}
}
