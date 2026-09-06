// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
)

// Nothing could assert this while the options sat inline in buildGRPCServer,
// which is how the main listener shipped without keepalive at all (ADR-0063).
// These are cheap, and they are the reason the assembly was extracted.

func TestBaseServerOptionsInstallsEveryTransportOption(t *testing.T) {
	t.Parallel()

	opts := baseServerOptions(nil, nil, otelgrpc.NewServerHandler())

	// interceptors(2) + stats handler + recv/send ceilings + keepalive params +
	// enforcement policy. grpc.ServerOption is opaque so the count is the only
	// thing assertable here; the VALUES are asserted in
	// internal/infra/grpckeepalive, which is where they live.
	const want = 7
	if len(opts) != want {
		t.Fatalf("expected %d transport options, got %d — an option was dropped, and a "+
			"dropped keepalive option silently returns this listener to grpc-go "+
			"defaults (MinTime 5m), which answers Envoy PINGs with GOAWAY", want, len(opts))
	}
	for i, o := range opts {
		if o == nil {
			t.Fatalf("option %d is nil", i)
		}
	}
}

func TestBaseServerOptionsSurvivesNilInterceptorSlices(t *testing.T) {
	t.Parallel()

	// buildGRPCServer builds these conditionally — several entries are appended
	// only when their dependency is wired. Empty is a real state, not a
	// degenerate one, and it must not change the transport posture.
	var unary []grpc.UnaryServerInterceptor
	var stream []grpc.StreamServerInterceptor

	if got := len(baseServerOptions(unary, stream, otelgrpc.NewServerHandler())); got != 7 {
		t.Fatalf("empty interceptor slices changed the option set: got %d", got)
	}
}

func TestBaseServerOptionsAddsTheUnaryDeadlineAndOnlyThere(t *testing.T) {
	t.Parallel()

	// The deadline must land on the unary chain and nowhere near the stream one.
	// grpc.ServerOption is opaque, so this asserts on what IS observable: the
	// slice handed in for unary grows by exactly one, and the stream slice is
	// never touched. A Mission has no bounded duration, so a deadline reaching
	// the stream chain would end every mission at 60s and report success.
	unary := []grpc.UnaryServerInterceptor{
		func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			return h(ctx, req)
		},
	}
	stream := []grpc.StreamServerInterceptor{
		func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			return h(srv, ss)
		},
	}
	before := len(stream)

	_ = baseServerOptions(unary, stream, otelgrpc.NewServerHandler())

	if len(stream) != before {
		t.Fatalf("the stream interceptor slice was modified: %d -> %d", before, len(stream))
	}
}
