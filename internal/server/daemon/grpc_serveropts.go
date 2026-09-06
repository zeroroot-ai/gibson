// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"

	"github.com/zeroroot-ai/gibson/internal/infra/grpckeepalive"
)

// baseServerOptions assembles the transport-level options for the daemon's main
// gRPC listener.
//
// It is a package-level function rather than an inline literal inside
// buildGRPCServer because buildGRPCServer is 1500 lines with roughly forty
// dependencies and is untestable in practice — the repo says so in
// discovery_wiring_test.go. Nothing could assert that the keepalive options
// were installed at all while they lived in there, which is precisely how the
// main listener went without them (ADR-0063). Out here, a test can.
//
// It takes its inputs as arguments and reads no daemon state, so it stays
// callable from a test with nothing constructed.
func baseServerOptions(
	unary []grpc.UnaryServerInterceptor,
	stream []grpc.StreamServerInterceptor,
	otel stats.Handler,
) []grpc.ServerOption {
	// The unary deadline goes LAST, so it wraps the handler alone. Recovery,
	// scrubbing, correlation and validation all run outside it: they are fast and
	// non-blocking, and a validation rejection should not be racing a timeout.
	// It is on the UNARY chain only — a Mission has no bounded duration, so no
	// streaming handler may ever acquire a deadline (ADR-0063).
	unary = append(unary, newUnaryDeadlineInterceptor(defaultUnaryDeadline))

	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(stream...),
		grpc.StatsHandler(otel),
		// Explicit per-message ceilings. Callers on this server include
		// components running inside sandboxes, so the cost one message may
		// impose on the daemon is stated here rather than inherited from
		// grpc-go's defaults.
		grpc.MaxRecvMsgSize(maxDaemonRecvMsgBytes),
		grpc.MaxSendMsgSize(maxDaemonSendMsgBytes),
		// Shared with the harness callback listener. Envoy PINGs both on the
		// same interval; grpc-go's default enforcement answers that with GOAWAY
		// too_many_pings and tears down live mission streams. ADR-0063.
		grpckeepalive.Params(),
		grpckeepalive.Enforcement(),
	}
}
