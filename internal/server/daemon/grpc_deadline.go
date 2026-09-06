// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"time"

	"google.golang.org/grpc"
)

// defaultUnaryDeadline bounds how long a single unary handler may run.
//
// 60 seconds is not a new policy — it is the bound the edge used to impose.
// Envoy carried `timeout: 60s` on every `/gibson.` route, which applied to
// unary and streaming alike because route matching is by path prefix and
// cannot tell the two apart. That was fatal for streaming: a Mission has no
// bounded duration (gibson CONTEXT.md), so every mission died at 60s. ADR-0063
// removes the edge timeout entirely and moves the unary half here, where the
// two call shapes ARE distinguishable.
const defaultUnaryDeadline = 60 * time.Second

// The bounds a configured deadline must fall inside.
//
// A floor exists because a deadline shorter than the slowest legitimate unary
// call turns a working RPC into a DeadlineExceeded, and the graph reads already
// carry their own multi-second budgets (graph_service.go graphQueryTimeout).
// A ceiling exists because the point of this interceptor is that SOMETHING
// bounds unary work now that the edge does not; a deadline measured in hours
// bounds nothing an operator would notice.
const (
	minUnaryDeadline = 1 * time.Second
	maxUnaryDeadline = 10 * time.Minute
)

// resolveUnaryDeadline turns a configured value into the deadline to enforce.
//
// It clamps rather than rejecting, because the alternative is a daemon that
// refuses to start over a transport tunable — and a daemon that will not start
// is worse than one running a sane deadline. Every adjustment is returned as a
// reason so the caller can log which value it actually got and why, instead of
// silently disagreeing with its own configuration.
func resolveUnaryDeadline(configured time.Duration) (deadline time.Duration, adjustment string) {
	switch {
	case configured == 0:
		return defaultUnaryDeadline, ""
	case configured < 0:
		return defaultUnaryDeadline, "negative deadline is meaningless; using the default"
	case configured < minUnaryDeadline:
		return minUnaryDeadline, "deadline below the floor would fail legitimate calls; raised to the floor"
	case configured > maxUnaryDeadline:
		return maxUnaryDeadline, "deadline above the ceiling bounds nothing useful; lowered to the ceiling"
	default:
		return configured, ""
	}
}

// newUnaryDeadlineInterceptor bounds every unary handler at d.
//
// # WHY THIS IS A UNARY INTERCEPTOR AND NOT A GENERAL ONE
//
// Streaming RPCs must never be reached by this. Making it a
// grpc.UnaryServerInterceptor is what guarantees that: grpc-go dispatches
// streaming handlers through the stream chain, so there is no code path by
// which RunMission, Subscribe, GetComponentLogs or any other server-streaming
// method can acquire this deadline. That is a structural guarantee rather than
// a promise to be careful, which matters because the failure mode — a mission
// silently ending early and reporting success — is close to undetectable.
//
// A caller's own deadline still wins. If the incoming context already carries
// one that is sooner, context.WithTimeout keeps the earlier of the two, so a
// client asking for 5s gets 5s rather than 60s.
//
// The cancellation propagates: a handler blocked on Postgres, Neo4j or an
// outbound RPC observes ctx.Done() and unwinds, so this frees the resources
// underneath the call and not merely the gRPC stream above it.
//
// The return type is the guarantee, checked by the compiler at this line:
// grpc.UnaryServerInterceptor cannot be installed on the stream chain, so no
// amount of later editing can attach this deadline to RunMission.
//
// ADR-0063.
func newUnaryDeadlineInterceptor(d time.Duration) grpc.UnaryServerInterceptor {
	d, _ = resolveUnaryDeadline(d)
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		return handler(ctx, req)
	}
}
