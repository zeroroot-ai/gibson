// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package grpckeepalive holds the keepalive posture every daemon gRPC
// listener must share.
//
// It exists because the two listeners drifted. Envoy PINGs both of them on the
// same 10-second interval (helm/gibson-workloads/files/envoy/envoy.yaml,
// clusters gibson_daemon_grpc and gibson_daemon_callback), but only the harness
// callback server was ever given a matching EnforcementPolicy. The main
// listener — the one carrying RunMission, Subscribe, ResumeMission,
// WatchManifestInvalidations and GetComponentLogs — kept grpc-go's defaults:
//
//	EnforcementPolicy{ MinTime: 5m, PermitWithoutStream: false }
//
// Thirty times stricter than the interval Envoy actually uses. grpc-go counts
// two strikes and answers GOAWAY `too_many_pings`, tearing down every in-flight
// mission stream on that connection.
//
// Having the numbers written out twice is what let one copy be fixed and the
// other not. They are written once here instead, so the two listeners cannot
// disagree again.
//
// ADR-0063.
package grpckeepalive

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

const (
	// PingInterval is how often a listener PINGs an idle peer. It matches the
	// `connection_keepalive.interval` Envoy uses toward the daemon; the two are
	// deliberately the same number so neither side surprises the other.
	PingInterval = 10 * time.Second

	// PingTimeout is how long to wait for a PING ack before closing. Must stay
	// below PingInterval so a PING is never still outstanding when the next
	// falls due.
	PingTimeout = 5 * time.Second

	// MinClientPingInterval is the floor a CLIENT must respect. It is
	// deliberately shorter than PingInterval: Envoy and the SDK both PING at
	// 10s, and a floor equal to that would make an ordinary jittered PING
	// arriving a millisecond early count as a strike.
	MinClientPingInterval = 5 * time.Second
)

// ServerParameters exposes the values Params carries, so tests can assert on
// the numbers rather than on the opaque grpc.ServerOption it returns.
func ServerParameters() keepalive.ServerParameters {
	return keepalive.ServerParameters{Time: PingInterval, Timeout: PingTimeout}
}

// EnforcementPolicy exposes the policy Enforcement carries. The MinTime it
// carries is the whole point of this package: grpc-go defaults it to 5 minutes,
// Envoy PINGs at 10 seconds, and the gap between those two numbers is what sent
// GOAWAY too_many_pings and killed live mission streams.
func EnforcementPolicy() keepalive.EnforcementPolicy {
	return keepalive.EnforcementPolicy{
		MinTime:             MinClientPingInterval,
		PermitWithoutStream: true,
	}
}

// Params is the keepalive-parameters option every daemon listener installs.
//
// PermitWithoutStream (in Enforcement) is true because a client holding an open
// connection with no active RPC is the normal state here — the SDK dials once
// and keeps the channel warm — and a peer forbidden from PINGing while idle
// cannot discover a connection the network has already dropped.
func Params() grpc.ServerOption { return grpc.KeepaliveParams(ServerParameters()) }

// Enforcement is the enforcement-policy option every daemon listener installs.
// Its MinTime is the whole reason this package exists: see EnforcementPolicy.
func Enforcement() grpc.ServerOption { return grpc.KeepaliveEnforcementPolicy(EnforcementPolicy()) }
