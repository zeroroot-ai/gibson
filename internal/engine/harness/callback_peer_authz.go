// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// peerSPIFFEID extracts the connecting peer's SPIFFE URI SAN from ctx. It
// mirrors the extraction logic in internal/server/daemon/grpc.go's
// spiffePlatformBypass so both listeners identify peers identically.
//
// Returns ok=false when the connection carries no verified TLS peer certificate
// or the certificate carries no SPIFFE URI SAN. Under SPIFFE mTLS that outcome
// is a DENY (checkCallbackPeerAuthz), not a pass-through: on a listener wrapped
// in tlsconfig.MTLSServerConfig every accepted connection must carry a SPIFFE
// leaf, so failing to resolve one means the peer cannot be identified and no
// policy can be applied to it.
func peerSPIFFEID(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", false
	}
	for _, u := range tlsInfo.State.PeerCertificates[0].URIs {
		if u != nil && strings.HasPrefix(u.Scheme, "spiffe") {
			return u.String(), true
		}
	}
	return "", false
}

// checkCallbackPeerAuthz is the shared, transport-agnostic decision used by both
// interceptors below. It is fail-closed in all three ways the previous denylist
// was fail-open:
//
//   - resolved == false → DENY. The peer presented no usable SPIFFE identity on
//     a SPIFFE-pinned listener; an unidentifiable peer gets nothing. The old
//     code returned early and let the request through untouched.
//   - svid has no entry in policies → DENY. An unknown or newly-added peer SVID
//     gets nothing. The old denylist gave every unnamed peer FULL access to all
//     RPCs, including GetCredential, by default.
//   - method not in the peer's policy → DENY (least privilege). The old code had
//     no per-method dimension at all.
//
// Extracted as a pure function (given an already-resolved svid) so the
// fail-closed semantics are directly unit testable without a live TLS peer.
// ctx is taken solely to propagate it into the structured-log call
// (logger.WarnContext), matching this codebase's context-aware logging
// convention — the decision itself does no I/O and never blocks on ctx.
func checkCallbackPeerAuthz(ctx context.Context, svid string, resolved bool, method string, policies map[string]map[string]bool, logger *slog.Logger) error {
	deny := func(reason string, err error) error {
		if logger != nil {
			logger.WarnContext(ctx, "harness callback: peer denied by method policy",
				"event", "callback.authz.peer_denied",
				"spiffe_id", svid,
				"method", method,
				"reason", reason,
			)
		}
		return err
	}

	if !resolved {
		return deny("no_peer_spiffe_id", status.Error(codes.PermissionDenied,
			"harness callback: peer presented no SPIFFE identity; denied"))
	}
	methods, policed := policies[svid]
	if !policed {
		return deny("peer_not_policed", status.Errorf(codes.PermissionDenied,
			"SPIFFE peer %q has no HarnessCallbackService method policy; denied", svid))
	}
	if !methods[method] {
		return deny("method_not_in_policy", status.Errorf(codes.PermissionDenied,
			"SPIFFE peer %q is not authorised to call %q", svid, method))
	}
	return nil
}

// callbackPeerAuthzInterceptors builds the unary/stream interceptor pair that
// applies the per-peer method policy BEFORE the request reaches the
// header-trusting auth.UnaryServerInterceptor()/StreamServerInterceptor(). They
// must run first in the chain: a peer that is not authorised for the method must
// never get as far as having its raw x-gibson-identity-* headers trusted.
//
// enforce mirrors "the listener is wrapped in SPIFFE mTLS"
// (CallbackServer.spiffeSource != nil). With SPIFFE unwired there is no peer
// certificate to derive an identity from, so there is no policy to apply; that
// posture is confined to the plaintext loopback dev/test bind, which
// rejectNonLoopbackWithoutSPIFFE (listener_guard.go) already refuses to expose
// on any non-loopback address. Every production bind runs with enforce=true.
func callbackPeerAuthzInterceptors(logger *slog.Logger, enforce bool) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	policies := callbackPeerMethodPolicies()

	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if enforce {
			svid, ok := peerSPIFFEID(ctx)
			if err := checkCallbackPeerAuthz(ctx, svid, ok, info.FullMethod, policies, logger); err != nil {
				return nil, err
			}
		}
		return handler(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if enforce {
			ctx := ss.Context()
			svid, ok := peerSPIFFEID(ctx)
			if err := checkCallbackPeerAuthz(ctx, svid, ok, info.FullMethod, policies, logger); err != nil {
				return err
			}
		}
		return handler(srv, ss)
	}
	return unary, stream
}
