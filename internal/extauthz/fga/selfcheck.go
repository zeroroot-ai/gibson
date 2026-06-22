package fga

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
)

// SelfCheck performs a single Check round-trip against the configured FGA
// endpoint to verify the transport (host, port, protocol, store, model) is
// reachable BEFORE ext-authz enters the serving loop. The Check uses a
// well-formed but intentionally non-existent tuple; FGA returns
// {"allowed":false} for any unknown tuple, which is the success signal —
// we only care that the HTTP/JSON exchange completed end-to-end.
//
// Failure mode this catches: deploy#140 (2026-05-15) — ext-authz was wired
// to dial OpenFGA's gRPC port (8081) with an HTTP/1.x client and ran for
// hours returning gRPC UNAVAILABLE to every dashboard request, with no
// alarm at any cluster surface (pod was Ready, probes were green, Argo
// was Synced). The startup self-check turns silent multi-hour outages
// into a CrashLoop with a one-line root cause in the container log.
//
// On any transport-class error (DNS failure, connection refused, TLS
// handshake error, "malformed HTTP response" from a protocol mismatch),
// SelfCheck returns an error wrapping a clear diagnostic message that
// names the configured addr.
//
// Spec: ext-authz#24.
func SelfCheck(ctx context.Context, client FGAClient, addr string) error {
	if client == nil {
		return errors.New("fga.SelfCheck: client must not be nil")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Intentionally non-existent sentinel tuple. The naming convention
	// keeps the canary lookups visible in FGA audit logs and makes it
	// obvious to a future operator that these aren't real data.
	_, err := client.Check(ctx).
		Body(fgaclient.ClientCheckRequest{
			User:     "user:__ext_authz_selfcheck__",
			Relation: "owner",
			Object:   "tenant:__ext_authz_selfcheck__",
		}).
		Execute()
	if err == nil {
		return nil
	}

	if isTransportError(err) {
		return fmt.Errorf(
			"fga.SelfCheck: cannot reach OpenFGA at %q — probable port/protocol mismatch "+
				"(ext-authz uses HTTP/JSON; OpenFGA HTTP listener is on the httpPort, "+
				"NOT the grpcPort): %w",
			addr, err)
	}

	// Non-transport errors (e.g. authentication, model not found, store not
	// found) mean transport works but config is wrong — still a fatal
	// startup condition, but worth distinguishing in the log.
	return fmt.Errorf("fga.SelfCheck: Check round-trip failed against %q: %w", addr, err)
}

// isTransportError matches errors that indicate the FGA Check never reached
// the OpenFGA application layer (DNS, dial, TLS, HTTP framing). The OpenFGA
// Go SDK wraps the underlying net/http error, so we match on the error
// string for the few high-signal substrings that consistently indicate
// transport-class failure across DNS / dial / TLS / HTTP framing layers.
//
// We deliberately do NOT use errors.As against net.Error or url.Error, since
// the SDK wraps in a way that loses the typed unwrap chain in some cases.
// The string-match here is narrow enough to avoid false positives.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, marker := range []string{
		"malformed HTTP response", // HTTP/1.x client speaking to HTTP/2 server (deploy#140)
		"no such host",            // DNS failure
		"connection refused",      // dial failure (pod not up, wrong port)
		"connect: network is unreachable",
		"i/o timeout",               // dial / read timeout
		"context deadline exceeded", // 10s SelfCheck deadline elapsed
		"x509:",                     // TLS verification failure
		"tls: ",                     // TLS handshake failure
		"EOF",                       // server closed connection mid-handshake
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}
