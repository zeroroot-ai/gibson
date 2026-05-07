package harness

import (
	"fmt"
	"net"
)

// rejectNonLoopbackWithoutSPIFFE enforces critical-tls-no-fallbacks Requirement
// 1.5 (was security-hardening R1.4) for the harness callback listener: when
// SPIFFE mTLS is not configured the callback server may only bind on loopback
// (127.0.0.0/8 or [::1]). Any other address is rejected with an error pointing
// the operator at the chart values they need to populate, including the new
// GIBSON_CALLBACK_PEER_SVIDS allowlist that initSPIFFEX509Source consumes.
//
// This mirrors the daemon-side rejectNonLoopbackWithoutSPIFFE guard at
// `core/gibson/internal/daemon/grpc.go:1101`. Keeping a sibling helper in the
// harness package avoids importing daemon → harness (an import cycle).
func rejectNonLoopbackWithoutSPIFFE(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf(
			"callback listener cannot bind to %q without SPIFFE: invalid address format (%w); "+
				"populate gibson.config.callback.spiffe.peerSvids in chart values "+
				"(rendered as GIBSON_CALLBACK_PEER_SVIDS env on the daemon) and ensure "+
				"GIBSON_SPIFFE_ENVOY_ID is set to enable mTLS, "+
				"or restrict callback.listenAddress to a loopback address — "+
				"spec: critical-tls-no-fallbacks Requirement 1.5",
			addr, err,
		)
	}

	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf(
			"callback listener refuses to bind to non-loopback address %q without SPIFFE mTLS: "+
				"a non-loopback bind without transport security exposes the identity-header "+
				"trust path to in-cluster attackers; populate gibson.config.callback.spiffe.peerSvids "+
				"(rendered as GIBSON_CALLBACK_PEER_SVIDS) and GIBSON_SPIFFE_ENVOY_ID, "+
				"or set callback.listenAddress to 127.0.0.1 / [::1] — "+
				"spec: critical-tls-no-fallbacks Requirement 1.5",
			addr,
		)
	}

	if host == "localhost" {
		return nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf(
			"callback listener refuses to bind to non-loopback hostname %q without SPIFFE mTLS; "+
				"populate gibson.config.callback.spiffe.peerSvids (rendered as "+
				"GIBSON_CALLBACK_PEER_SVIDS) or use 127.0.0.1 / [::1] — "+
				"spec: critical-tls-no-fallbacks Requirement 1.5",
			addr,
		)
	}

	if !ip.IsLoopback() {
		return fmt.Errorf(
			"callback listener refuses to bind to non-loopback address %q without SPIFFE mTLS: "+
				"populate gibson.config.callback.spiffe.peerSvids (rendered as "+
				"GIBSON_CALLBACK_PEER_SVIDS) or restrict the listen address to "+
				"a loopback interface — spec: critical-tls-no-fallbacks Requirement 1.5",
			addr,
		)
	}

	return nil
}
