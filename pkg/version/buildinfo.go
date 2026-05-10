// Default build-info: setec_integration off.
//
// This file's package-level variable defaults to "off". A peer file
// (`buildinfo_setec.go`) builds only when the `setec_integration` tag is
// set and overrides the same variable to "on" at compile time.
//
// The dispatch policy gate (via the harness), the `Connect` RPC's version
// info, and the production-mode startup self-check all read this single
// source of truth.
//
// Spec: setec-sandbox-prod-default §C1 (R1.3, R1.4).

//go:build !setec_integration

package version

// BuildTagSetecIntegration reports whether the binary was built with the
// `setec_integration` build tag. "on" means the Setec sandbox adapter is
// linked in; "off" means the SDK / dev stub is in use.
var BuildTagSetecIntegration = "off"
