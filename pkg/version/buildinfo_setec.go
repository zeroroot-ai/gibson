// Setec-tag-on build-info: setec_integration ON.
//
// This file builds only under `-tags setec_integration` and shadows the
// default `BuildTagSetecIntegration = "off"` declaration in buildinfo.go
// (which is gated on the inverse `!setec_integration` tag, so exactly one
// of the two compiles in any given build).
//
// Spec: setec-sandbox-prod-default §C1 (R1.3, R1.4).

//go:build setec_integration

package version

// BuildTagSetecIntegration reports that the binary was built with the
// `setec_integration` build tag. The Setec sandbox adapter is linked in;
// the production-mode self-check at startup will not refuse.
var BuildTagSetecIntegration = "on"
