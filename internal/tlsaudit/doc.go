// Package tlsaudit hosts CI guards that statically audit the workspace for
// TLS-related security regressions. It contains test code only — no
// production-shipping symbols. The package exists in its own directory so the
// CI guards (e.g. TestNoFallbackAudit for spec critical-tls-no-fallbacks) can
// be run even when transient sibling-spec WIP breaks the daemon's import graph.
package tlsaudit
