// Package authz — workcontext.go defines constants for the work-item authz context
// that the harness attaches to dispatched work items.
//
// The HMAC signing system has been removed per admin-services-completion
// Requirement 6.4 (dead defense-in-depth; no verifier ever existed in the SDK).
// These constants are retained because they are still used to populate the
// queue.AuthzContext fields (run_id, issued_at, ttl_seconds) in the harness.
package authz

const (
	// DefaultWorkTTLSeconds is the default TTL for work envelope AuthzContexts.
	// 10 minutes is long enough for normal tool execution but short enough to
	// limit the window of stale authz in queues.
	DefaultWorkTTLSeconds = 600

	// AuthzContextWorkKey is the key used in the work item Context map to carry
	// the JSON-encoded queue.AuthzContext. Shared between harness dispatch
	// (daemon side) and serve loop verification (SDK side).
	AuthzContextWorkKey = "authz_context"
)
