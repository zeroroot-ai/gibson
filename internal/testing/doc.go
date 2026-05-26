// Package testing provides test utilities and helpers for Gibson tests.
//
// This package includes helpers for:
//   - Tenant context injection for multi-tenant testing
//   - Common test patterns and utilities
//
// The tenant helpers ensure that tests work correctly with tenant-scoped
// resources like Redis and Neo4j, which require tenant context for proper
// data isolation in SaaS mode.
//
// Example:
//
//	import testutil "github.com/zeroroot-ai/gibson/internal/testing"
//
//	func TestWithTenantScope(t *testing.T) {
//	    ctx := testutil.WithTestTenant()
//	    // Use ctx for tenant-scoped operations
//	}
package testing
