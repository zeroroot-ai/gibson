// Package tenant defines canonical per-tenant resource names and key
// derivation helpers shared by the Gibson daemon and the tenant-operator.
//
// This is platform-internal infrastructure code. It is NOT part of the
// customer-facing SDK at github.com/zero-day-ai/sdk. Customers building
// agents, tools, and plugins should never import from this package — the
// resource names and KEK helpers it exposes are implementation details of
// the Gibson control plane that we coordinate between gibson and
// tenant-operator. Stability is governed by the gibson tag, not by SDK
// semver guarantees.
//
// # Why this lives here
//
// gibson and tenant-operator are two halves of the same control plane. The
// daemon writes per-tenant Postgres rows; the operator creates the per-tenant
// Postgres role. They must agree byte-for-byte on every per-tenant resource
// name, or runtime authentication fails. Putting the canonical naming logic
// in this package — and having both binaries import it — makes such drift
// structurally impossible.
//
// # What does NOT belong here
//
// Anything customer-facing: agent/tool/plugin contracts, secrets broker
// interfaces, identity types. Those live in github.com/zero-day-ai/sdk.
// This package depends on github.com/zero-day-ai/sdk/auth (for the sealed
// TenantID type) and stdlib only — keeping it a leaf package so the
// operator's go.sum doesn't accidentally pull in the daemon's full
// dependency closure.
//
// # Stability contract
//
// The string formats returned by Names methods (PostgresAppRole, FGAObject,
// VaultPathPrefix, etc.) are coupled to provisioned state in production
// clusters. Changing any format is a breaking change requiring a coordinated
// migration across operator, daemon, and chart, plus a re-provisioning sweep
// on every existing tenant. Add new methods freely; renaming or repurposing
// existing ones requires the same careful migration as a SQL schema change.
package tenant
