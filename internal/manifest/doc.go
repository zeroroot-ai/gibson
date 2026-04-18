// Package manifest implements the daemon side of the capability manifest
// pipeline (spec: capability-manifest-rpc).
//
// The manifest is a single, signed, versioned snapshot of every component,
// permission, cross-component rule, limit, and runtime context that applies
// to a principal in their resolved tenant. Two consumers share the same
// proto shape:
//
//   - the SDK calls GetCapabilityManifest on session start, caches the
//     result under TTL + invalidation, and enforces permission decisions
//     locally before round-tripping to the daemon;
//   - the ADK calls it at scaffold-time so generated agent code references
//     only valid, permitted components.
//
// The daemon remains the source of truth and re-checks every Harness call
// against live FGA — the manifest is the SDK/ADK's projection of that
// truth, not a replacement.
//
// Package layout:
//
//	doc.go          package documentation (this file)
//	types.go        value types (ManifestSubject, BuilderConfig, SigningKeyJWK, …)
//	interfaces.go   interfaces (Builder, Signer, VersionStore, Invalidator)
//	builder.go      Builder implementation (Task 9)
//	signer.go       Ed25519 Signer (Task 5)
//	version_store.go per-tenant monotonic counter (Task 6)
//	invalidator.go  Redis pubsub fan-out (Task 7)
//	staleness.go    Harness interceptor helper (Task 13)
//
// The package takes no runtime dependencies on concrete daemon internals —
// all collaborators are injected through interfaces defined in interfaces.go
// so the Builder is straightforward to unit-test with mocks.
package manifest
