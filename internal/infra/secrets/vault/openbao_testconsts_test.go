//go:build openbao_smoke || openbao_integration

// Package vault — openbao_testconsts_test.go
//
// Shared test constants for the OpenBao smoke (slice 2 / sdk#89) +
// integration (slice 3 / sdk#90) suites. Guarded by the union of both
// build tags so the unused linter does not flag them outside those suites.
//
// File name ends in `_test.go` so it's compiled only with the test
// binary, never with `go build` of the package's production source.
package vault

const (
	// openbaoImage is the pinned OpenBao container image used for the
	// smoke + compat suites. Pinned to a specific 2.5.x release —
	// NOT `latest`. Bump deliberately when picking up upstream
	// security fixes; the version assertion in openbao_smoke_test.go
	// catches accidental drift.
	openbaoImage = "openbao/openbao:2.5.3" //nolint:unused // referenced only by build-tag-gated test files

	// openbaoExpectedVersion is the version string OpenBao reports at
	// /v1/sys/health. Matches the image tag's semver, sans the leading
	// "v". Asserted in TestOpenBaoSmoke_Health to catch drift between
	// the image pin and the running binary.
	openbaoExpectedVersion = "2.5.3" //nolint:unused // referenced only by build-tag-gated test files

	// openbaoDevRootToken is the fixed root token used by OpenBao's
	// dev-mode server. Mirrors the devRootToken pattern from the
	// existing Vault integration_test.go so the same scaffolding
	// pattern works against either backend.
	openbaoDevRootToken = "dev-root-token" //nolint:gosec,unused // test-only dev token; not a real credential; referenced only by build-tag-gated test files

	// openbaoTestMount is the KV v2 mount path enabled by default in
	// OpenBao's dev mode. Distinct from integration_test.go's
	// intTestMount (which is tagged `integration`, not visible under
	// `openbao_integration`) to keep the build-tag-isolated test
	// trees self-contained.
	openbaoTestMount = "secret" //nolint:unused // referenced only by build-tag-gated test files

	// openbaoTestTenantID is the test tenant ID used by the compat
	// suite's per-tenant policy. Mirrors intTestTenantID's role
	// without depending on it cross-build-tag.
	openbaoTestTenantID = "openbao-test" //nolint:unused // referenced only by build-tag-gated test files
)
