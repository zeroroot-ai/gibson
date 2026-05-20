//go:build e2e
// +build e2e

// Package helpers — mock_llm_client.go
//
// Configures the mock-LLM provider via the daemon's admin gRPC RPC surface
// (CreateProvider / SetDefaultProvider / DeleteProvider). The daemon-side mock
// provider lives in tests/e2e/fixtures/providers/mock-llm/provider.go (Task 10)
// and is only compiled into the daemon binary when built with -tags=test_fixtures
// AND the daemon env var GIBSON_TEST_FIXTURES_ENABLED=true is set.
//
// This helper is the test-side client that registers / de-registers the mock
// provider through the daemon's normal configuration path — it does NOT interact
// with the mock provider directly.
//
// Security: credential values are NEVER logged. The mock provider uses a
// well-known non-secret token ("mock-test-token") that is meaningless outside
// the test environment.
//
// Design Component 6 / Requirements: R3.1, R3.2, R3.3, R4.3.
package helpers

import (
	"context"
	"fmt"

	tenantv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/tenant/v1"
)

const (
	// MockProviderName is the tenant-scoped name used for the mock-llm provider.
	// Must not conflict with any real provider name.
	MockProviderName = "mock-llm-e2e-test"

	// MockProviderType is the daemon provider type key for the mock.
	// The daemon recognizes "mock" when built with -tags=test_fixtures.
	MockProviderType = "mock"

	// MockProviderDefaultModel is the model name returned by the mock.
	MockProviderDefaultModel = "mock-model"

	// MockProviderDeterministicResponse is the response returned by the mock
	// provider for normal (non-error-injected) calls. The probe agent embeds
	// this string in its finding evidence field (R3.3 assertion).
	MockProviderDeterministicResponse = "MOCK_LLM_DETERMINISTIC_RESPONSE_v1"

	// MockProviderErrorResponse triggers the error path in the mock provider
	// (R4.3: LLM error injection). Set via the "inject_error" credential key.
	MockProviderErrorMode = "error_injection_mode"

	// MockProviderSlowMode adds a 10s artificial delay, used for the
	// deadline-exceeded negative test (R4.4).
	MockProviderSlowMode = "slow_mode"
)

// RegisterMockProvider registers the mock-LLM provider with the daemon via the
// CreateProvider admin RPC, then sets it as the tenant's default provider.
//
// The daemon must be built with -tags=test_fixtures AND have
// GIBSON_TEST_FIXTURES_ENABLED=true in its environment for the mock type to
// be accepted. If the build tag is missing, CreateProvider returns an error
// ("unknown provider type") which this function propagates.
//
// Security: the mock token is a fixed test-only string — never log it.
//
// Requirements: R3.1, R3.2.
func RegisterMockProvider(ctx context.Context, adminClient tenantv1.TenantAdminServiceClient) error {
	resp, err := adminClient.CreateProvider(ctx, &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:         MockProviderName,
			Type:         MockProviderType,
			DefaultModel: MockProviderDefaultModel,
			Credentials: map[string]string{
				// The mock provider accepts any value here; the daemon encrypts it.
				// We use a fixed test-only string (not a real secret).
				"api_key":           "mock-test-token-e2e-only",
				"deterministic_key": MockProviderDeterministicResponse,
			},
			SetAsDefault: true, // make the mock the default for this tenant
		},
	})
	if err != nil {
		return fmt.Errorf(
			"mock_llm_client: RegisterMockProvider: CreateProvider RPC failed: %w "+
				"(hint: verify daemon was built with -tags=test_fixtures AND "+
				"GIBSON_TEST_FIXTURES_ENABLED=true is set in the daemon's environment; "+
				"see NFR Security in mission-run-e2e-tdd/requirements.md)",
			err,
		)
	}
	_ = resp
	return nil
}

// InjectErrorMode reconfigures the mock provider to return errors on all LLM
// calls. Used by the R4.3 negative test (LLM error → mission fails cleanly).
//
// Updates the provider via UpdateProvider RPC with the "inject_error" credential.
//
// Requirements: R4.3.
func InjectErrorMode(ctx context.Context, adminClient tenantv1.TenantAdminServiceClient) error {
	_, err := adminClient.UpdateProvider(ctx, &tenantv1.UpdateProviderRequest{
		Name: MockProviderName,
		Input: &tenantv1.ProviderConfigInput{
			Name:         MockProviderName,
			Type:         MockProviderType,
			DefaultModel: MockProviderDefaultModel,
			Credentials: map[string]string{
				"api_key":      "mock-test-token-e2e-only",
				"inject_error": "true",
			},
			SetAsDefault: true,
		},
	})
	if err != nil {
		return fmt.Errorf("mock_llm_client: InjectErrorMode: UpdateProvider failed: %w", err)
	}
	return nil
}

// InjectSlowMode reconfigures the mock provider to add a 10s delay on each
// LLM call. Used by the R4.4 deadline-exceeded negative test.
//
// Requirements: R4.4.
func InjectSlowMode(ctx context.Context, adminClient tenantv1.TenantAdminServiceClient) error {
	_, err := adminClient.UpdateProvider(ctx, &tenantv1.UpdateProviderRequest{
		Name: MockProviderName,
		Input: &tenantv1.ProviderConfigInput{
			Name:         MockProviderName,
			Type:         MockProviderType,
			DefaultModel: MockProviderDefaultModel,
			Credentials: map[string]string{
				"api_key":      "mock-test-token-e2e-only",
				MockProviderSlowMode: "10000", // 10s delay in milliseconds
			},
			SetAsDefault: true,
		},
	})
	if err != nil {
		return fmt.Errorf("mock_llm_client: InjectSlowMode: UpdateProvider failed: %w", err)
	}
	return nil
}

// ResetMockProvider resets the mock provider to normal (deterministic) mode.
// Removes any error or slow-mode injection. Idempotent.
//
// Requirements: R3.2 (deterministic responses).
func ResetMockProvider(ctx context.Context, adminClient tenantv1.TenantAdminServiceClient) error {
	_, err := adminClient.UpdateProvider(ctx, &tenantv1.UpdateProviderRequest{
		Name: MockProviderName,
		Input: &tenantv1.ProviderConfigInput{
			Name:         MockProviderName,
			Type:         MockProviderType,
			DefaultModel: MockProviderDefaultModel,
			Credentials: map[string]string{
				"api_key":           "mock-test-token-e2e-only",
				"deterministic_key": MockProviderDeterministicResponse,
				// Absent inject_error / slow_mode → normal mode.
			},
			SetAsDefault: true,
		},
	})
	if err != nil {
		return fmt.Errorf("mock_llm_client: ResetMockProvider: UpdateProvider failed: %w", err)
	}
	return nil
}

// UnregisterMockProvider removes the mock-LLM provider from the tenant's
// provider store via the DeleteProvider admin RPC.
//
// Idempotent: if the provider was already deleted, the error is logged but not
// returned (tolerates NotFound).
//
// Requirements: R3.1.
func UnregisterMockProvider(ctx context.Context, adminClient tenantv1.TenantAdminServiceClient) error {
	_, err := adminClient.DeleteProvider(ctx, &tenantv1.DeleteProviderRequest{
		Name: MockProviderName,
	})
	if err != nil {
		// Treat as non-fatal — the provider may already be gone.
		return fmt.Errorf("mock_llm_client: UnregisterMockProvider: DeleteProvider failed: %w "+
			"(non-fatal — provider may already be deleted)", err)
	}
	return nil
}
