package auth

import (
	"context"
	"fmt"
)

// tenantValidator is the package-level tenant validator used by auth interceptors.
// It is set during daemon initialization via SetTenantValidator and must be
// configured before the gRPC server starts accepting requests.
var tenantValidator *CachedTenantValidator

// SetTenantValidator configures the tenant validator used by auth interceptors.
//
// Must be called before the gRPC server starts accepting requests. Calling it
// after the server is running is safe from a concurrency standpoint — the
// package-level variable is written once at startup — but any in-flight
// requests that started before the call will not be subject to validation.
func SetTenantValidator(v *CachedTenantValidator) {
	tenantValidator = v
}

// validateTenantAccess checks whether the extracted tenant is accessible.
//
// It consults the package-level tenantValidator (set via SetTenantValidator).
// If no validator has been configured, or if tenantID is empty, validation is
// skipped and nil is returned so that deployments without tenant validation are
// unaffected.
//
// Returns a non-nil error when:
//   - The tenant is not found in the backing store.
//   - The tenant status is not accessible (e.g., "deleted").
//
// The error text is intentionally vague for security — callers should map it
// to a gRPC PermissionDenied or NotFound status as appropriate.
func validateTenantAccess(ctx context.Context, tenantID string) error {
	if tenantValidator == nil || tenantID == "" {
		return nil
	}

	tenantStatus, err := tenantValidator.ValidateTenantStatus(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("tenant %q not found", tenantID)
	}

	if !IsTenantAccessible(tenantStatus) {
		return fmt.Errorf("tenant %q is %s", tenantID, tenantStatus)
	}

	return nil
}
