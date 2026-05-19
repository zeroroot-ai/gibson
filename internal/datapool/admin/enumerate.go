package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/sdk/auth"
)

// ErrStopIteration is the sentinel error returned by a ForEachTenant callback
// to signal that iteration should halt immediately. It is not treated as a
// failure — ForEachTenant returns nil when this is the only "error" received.
var ErrStopIteration = errors.New("admin: stop iteration")

// ForEachTenant enumerates all tenant IDs from lister, acquires a per-tenant
// Conn for each via tenantPool, and calls fn with the tenant ID and its Conn.
// The Conn is released after fn returns.
//
// adminConn must be a non-released AdminConn obtained via AdminPool.Acquire;
// its subject and method are used for audit context. The conn fields
// (AdminPostgres, AdminRedis, etc.) are available to fn if needed, though
// fn typically operates on the per-tenant tc *datapool.Conn.
//
// Error semantics:
//   - If fn returns ErrStopIteration, ForEachTenant stops immediately and
//     returns nil (not an error).
//   - All other non-nil errors from fn are accumulated; iteration continues to
//     the next tenant.
//   - If listing tenants fails, the error is returned immediately.
//
// ForEachTenant is safe to call concurrently from separate goroutines; each
// call manages its own per-tenant Conn lifecycles independently.
//
// The Lister source (Kubernetes Tenant CRDs in production, fakes in tests)
// is intentionally injected so the admin pool stays loosely coupled to the
// tenant-enumeration concern. See internal/tenants for the canonical
// production implementation.
func ForEachTenant(
	ctx context.Context,
	adminConn *datapool.AdminConn,
	lister Lister,
	tenantPool datapool.Pool,
	fn func(tenant auth.TenantID, conn *datapool.Conn) error,
) error {
	if adminConn == nil {
		return fmt.Errorf("admin: ForEachTenant: adminConn must not be nil")
	}

	tenantList, err := lister.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("admin: ForEachTenant: listing tenants: %w", err)
	}

	var errs []error
	for _, tenant := range tenantList {
		// Check for context cancellation between tenants.
		select {
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
			return joinErrors(errs)
		default:
		}

		conn, err := tenantPool.For(ctx, tenant)
		if err != nil {
			// A NotProvisionedError means the tenant's data-plane is still
			// being set up; include it in the error accumulation and continue.
			errs = append(errs, fmt.Errorf("tenant %s: acquire: %w", tenant, err))
			continue
		}

		fnErr := fn(tenant, conn)
		conn.Release()

		if errors.Is(fnErr, ErrStopIteration) {
			return joinErrors(errs)
		}
		if fnErr != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tenant, fnErr))
		}
	}

	return joinErrors(errs)
}

// joinErrors returns nil when errs is empty, the single error when len==1,
// or a combined error wrapping all errors for multiple.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return fmt.Errorf("%d errors during ForEachTenant: %w", len(errs), errors.Join(errs...))
}
