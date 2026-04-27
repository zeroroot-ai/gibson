package admin

import (
	"context"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/sdk/auth"
)

// ErrStopIteration is the sentinel error returned by a ForEachTenant callback
// to signal that iteration should halt immediately. It is not treated as a
// failure — ForEachTenant returns nil when this is the only "error" received.
var ErrStopIteration = errors.New("admin: stop iteration")

// tenantGVR is the GroupVersionResource for the Tenant CRD.
var tenantGVR = schema.GroupVersionResource{
	Group:    "gibson.io",
	Version:  "v1alpha1",
	Resource: "tenants",
}

// TenantLister abstracts the source of tenant IDs for ForEachTenant.
// In production, a k8sLister backed by a Kubernetes dynamic client is used.
// In tests, a fake implementation is injected.
type TenantLister interface {
	// ListTenants returns the IDs of all known tenants. The returned slice
	// may be empty when no tenants exist; the caller iterates it as-is.
	ListTenants(ctx context.Context) ([]auth.TenantID, error)
}

// k8sLister is the production TenantLister that reads the Tenant CRD list
// from the Kubernetes API server using the same GVR as provisioning_check.go.
type k8sLister struct {
	client    dynamic.Interface
	namespace string
}

// NewK8sTenantLister creates a TenantLister backed by the Kubernetes dynamic
// client. namespace may be empty for cluster-scoped resources.
func NewK8sTenantLister(client dynamic.Interface, namespace string) TenantLister {
	return &k8sLister{client: client, namespace: namespace}
}

func (l *k8sLister) ListTenants(ctx context.Context) ([]auth.TenantID, error) {
	var resource dynamic.ResourceInterface
	if l.namespace != "" {
		resource = l.client.Resource(tenantGVR).Namespace(l.namespace)
	} else {
		resource = l.client.Resource(tenantGVR)
	}

	list, err := resource.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("admin: ListTenants: %w", err)
	}

	tenants := make([]auth.TenantID, 0, len(list.Items))
	for _, item := range list.Items {
		meta, ok := item.Object["metadata"].(map[string]any)
		if !ok {
			continue
		}
		tenantStr, ok := meta["name"].(string)
		if !ok || tenantStr == "" {
			continue
		}
		tid, err := auth.NewTenantID(tenantStr)
		if err != nil {
			// Skip tenants with invalid IDs rather than aborting the list.
			continue
		}
		tenants = append(tenants, tid)
	}
	return tenants, nil
}

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
func ForEachTenant(
	ctx context.Context,
	adminConn *datapool.AdminConn,
	lister TenantLister,
	tenantPool datapool.Pool,
	fn func(tenant auth.TenantID, conn *datapool.Conn) error,
) error {
	if adminConn == nil {
		return fmt.Errorf("admin: ForEachTenant: adminConn must not be nil")
	}

	tenants, err := lister.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("admin: ForEachTenant: listing tenants: %w", err)
	}

	var errs []error
	for _, tenant := range tenants {
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
