// Package tenants provides tenant metadata enumeration utilities that are
// intentionally OUTSIDE internal/datapool/admin/.
//
// The admin pool (internal/datapool/admin/) is the cross-tenant data-plane
// gate — its import is restricted to internal/admin/, internal/datapool/admin/,
// internal/migrate/, and cmd/gibson-migrate/ per the gibsoncheck
// adminpoolacquire rule (database-per-tenant-data-plane Requirement 11.5).
//
// Tenant metadata enumeration (reading the Kubernetes Tenant CRD list) is a
// separate concern from cross-tenant data access. It does not touch any
// tenant data and so does not need the same restrictions. Callers that need
// "list me every tenant id" (e.g. the daemon's startup migration check, the
// in-flight-mission recovery loop, the gibson-migrate CLI) use this package
// instead of importing internal/datapool/admin.
package tenants

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/zero-day-ai/sdk/auth"
)

// tenantGVR is the GroupVersionResource for the Tenant CRD.
var tenantGVR = schema.GroupVersionResource{
	Group:    "gibson.zero-day.ai",
	Version:  "v1alpha1",
	Resource: "tenants",
}

// Lister abstracts the source of tenant IDs. In production, a K8s-backed
// lister is used; tests inject fakes.
type Lister interface {
	// ListTenants returns the IDs of all known tenants. The returned slice
	// may be empty when no tenants exist; the caller iterates as-is.
	ListTenants(ctx context.Context) ([]auth.TenantID, error)
}

// k8sLister is the production Lister that reads the Tenant CRD list from
// the Kubernetes API server.
type k8sLister struct {
	client    dynamic.Interface
	namespace string
}

// NewK8sLister creates a Lister backed by the Kubernetes dynamic client.
// namespace may be empty for cluster-scoped resources.
func NewK8sLister(client dynamic.Interface, namespace string) Lister {
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
		return nil, fmt.Errorf("tenants: ListTenants: %w", err)
	}

	out := make([]auth.TenantID, 0, len(list.Items))
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
		out = append(out, tid)
	}
	return out, nil
}
