package admin

// lister.go — relocated from internal/tenants/ per ADR-0023.
//
// Tenant enumeration via the Kubernetes API server is an administrative
// concern and lives behind the gibsoncheck `adminpoolacquire` import
// restriction. Daemon hot-path code cannot reach it; only admin and
// migration call sites can.
//
// The K8sLister filters tenants whose metadata.deletionTimestamp is set
// — those are mid-teardown and consumers (mission recovery, migration
// check) should not act on them. The 2026-05-19 testa123 incident bit
// the previous mission-recovery loop precisely because the lister
// returned a tenant whose finalizer was stuck.

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/zeroroot-ai/sdk/auth"
)

// tenantGVR is the GroupVersionResource for the Tenant CRD.
var tenantGVR = schema.GroupVersionResource{
	Group:    "gibson.zeroroot.ai",
	Version:  "v1alpha1",
	Resource: "tenants",
}

// Lister abstracts the source of tenant IDs. In production, a K8s-backed
// lister is used; tests inject fakes.
type Lister interface {
	// ListTenants returns the IDs of all known tenants whose data plane
	// is in scope for admin work — i.e. tenants whose Kubernetes Tenant
	// CRD exists and does NOT have a deletionTimestamp set. Tenants in
	// the middle of teardown are excluded; callers that genuinely want
	// to act on dying tenants should use a future ListAllIncludingDying
	// method instead.
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
//
// NOTE: this constructor MUST NOT be invoked from daemon hot-path code.
// The gibsoncheck `adminpoolacquire` rule restricts imports of this
// package to `internal/server/admin/`, `internal/infra/datapool/admin/`,
// `internal/migrate/`, and `cmd/gibson-migrate/`. See ADR-0023 for the
// underlying decision.
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
		return nil, fmt.Errorf("admin: ListTenants: %w", err)
	}

	out := make([]auth.TenantID, 0, len(list.Items))
	for _, item := range list.Items {
		meta, ok := item.Object["metadata"].(map[string]any)
		if !ok {
			continue
		}
		// Skip tenants mid-teardown: a non-empty deletionTimestamp means
		// the controller is winding down this tenant; admin / migration
		// work should not run against it.
		if deletionTs, hasDeletion := meta["deletionTimestamp"].(string); hasDeletion && deletionTs != "" {
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
