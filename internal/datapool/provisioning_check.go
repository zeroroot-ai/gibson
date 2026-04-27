package datapool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	dpmetrics "github.com/zero-day-ai/gibson/internal/datapool/metrics"
	"github.com/zero-day-ai/sdk/auth"
)

// tenantGVR is the GroupVersionResource for the Tenant CRD managed by the
// tenant-operator. We use unstructured access rather than importing the
// tenant-operator module to avoid a cyclic dependency between gibson and
// github.com/zero-day-ai/gibson/tenant-operator.
var tenantGVR = schema.GroupVersionResource{
	Group:    "gibson.io",
	Version:  "v1alpha1",
	Resource: "tenants",
}

// provisioningState caches the last-known provisioning status for a tenant.
type provisioningState struct {
	ready     bool
	fetchedAt time.Time
}

// provisioningChecker verifies whether a tenant's data-plane has been
// provisioned by the tenant-operator before Pool.For returns a Conn.
//
// It uses the Kubernetes dynamic client to read the Tenant CRD's
// status.dataPlane field (to be populated by Phase F). The result is cached
// in-process; stale entries expire after cacheTTL.
//
// Fail-closed: on persistent CRD unavailability, isProvisioned returns
// NotProvisionedError rather than falling through to a happy path.
type provisioningChecker struct {
	mu       sync.RWMutex
	cache    map[auth.TenantID]provisioningState
	cacheTTL time.Duration
	client   dynamic.Interface
	// namespace is where Tenant CRDs live; empty means cluster-scoped.
	namespace string
}

// newProvisioningChecker creates a provisioningChecker backed by the given
// Kubernetes dynamic client. cacheTTL controls how long a cached status is
// trusted before a re-fetch is performed.
func newProvisioningChecker(client dynamic.Interface, cacheTTL time.Duration) *provisioningChecker {
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}
	return &provisioningChecker{
		cache:    make(map[auth.TenantID]provisioningState),
		cacheTTL: cacheTTL,
		client:   client,
	}
}

// isProvisioned returns true if the tenant's data-plane is ready. It checks
// the in-process cache first; on a miss (or stale entry) it performs a
// synchronous API call.
//
// Fail-closed: if the Tenant CRD does not exist or the API call fails, the
// method returns a NotProvisionedError rather than a nil error.
func (c *provisioningChecker) isProvisioned(ctx context.Context, tenant auth.TenantID) (bool, error) {
	// Fast path: check cache.
	c.mu.RLock()
	state, ok := c.cache[tenant]
	c.mu.RUnlock()

	if ok && time.Since(state.fetchedAt) < c.cacheTTL {
		if !state.ready {
			return false, &NotProvisionedError{
				Tenant: tenant.String(),
				Reason: "cached status: data-plane not ready",
			}
		}
		return true, nil
	}

	// Slow path: synchronous fetch from the API server.
	ready, err := c.fetchFromAPI(ctx, tenant)
	if err != nil {
		return false, err
	}

	// Update cache.
	c.mu.Lock()
	c.cache[tenant] = provisioningState{
		ready:     ready,
		fetchedAt: time.Now(),
	}
	c.mu.Unlock()

	if !ready {
		return false, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "Tenant CRD found but status.dataPlane is not ready (Phase F not yet complete)",
		}
	}
	return true, nil
}

// fetchFromAPI performs a synchronous GET of the Tenant CRD and inspects
// status.dataPlane.ready.
//
// Note: status.dataPlane is populated by Phase F of this spec. Until Phase F
// lands, the field will be absent and this method returns NotProvisionedError.
// This is intentional: "absent = not provisioned" is the safe default.
func (c *provisioningChecker) fetchFromAPI(ctx context.Context, tenant auth.TenantID) (bool, error) {
	if c.client == nil {
		// No Kubernetes client configured — behave as if not provisioned.
		// This happens in test/dev environments without a cluster.
		return false, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "no Kubernetes client configured (dev mode)",
		}
	}

	name := tenant.String()
	resource := c.client.Resource(tenantGVR)

	obj, err := resource.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			dpmetrics.IncProvisioningCheckFailure(dpmetrics.ReasonNotProvisioned)
			return false, &NotProvisionedError{
				Tenant: tenant.String(),
				Reason: fmt.Sprintf("Tenant CRD %q not found in cluster", name),
			}
		}
		// Transient API error — fail closed.
		dpmetrics.IncProvisioningCheckFailure(dpmetrics.ReasonCRDUnavailable)
		return false, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: fmt.Sprintf("Tenant CRD lookup failed: %v", err),
		}
	}

	// Navigate: .status.dataPlane.ready
	//
	// Phase F (task 6.7) adds status.dataPlane to the CRD. Until then, this
	// field is absent and we return not-provisioned.
	status, ok := obj.Object["status"].(map[string]any)
	if !ok {
		dpmetrics.IncProvisioningCheckFailure(dpmetrics.ReasonNotProvisioned)
		return false, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "Tenant CRD status field absent or wrong type",
		}
	}

	dataPlane, ok := status["dataPlane"].(map[string]any)
	if !ok {
		// Phase F has not populated the dataPlane field yet.
		dpmetrics.IncProvisioningCheckFailure(dpmetrics.ReasonNotProvisioned)
		return false, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "status.dataPlane absent (Phase F not yet deployed)",
		}
	}

	ready, _ := dataPlane["ready"].(bool)
	return ready, nil
}

// Invalidate removes a tenant's cached state, forcing a re-fetch on next
// isProvisioned call. Call this when a provisioning event is observed.
func (c *provisioningChecker) Invalidate(tenant auth.TenantID) {
	c.mu.Lock()
	delete(c.cache, tenant)
	c.mu.Unlock()
}
