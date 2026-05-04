package datapool

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
)

// buildFakeClient builds a fake dynamic client with the given Tenant objects.
func buildFakeClient(t *testing.T, tenants ...*unstructured.Unstructured) dynamic.Interface {
	t.Helper()
	scheme := runtime.NewScheme()
	// Register the Tenant GVR with the fake client.
	gvk := schema.GroupVersionKind{
		Group:   tenantGVR.Group,
		Version: tenantGVR.Version,
		Kind:    "Tenant",
	}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	listGVK := schema.GroupVersionKind{
		Group:   tenantGVR.Group,
		Version: tenantGVR.Version,
		Kind:    "TenantList",
	}
	scheme.AddKnownTypeWithName(listGVK, &unstructured.UnstructuredList{})

	objects := make([]runtime.Object, len(tenants))
	for i, t := range tenants {
		objects[i] = t
	}
	return fake.NewSimpleDynamicClient(scheme, objects...)
}

// makeTenant creates an unstructured Tenant object with the given status.
func makeTenant(name string, dataPlaneReady bool) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "gibson.zero-day.ai/v1alpha1",
		"kind":       "Tenant",
		"metadata": map[string]any{
			"name": name,
		},
		"status": map[string]any{
			"dataPlane": map[string]any{
				"ready": dataPlaneReady,
			},
		},
	}
	raw, _ := json.Marshal(obj)
	var u unstructured.Unstructured
	_ = json.Unmarshal(raw, &u)
	return &u
}

func TestProvisioningChecker_CacheHit_Ready(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	checker := &provisioningChecker{
		cache:    make(map[auth.TenantID]provisioningState),
		cacheTTL: 5 * time.Minute,
	}
	// Pre-populate cache with a ready state.
	checker.cache[tenant] = provisioningState{
		ready:     true,
		fetchedAt: time.Now(),
	}

	ok, err := checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestProvisioningChecker_CacheHit_NotReady(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	checker := &provisioningChecker{
		cache:    make(map[auth.TenantID]provisioningState),
		cacheTTL: 5 * time.Minute,
	}
	checker.cache[tenant] = provisioningState{
		ready:     false,
		fetchedAt: time.Now(),
	}

	_, err := checker.isProvisioned(context.Background(), tenant)
	require.Error(t, err)
	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Equal(t, "acme", npErr.Tenant)
}

func TestProvisioningChecker_CacheMiss_FetchReady(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	obj := makeTenant("acme", true)
	client := buildFakeClient(t, obj)

	checker := newProvisioningChecker(client, 5*time.Minute)

	ok, err := checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestProvisioningChecker_CacheMiss_FetchNotReady(t *testing.T) {
	tenant := auth.MustNewTenantID("notready")
	obj := makeTenant("notready", false)
	client := buildFakeClient(t, obj)

	checker := newProvisioningChecker(client, 5*time.Minute)

	_, err := checker.isProvisioned(context.Background(), tenant)
	require.Error(t, err)
	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
}

func TestProvisioningChecker_TenantNotFound(t *testing.T) {
	tenant := auth.MustNewTenantID("ghost")
	client := buildFakeClient(t) // no tenants

	checker := newProvisioningChecker(client, 5*time.Minute)

	_, err := checker.isProvisioned(context.Background(), tenant)
	require.Error(t, err)
	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Equal(t, "ghost", npErr.Tenant)
}

func TestProvisioningChecker_NilClient_FailsClosed(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	checker := newProvisioningChecker(nil, 5*time.Minute)

	_, err := checker.isProvisioned(context.Background(), tenant)
	require.Error(t, err)
	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Contains(t, npErr.Reason, "no Kubernetes client")
}

func TestProvisioningChecker_StaleCacheRefetches(t *testing.T) {
	tenant := auth.MustNewTenantID("refresh")
	obj := makeTenant("refresh", true)
	client := buildFakeClient(t, obj)

	checker := newProvisioningChecker(client, 1*time.Nanosecond)

	// Seed cache with stale not-ready entry.
	checker.mu.Lock()
	checker.cache[tenant] = provisioningState{
		ready:     false,
		fetchedAt: time.Now().Add(-1 * time.Hour), // stale
	}
	checker.mu.Unlock()

	// Should re-fetch from API and find it ready.
	ok, err := checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestProvisioningChecker_Invalidate(t *testing.T) {
	tenant := auth.MustNewTenantID("inv")
	obj := makeTenant("inv", true)
	client := buildFakeClient(t, obj)

	checker := newProvisioningChecker(client, 5*time.Minute)

	// Populate cache with stale not-ready.
	checker.mu.Lock()
	checker.cache[tenant] = provisioningState{ready: false, fetchedAt: time.Now()}
	checker.mu.Unlock()

	checker.Invalidate(tenant)

	// After invalidation, should fetch fresh from API.
	ok, err := checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestProvisioningChecker_MissingDataPlanField verifies that a Tenant with
// no status.dataPlane field (pre-Phase F) is treated as not provisioned.
func TestProvisioningChecker_MissingDataPlaneField(t *testing.T) {
	tenant := auth.MustNewTenantID("nophase")
	// Build a Tenant without dataPlane in status.
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "gibson.zero-day.ai/v1alpha1",
			"kind":       "Tenant",
			"metadata":   map[string]any{"name": "nophase"},
			"status":     map[string]any{"phase": "Ready"},
		},
	}

	_ = errors.NewNotFound(schema.GroupResource{}, "")

	client := buildFakeClient(t, obj)
	checker := newProvisioningChecker(client, 5*time.Minute)

	_, err := checker.isProvisioned(context.Background(), tenant)
	require.Error(t, err)
	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Contains(t, npErr.Reason, "absent")
}
