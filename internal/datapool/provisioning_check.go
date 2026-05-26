package datapool

import (
	"context"
	"sync"
	"time"

	dpmetrics "github.com/zeroroot-ai/gibson/internal/datapool/metrics"
	"github.com/zeroroot-ai/sdk/auth"
)

// provisioningState caches the last-known provisioning status for a tenant.
//
// The cache distinguishes the negative cases so callers see the same typed
// error on a cache hit as they would on a cache miss:
//   - brokerMissing: tenant_secrets_broker_config row absent → NotProvisionedError
//   - dbMissing:     broker row present but per-tenant DB absent → DataPlaneUnreachableError
//   - ready:         both probes positive
type provisioningState struct {
	ready         bool
	brokerMissing bool
	dbMissing     bool
	fetchedAt     time.Time
}

// provisioningChecker verifies whether a tenant's data-plane has been
// provisioned by the tenant-operator before Pool.For returns a Conn.
//
// It consults a DataPlaneProbe (broker_config row existence + per-tenant
// database existence) rather than the Kubernetes Tenant CRD. This is
// the post-ADR-0023 shape — the previous K8s-GET path made one bad Tenant
// CRD a daemon-wide outage (2026-05-19 testa123 incident).
//
// The result is cached in-process; stale entries expire after cacheTTL.
//
// Fail-closed: on persistent probe failure, isProvisioned returns a typed
// error rather than falling through to a happy path.
type provisioningChecker struct {
	mu       sync.RWMutex
	cache    map[auth.TenantID]provisioningState
	cacheTTL time.Duration
	probe    DataPlaneProbe
}

// newProvisioningChecker creates a provisioningChecker backed by the given
// DataPlaneProbe. cacheTTL controls how long a cached status is trusted
// before a re-fetch is performed. A nil probe behaves as fail-closed
// (every isProvisioned call returns NotProvisionedError) — that matches
// the previous "nil Kubernetes client" semantics in dev environments.
func newProvisioningChecker(probe DataPlaneProbe, cacheTTL time.Duration) *provisioningChecker {
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}
	return &provisioningChecker{
		cache:    make(map[auth.TenantID]provisioningState),
		cacheTTL: cacheTTL,
		probe:    probe,
	}
}

// isProvisioned returns true if the tenant's data-plane is ready. It
// checks the in-process cache first; on a miss (or stale entry) it
// invokes the probe.
//
// Fail-closed: any probe failure or negative-shaped result returns a
// typed error rather than nil/true.
func (c *provisioningChecker) isProvisioned(ctx context.Context, tenant auth.TenantID) (bool, error) {
	c.mu.RLock()
	state, hit := c.cache[tenant]
	c.mu.RUnlock()

	if hit && time.Since(state.fetchedAt) < c.cacheTTL {
		return c.resultFromState(tenant, state)
	}

	state, err := c.refresh(ctx, tenant)
	if err != nil {
		// Probe failures (e.g. platform postgres unreachable) are reported
		// as DataPlaneUnreachableError — distinct from NotProvisionedError.
		// The caller can retry; we deliberately do NOT cache the failure.
		return false, &DataPlaneUnreachableError{
			Tenant: tenant.String(),
			Reason: err.Error(),
		}
	}

	c.mu.Lock()
	c.cache[tenant] = state
	c.mu.Unlock()

	return c.resultFromState(tenant, state)
}

// refresh invokes both probe methods and returns the composite state.
// The probe itself returns booleans for the negative-case answers; only
// genuine probe failures (e.g. platform postgres unreachable) come back
// as errors.
func (c *provisioningChecker) refresh(ctx context.Context, tenant auth.TenantID) (provisioningState, error) {
	if c.probe == nil {
		return provisioningState{
			brokerMissing: true,
			fetchedAt:     time.Now(),
		}, nil
	}

	brokerOK, err := c.probe.BrokerConfigExists(ctx, tenant)
	if err != nil {
		return provisioningState{}, err
	}
	if !brokerOK {
		dpmetrics.IncProvisioningCheckFailure(dpmetrics.ReasonNotProvisioned)
		return provisioningState{
			brokerMissing: true,
			fetchedAt:     time.Now(),
		}, nil
	}

	pingOK, err := c.probe.Pingable(ctx, tenant)
	if err != nil {
		return provisioningState{}, err
	}
	if !pingOK {
		dpmetrics.IncProvisioningCheckFailure(dpmetrics.ReasonCRDUnavailable)
		return provisioningState{
			dbMissing: true,
			fetchedAt: time.Now(),
		}, nil
	}

	return provisioningState{
		ready:     true,
		fetchedAt: time.Now(),
	}, nil
}

// resultFromState translates a cached or freshly-fetched state into the
// (bool, error) return shape callers expect.
func (c *provisioningChecker) resultFromState(tenant auth.TenantID, state provisioningState) (bool, error) {
	switch {
	case state.ready:
		return true, nil
	case state.brokerMissing:
		return false, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "tenant_secrets_broker_config row absent",
		}
	case state.dbMissing:
		return false, &DataPlaneUnreachableError{
			Tenant: tenant.String(),
			Reason: "per-tenant database does not exist in cluster",
		}
	default:
		// Defensive: a zero-value state with no flags set. Treat as not provisioned.
		return false, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "indeterminate cache state",
		}
	}
}

// Invalidate removes a tenant's cached state, forcing a re-fetch on next
// isProvisioned call. Call this when a provisioning event is observed.
func (c *provisioningChecker) Invalidate(tenant auth.TenantID) {
	c.mu.Lock()
	delete(c.cache, tenant)
	c.mu.Unlock()
}
