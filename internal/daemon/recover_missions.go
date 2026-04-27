package daemon

// recover_missions.go — Phase D cutover: per-tenant crash-recovery of running
// missions at daemon boot.
//
// Decision: at startup, enumerate tenant CRDs via the same Kubernetes dynamic
// client used by startup_migration_check.go. For each tenant whose data-plane
// is ready (verified structurally by Pool.For — a NotProvisionedError means
// skip), acquire a Conn, call conn.Missions().ListRunning(), and transition each
// running mission to paused. Failures for individual tenants are logged and
// skipped; the daemon still starts.
//
// The previous recoverRunningMissions relied on d.missionStore (a global
// RedisMissionStore) which crosses tenant boundaries. This replaces that path.

import (
	"context"
	"errors"
	"fmt"
	"os"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/datapool/admin"
	"github.com/zero-day-ai/sdk/auth"
)

// recoverRunningMissionsAcrossTenants is the Phase D replacement for the
// old recoverRunningMissions. It fans out across all provisioned tenants and
// transitions any mission runs still in "running" state to "paused", allowing
// operators to resume them after the daemon restart.
//
// When d.pool is nil (no security.key_provider configured) the recovery is a
// no-op — the daemon falls back to the legacy global-store path automatically
// because d.missionStore still holds the RedisMissionStore for other callers.
//
// When the Kubernetes API is unreachable (dev/test environments) the function
// logs a warning and returns nil without failing startup.
func (d *daemonImpl) recoverRunningMissionsAcrossTenants(ctx context.Context) error {
	if d.pool == nil {
		d.logger.Info(ctx, "recover missions: data-plane pool not configured; skipping per-tenant recovery")
		return nil
	}

	// Build a Kubernetes dynamic client to enumerate tenant CRDs.
	// This mirrors buildMigrationCheckConfig in startup_migration_check.go.
	dynClient, err := buildDynamicClient()
	if err != nil || dynClient == nil {
		d.logger.Warn(ctx, "recover missions: cannot build Kubernetes client (dev mode?); skipping",
			"error", err)
		return nil
	}

	namespace := os.Getenv("GIBSON_K8S_NAMESPACE")
	lister := admin.NewK8sTenantLister(dynClient, namespace)

	tenants, err := lister.ListTenants(ctx)
	if err != nil {
		d.logger.Warn(ctx, "recover missions: cannot list tenants from CRD; skipping",
			"error", err)
		return nil
	}

	if len(tenants) == 0 {
		d.logger.Info(ctx, "recover missions: no provisioned tenants found; nothing to recover")
		return nil
	}

	d.logger.Info(ctx, "recover missions: scanning tenants for running missions",
		"tenant_count", len(tenants))

	var totalRecovered int
	for _, tenant := range tenants {
		recovered, err := d.recoverTenantMissions(ctx, tenant)
		if err != nil {
			d.logger.Warn(ctx, "recover missions: partial recovery failure — continuing",
				"tenant", tenant.String(),
				"error", err)
			continue
		}
		totalRecovered += recovered
	}

	d.logger.Info(ctx, "recover missions: complete",
		"total_recovered", totalRecovered,
		"tenants_scanned", len(tenants))
	return nil
}

// recoverTenantMissions acquires a Conn for tenant, calls ListRunning, and
// updates each running mission-run to "paused". Returns the number of runs
// transitioned and any error encountered. A NotProvisionedError means the
// tenant's data-plane is not ready yet; this is not an error — we return 0, nil.
func (d *daemonImpl) recoverTenantMissions(ctx context.Context, tenant auth.TenantID) (int, error) {
	conn, err := d.pool.For(ctx, tenant)
	if err != nil {
		var npErr *datapool.NotProvisionedError
		if errors.As(err, &npErr) {
			// Tenant CRD exists but data-plane provisioning is not complete.
			// This is expected during a partial rollout — skip silently.
			return 0, nil
		}
		return 0, fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	if conn.Redis == nil {
		// Redis not configured for this conn; cannot recover mission runs.
		return 0, nil
	}

	running, err := conn.Missions().ListRunning(ctx)
	if err != nil {
		return 0, fmt.Errorf("list running: %w", err)
	}

	if len(running) == 0 {
		return 0, nil
	}

	recovered := 0
	for _, rm := range running {
		d.logger.Warn(ctx, "recover missions: pausing mission run after daemon restart",
			"tenant", tenant.String(),
			"mission_id", rm.MissionID,
			"mission_name", rm.MissionName,
			"run_id", rm.RunID,
		)
		// Update the run document status field directly via Redis JSON.
		// We use a JSON.SET patch to flip only the status so we don't have to
		// deserialize and re-marshal the full document.
		key := fmt.Sprintf("gibson:mission_run:%s", rm.RunID)
		if err := conn.Redis.Do(ctx, "JSON.SET", key, "$.status", `"paused"`).Err(); err != nil {
			d.logger.Error(ctx, "recover missions: failed to pause mission run",
				"tenant", tenant.String(),
				"run_id", rm.RunID,
				"error", err)
			continue
		}
		recovered++
	}

	return recovered, nil
}

// buildDynamicClient constructs a Kubernetes dynamic client from the in-cluster
// config or the KUBECONFIG env var. Returns nil, nil when neither is available
// (dev environments without a cluster).
func buildDynamicClient() (dynamic.Interface, error) {
	var cfg *rest.Config
	var err error

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		// Not an error condition — the daemon may run without a cluster in dev.
		return nil, nil //nolint:nilerr
	}

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	return client, nil
}
