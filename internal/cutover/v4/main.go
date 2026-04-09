// Package cutoverv4 implements the v4.0 clean-slate cutover that wipes tenant
// Neo4j graph data and flushes Redis mission state as part of the v4.0 schema
// cut-over.  The Redis Streams audit log is explicitly preserved.
//
// The cutover is idempotent: a sentinel key (tenant:{id}:cutover:v4:done)
// prevents double-wipes. Failure on one tenant does NOT halt other tenants.
package cutoverv4

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
)

const (
	// sentinelKeySuffix is appended to "tenant:{id}:" to form the idempotency key.
	sentinelKeySuffix = "cutover:v4:done"

	// sentinelTTL is how long we keep the sentinel key. Set to a large value so
	// operators can inspect it, but it does not accumulate indefinitely.
	sentinelTTL = 365 * 24 * time.Hour

	// batchNodeThreshold is the node count above which we switch to batched
	// Cypher deletions to avoid transaction-size limits in Neo4j.
	batchNodeThreshold = 100_000
)

// Config holds all runtime inputs for the cutover orchestration.
// Connections are injected by the caller so the orchestrator does not create
// any new connections (which would violate the constraint of reusing existing
// daemon client paths).
type Config struct {
	// TenantID targets a single tenant. Empty string means "all tenants".
	TenantID string

	// Tenants is an explicit list of tenant IDs to process when TenantID is
	// empty. If both are empty, Run returns an error.
	Tenants []string

	// Confirm must be true; the cobra layer enforces this before calling Run,
	// but we re-check here for library-level safety.
	Confirm bool

	// Yes skips the per-tenant interactive confirmation prompt.
	Yes bool

	// DryRun prints what would happen without mutating any data.
	DryRun bool

	// Logger is the slog logger. Required.
	Logger *slog.Logger

	// RedisClient is an open, connected Redis client. Required.
	RedisClient redis.UniversalClient

	// GraphClient is an open, connected Neo4j graph client. Required.
	GraphClient graph.GraphClient
}

// Summary reports the aggregate outcome of the cutover run.
type Summary struct {
	TenantsWiped   int
	TenantsSkipped int
	TenantsFailed  int
}

// Run executes the cutover against all tenants nominated in cfg.
// It returns a non-nil error only for configuration failures; per-tenant
// failures are recorded in the summary log rather than returned as errors,
// to ensure all tenants are attempted.
func Run(ctx context.Context, cfg Config) error {
	if !cfg.Confirm {
		return fmt.Errorf("cutover refused: Confirm flag is false — pass --confirm to run")
	}
	if cfg.Logger == nil {
		return fmt.Errorf("cutover refused: Logger is required")
	}
	if cfg.RedisClient == nil {
		return fmt.Errorf("cutover refused: RedisClient is required")
	}
	if cfg.GraphClient == nil {
		return fmt.Errorf("cutover refused: GraphClient is required")
	}

	log := cfg.Logger

	tenants, err := resolveTenants(cfg)
	if err != nil {
		return err
	}

	if cfg.DryRun {
		log.Info("cutover-v4 DRY RUN — no data will be modified",
			"tenant_count", len(tenants),
		)
	} else {
		log.Info("cutover-v4 starting",
			"tenant_count", len(tenants),
			"dry_run", false,
		)
	}

	var summary Summary

	for _, tenantID := range tenants {
		tid := tenantID // capture loop variable

		select {
		case <-ctx.Done():
			log.Warn("cutover-v4 context cancelled; stopping early",
				"tenants_remaining", len(tenants)-summary.TenantsWiped-summary.TenantsSkipped-summary.TenantsFailed,
			)
			break
		default:
		}

		logTenant := log.With("tenant_id", tid)

		// --- Idempotency check ---
		sentinelKey := fmt.Sprintf("tenant:%s:%s", tid, sentinelKeySuffix)
		existing, err := cfg.RedisClient.Get(ctx, sentinelKey).Result()
		if err == nil && existing != "" {
			logTenant.Info("cutover-v4 skipping tenant (sentinel key present)",
				"sentinel_key", sentinelKey,
				"sentinel_value", existing,
			)
			summary.TenantsSkipped++
			continue
		}
		if err != nil && err != redis.Nil {
			logTenant.Error("cutover-v4 failed to check sentinel key; skipping tenant",
				"sentinel_key", sentinelKey,
				"error", err,
			)
			summary.TenantsFailed++
			continue
		}

		// --- Dry run: report and continue ---
		if cfg.DryRun {
			logTenant.Info("cutover-v4 [dry-run] would wipe tenant",
				"neo4j_operation", fmt.Sprintf("MATCH (n) WHERE n.tenant_id = '%s' DETACH DELETE n", tid),
				"redis_patterns", []string{
					fmt.Sprintf("tenant:%s:mission:*", tid),
					fmt.Sprintf("tenant:%s:run:*", tid),
					fmt.Sprintf("tenant:%s:agent:*", tid),
				},
				"preserved", fmt.Sprintf("tenant:%s:audit:log", tid),
			)
			continue
		}

		// --- Interactive confirmation (if not --yes) ---
		if !cfg.Yes {
			if !interactiveConfirmTenant(tid) {
				logTenant.Info("cutover-v4 operator declined tenant; skipping")
				summary.TenantsSkipped++
				continue
			}
		}

		// --- Execute wipe ---
		if err := processTenant(ctx, tid, cfg, logTenant); err != nil {
			logTenant.Error("cutover-v4 tenant failed",
				"error", err,
			)
			summary.TenantsFailed++
			continue
		}

		// --- Set sentinel key ---
		ts := time.Now().UTC().Format(time.RFC3339)
		if setErr := cfg.RedisClient.Set(ctx, sentinelKey, ts, sentinelTTL).Err(); setErr != nil {
			// Log but do NOT count this as a tenant failure — the wipe itself succeeded.
			logTenant.Warn("cutover-v4 wipe succeeded but failed to set sentinel key; re-run will re-wipe",
				"sentinel_key", sentinelKey,
				"error", setErr,
			)
		} else {
			logTenant.Info("cutover-v4 sentinel key set",
				"sentinel_key", sentinelKey,
				"value", ts,
			)
		}

		logTenant.Info("cutover-v4 tenant complete")
		summary.TenantsWiped++
	}

	// --- Summary ---
	log.Info("cutover-v4 complete",
		"tenants_wiped", summary.TenantsWiped,
		"tenants_skipped", summary.TenantsSkipped,
		"tenants_failed", summary.TenantsFailed,
		"dry_run", cfg.DryRun,
	)

	if summary.TenantsFailed > 0 {
		return fmt.Errorf("cutover-v4 finished with %d failed tenant(s); check logs", summary.TenantsFailed)
	}

	return nil
}

// processTenant wipes the Neo4j graph and flushes Redis state for one tenant.
// Returns an error if either operation fails.
func processTenant(ctx context.Context, tenantID string, cfg Config, log *slog.Logger) error {
	// Neo4j wipe
	nodesDeleted, err := WipeTenantGraph(ctx, cfg.GraphClient, tenantID)
	if err != nil {
		return fmt.Errorf("neo4j wipe: %w", err)
	}
	log.Info("cutover-v4 neo4j graph wiped",
		"nodes_deleted", nodesDeleted,
	)

	// Redis flush
	keysDeleted, err := FlushTenantState(ctx, cfg.RedisClient, tenantID)
	if err != nil {
		return fmt.Errorf("redis flush: %w", err)
	}
	log.Info("cutover-v4 redis state flushed",
		"keys_deleted", keysDeleted,
	)

	return nil
}

// resolveTenants returns the ordered list of tenant IDs to process.
func resolveTenants(cfg Config) ([]string, error) {
	if cfg.TenantID != "" {
		return []string{cfg.TenantID}, nil
	}
	if len(cfg.Tenants) > 0 {
		return cfg.Tenants, nil
	}
	return nil, fmt.Errorf(
		"cutover refused: provide --tenant-id for a single tenant or populate Config.Tenants " +
			"for multi-tenant operation",
	)
}

// interactiveConfirmTenant asks the operator to confirm wiping a specific tenant.
// Returns true only when the operator types "yes".
func interactiveConfirmTenant(tenantID string) bool {
	fmt.Fprintf(os.Stdout, "Wipe tenant %q? Type \"yes\" to confirm: ", tenantID)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()) == "yes"
	}
	return false
}
