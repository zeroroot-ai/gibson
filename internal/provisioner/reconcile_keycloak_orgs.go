// Package provisioner — reconcile_keycloak_orgs.go
//
// OrgReconciler runs a one-shot startup reconciliation that ensures every
// tenant with Redis membership records also has:
//   - A Keycloak Organization (created if absent).
//   - All Redis members added to that organization (idempotent).
//   - An FGA admin tuple for each member that holds an owner/admin role
//     (idempotent; Write is a no-op if the tuple already exists).
//
// This covers existing tenants that were created before the authz-02
// Keycloak Organizations feature shipped. Once the platform completes
// cutover (authz-07), the flag `provisioner.reconcile_on_startup` is
// flipped to false and this code becomes dormant.
//
// Design invariants:
//
//   - Every individual tenant's reconciliation is attempted regardless of
//     earlier failures. A single failing tenant does not abort the batch.
//   - ErrNotFound and ErrConflict from Keycloak are treated as success
//     (already exists → skip / idempotent).
//   - A Redis membership record that references a Keycloak user ID that
//     does not exist in Keycloak is logged at WARN and skipped — the
//     reconciler never creates users, only organizations.
//   - The reconciler completes in <5 s for ≤100 tenants (sequential I/O;
//     each org check is a single HTTP call).
//
// Gating:
//
//	cfg.Provisioner.ReconcileOnStartup must be true.
//	If false, ReconcileKeycloakOrgs is a no-op (returns nil immediately).
package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/config"
)

// ---------------------------------------------------------------------------
// Narrow interfaces (allows test injection without real Redis / Keycloak)
// ---------------------------------------------------------------------------

// MembershipScanner is the minimal Redis interface used by the reconciler to
// read existing membership records without importing *redis.Client directly.
//
// Callers that have a *redis.Client can wrap it with NewRedisMembershipScanner.
type MembershipScanner interface {
	// ScanMemberships returns all membership records from the Redis
	// "membership:*" key space. It returns (tenantID, userID, email, role)
	// tuples. An empty slice is a valid no-op result.
	ScanMemberships(ctx context.Context) ([]MembershipRecord, error)
}

// membershipScanner is a package-internal alias used for constructor injection.
type membershipScanner = MembershipScanner

// ---------------------------------------------------------------------------
// RedisMembershipScanner — Redis-backed MembershipScanner
// ---------------------------------------------------------------------------

// redisMembershipRecord mirrors the JSON shape of membership records in Redis.
type redisMembershipRecord struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// RedisMembershipScanner implements MembershipScanner using a standalone
// Redis client.
//
// Construct with NewRedisMembershipScanner.
type RedisMembershipScanner struct {
	client *goredis.Client
}

// NewRedisMembershipScanner constructs a RedisMembershipScanner.
// client must be non-nil.
func NewRedisMembershipScanner(client *goredis.Client) *RedisMembershipScanner {
	return &RedisMembershipScanner{client: client}
}

// ScanMemberships scans the entire "membership:*" key space and returns all
// membership records.
func (s *RedisMembershipScanner) ScanMemberships(ctx context.Context) ([]MembershipRecord, error) {
	const pattern = "membership:*"
	var records []MembershipRecord
	var cursor uint64

	for {
		keys, nextCursor, err := s.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan memberships: %w", err)
		}

		for _, key := range keys {
			data, err := s.client.Get(ctx, key).Result()
			if errors.Is(err, goredis.Nil) {
				continue // key evicted between SCAN and GET
			}
			if err != nil {
				return nil, fmt.Errorf("get membership key %q: %w", key, err)
			}

			var rec redisMembershipRecord
			if err := json.Unmarshal([]byte(data), &rec); err != nil {
				// Skip unparseable records — log but continue.
				continue
			}
			records = append(records, MembershipRecord{
				TenantID: rec.TenantID,
				UserID:   rec.UserID,
				Email:    rec.Email,
				Role:     rec.Role,
			})
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return records, nil
}

// MembershipRecord holds the fields the reconciler needs from a membership
// Redis entry. It intentionally mirrors membership.Membership but avoids a
// package dependency cycle by redefining only the fields used here.
type MembershipRecord struct {
	TenantID string
	UserID   string
	Email    string
	Role     string
}

// ---------------------------------------------------------------------------
// OrgReconciler
// ---------------------------------------------------------------------------

// OrgReconciler runs one-shot startup reconciliation of Keycloak Organizations
// and FGA tuples from existing Redis membership records.
//
// Construct with NewOrgReconciler; call ReconcileKeycloakOrgs.
type OrgReconciler struct {
	cfg     config.ProvisionerConfig
	scanner membershipScanner
	kc      KeycloakAdmin
	authz   authz.Authorizer
	logger  *slog.Logger
}

// NewOrgReconciler constructs an OrgReconciler.
//
// All non-logger parameters must be non-nil.  When logger is nil, slog.Default()
// is used.
func NewOrgReconciler(
	cfg config.ProvisionerConfig,
	scanner membershipScanner,
	kc KeycloakAdmin,
	az authz.Authorizer,
	logger *slog.Logger,
) *OrgReconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &OrgReconciler{
		cfg:     cfg,
		scanner: scanner,
		kc:      kc,
		authz:   az,
		logger:  logger.With("component", "provisioner.reconciler"),
	}
}

// ReconcileKeycloakOrgs runs the one-shot startup reconciliation.
//
// If cfg.ReconcileOnStartup is false the function returns nil immediately.
// If there are no membership records the function returns nil (no-op fast path).
//
// Individual tenant failures are logged as errors but do not abort the batch.
// The function returns nil unless the initial membership scan fails, in which
// case it returns the scan error wrapped with context.
func (r *OrgReconciler) ReconcileKeycloakOrgs(ctx context.Context) error {
	if !r.cfg.ReconcileOnStartup {
		r.logger.InfoContext(ctx, "reconciliation disabled via config flag (reconcile_on_startup=false)")
		return nil
	}

	// ---------------------------------------------------------------------------
	// Phase 1: Scan all membership records from Redis.
	// ---------------------------------------------------------------------------
	records, err := r.scanner.ScanMemberships(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: failed to scan membership records: %w", err)
	}

	if len(records) == 0 {
		r.logger.InfoContext(ctx, "no tenants to reconcile")
		return nil
	}

	// Group records by tenantID.
	byTenant := make(map[string][]MembershipRecord, len(records))
	for _, rec := range records {
		byTenant[rec.TenantID] = append(byTenant[rec.TenantID], rec)
	}

	r.logger.InfoContext(ctx, "starting Keycloak org reconciliation",
		slog.Int("tenant_count", len(byTenant)),
		slog.Int("member_count", len(records)),
	)

	// ---------------------------------------------------------------------------
	// Phase 2: Per-tenant reconciliation.
	// ---------------------------------------------------------------------------
	var failedTenants []string
	for tenantID, members := range byTenant {
		if err := r.reconcileTenant(ctx, tenantID, members); err != nil {
			r.logger.ErrorContext(ctx, "reconcile: tenant failed",
				slog.String("tenant_id", tenantID),
				slog.String("error", err.Error()),
			)
			failedTenants = append(failedTenants, tenantID)
		}
	}

	if len(failedTenants) > 0 {
		r.logger.WarnContext(ctx, "reconciliation completed with failures",
			slog.Int("failed_tenants", len(failedTenants)),
			slog.String("tenants", strings.Join(failedTenants, ",")),
		)
	} else {
		r.logger.InfoContext(ctx, "reconciliation completed successfully",
			slog.Int("tenants_reconciled", len(byTenant)),
		)
	}

	// Return nil regardless of individual tenant failures: a partial reconcile
	// is recoverable (next startup will retry the failing tenants), and we must
	// not block daemon startup over a migration detail.
	return nil
}

// reconcileTenant ensures a KC Organization exists for tenantID and that every
// member from Redis is added to it, with a matching FGA admin tuple for
// owner/admin roles.
func (r *OrgReconciler) reconcileTenant(ctx context.Context, tenantID string, members []MembershipRecord) error {
	// -----------------------------------------------------------------------
	// Step 1: Ensure the Keycloak Organization exists.
	// -----------------------------------------------------------------------
	orgID, err := r.ensureOrg(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("ensure org for tenant %q: %w", tenantID, err)
	}

	// -----------------------------------------------------------------------
	// Step 2: Add each member to the org; write FGA tuple for privileged roles.
	// -----------------------------------------------------------------------
	for _, m := range members {
		if err := r.reconcileMember(ctx, tenantID, orgID, m); err != nil {
			// Log individual member failures as WARN — the tenant overall is
			// still partially reconciled, which is better than nothing.
			r.logger.WarnContext(ctx, "reconcile: member reconciliation failed",
				slog.String("tenant_id", tenantID),
				slog.String("user_id", m.UserID),
				slog.String("error", err.Error()),
			)
		}
	}

	return nil
}

// ensureOrg returns the Keycloak orgID for tenantID, creating the Organization
// if it does not already exist.
func (r *OrgReconciler) ensureOrg(ctx context.Context, tenantID string) (string, error) {
	// Try to fetch the existing org first (most common case after first
	// reconcile run — idempotent).
	existing, err := r.kc.GetOrganizationByAlias(ctx, tenantID)
	if err == nil {
		r.logger.DebugContext(ctx, "reconcile: org already exists, skipping creation",
			slog.String("tenant_id", tenantID),
			slog.String("org_id", existing.ID),
		)
		return existing.ID, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", fmt.Errorf("get org by alias %q: %w", tenantID, err)
	}

	// Org does not exist — create it.
	orgID, err := r.kc.CreateOrganization(ctx,
		tenantID,      // name (human-readable; for migrated tenants tenantID doubles as name)
		tenantID,      // alias (must equal tenantID for the claim to match)
		fmt.Sprintf("Migrated organization for tenant %s", tenantID),
	)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			// Race: another startup created it between our Get and Create.
			// Fetch again.
			existing, getErr := r.kc.GetOrganizationByAlias(ctx, tenantID)
			if getErr != nil {
				return "", fmt.Errorf("fetch org after conflict for %q: %w", tenantID, getErr)
			}
			return existing.ID, nil
		}
		return "", fmt.Errorf("create org for %q: %w", tenantID, err)
	}

	r.logger.InfoContext(ctx, "reconcile: created Keycloak org",
		slog.String("tenant_id", tenantID),
		slog.String("org_id", orgID),
	)
	return orgID, nil
}

// reconcileMember adds a single user to the KC org (idempotent) and writes the
// FGA admin tuple for owner/admin roles.
//
// If the user does not exist in Keycloak (ErrNotFound or ErrNotFound-wrapped),
// it is logged as WARN and skipped — the reconciler never creates users.
func (r *OrgReconciler) reconcileMember(ctx context.Context, tenantID, orgID string, m MembershipRecord) error {
	if m.UserID == "" {
		r.logger.WarnContext(ctx, "reconcile: skipping membership record with empty userID",
			slog.String("tenant_id", tenantID),
			slog.String("email", m.Email),
		)
		return nil
	}

	// Add the user to the KC org. ErrConflict means already a member — treat
	// as success. ErrNotFound means the KC user does not exist — log WARN.
	if err := r.kc.AddOrganizationMember(ctx, orgID, m.UserID); err != nil {
		if errors.Is(err, ErrConflict) {
			r.logger.DebugContext(ctx, "reconcile: user already an org member, skipping",
				slog.String("tenant_id", tenantID),
				slog.String("user_id", m.UserID),
			)
		} else if errors.Is(err, ErrNotFound) {
			r.logger.WarnContext(ctx, "reconcile: Keycloak user not found — orphaned membership record",
				slog.String("tenant_id", tenantID),
				slog.String("user_id", m.UserID),
				slog.String("email", m.Email),
				slog.String("role", m.Role),
			)
			return nil // skip FGA write too — user doesn't exist
		} else {
			return fmt.Errorf("add org member user=%q org=%q: %w", m.UserID, orgID, err)
		}
	} else {
		r.logger.InfoContext(ctx, "reconcile: added user to KC org",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", m.UserID),
		)
	}

	// Write FGA admin tuple for owner and admin roles. Viewer/operator roles
	// are not elevated to FGA admin — they have read-only access via standard
	// RBAC rules resolved at request time.
	if m.Role == "owner" || m.Role == "admin" {
		tuple := authz.Tuple{
			User:     fmt.Sprintf("user:%s", m.UserID),
			Relation: "admin",
			Object:   fmt.Sprintf("tenant:%s", tenantID),
		}
		if err := r.authz.Write(ctx, []authz.Tuple{tuple}); err != nil {
			// FGA Write is idempotent by design (duplicate tuple is not an error
			// in OpenFGA). Any error here is a real connectivity problem.
			return fmt.Errorf("write FGA tuple user=%q tenant=%q: %w", m.UserID, tenantID, err)
		}
		r.logger.InfoContext(ctx, "reconcile: wrote FGA admin tuple",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", m.UserID),
			slog.String("role", m.Role),
		)
	}

	return nil
}
