// Package daemon — dispatch_override.go
//
// DispatchOverrideServer implements the DispatchOverrideService gRPC server
// (internal/daemon/api/gibson/platform/v1.DispatchOverrideServiceServer).
//
// The service is the platform-operator escape hatch described in
// setec-sandbox-prod-default design §C4 (R3.4). It lets a platform operator
// temporarily allow UNTRUSTED+PLUGIN/AGENT dispatch for a specific tenant when
// Setec is degraded and waiting for the sandbox to recover is not feasible.
//
// Security invariants enforced here (FGA gate is handled upstream by ext-authz):
//
//   - ttl_seconds is hard-capped at 3600 (1 hour); larger values are clamped
//     silently and the response echoes the applied TTL.
//   - reason is mandatory; empty reason returns codes.InvalidArgument.
//   - Every mutation emits a synchronous audit event via audit.WriteSync that
//     must ack before the RPC response is sent.
//   - Redis stores the absolute expiry so a daemon restart does not silently
//     extend an active override. The in-memory map is authoritative for the
//     current process; Redis is the restart-safe fallback.
//   - The operator ID comes from the auth.Identity extracted by the ext-authz
//     interceptor (x-gibson-user-id header), never from a request field.
//
// Spec: setec-sandbox-prod-default §C4, R3.4, R3.5.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/audit"
	platformv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/platform/v1"
	"github.com/zero-day-ai/gibson/internal/dispatch"
	"github.com/zero-day-ai/sdk/auth"
)

// maxOverrideTTL is the server-side hard upper bound on override lifetime.
// Any client-requested TTL above this value is silently clamped.
const maxOverrideTTL = 3600 * time.Second

// overrideRedisKeyPrefix is the Redis key prefix for dispatch override records.
// Full key: dispatch:policy:override:{tenantID}
const overrideRedisKeyPrefix = "dispatch:policy:override:"

// OverrideRecord is the value stored in both the in-memory cache and Redis.
// It carries enough information for the dispatch gate to populate
// Input.OverrideActive and for auditors to trace the override to its originating
// audit event.
type OverrideRecord struct {
	TenantID     string    `json:"tenant_id"`
	OperatorID   string    `json:"operator_id"`    // Zitadel sub from x-gibson-user-id
	Reason       string    `json:"reason"`          // mandatory free text
	ExpiresAt    time.Time `json:"expires_at"`      // absolute expiry (UTC)
	AuditEventID string    `json:"audit_event_id"` // ID of the authorising audit row
}

// Active returns true if the record exists and has not yet expired.
func (r *OverrideRecord) Active() bool {
	return r != nil && time.Now().Before(r.ExpiresAt)
}

// DispatchOverrideServer implements platformv1.DispatchOverrideServiceServer.
//
// It is registered on the daemon gRPC server alongside the existing
// PlatformOperatorService. The FGA gate (platform_operator on system_tenant)
// is enforced upstream by ext-authz; this handler does not re-implement it.
type DispatchOverrideServer struct {
	platformv1.UnimplementedDispatchOverrideServiceServer

	redis  goredis.UniversalClient
	audit  *audit.Writer
	logger *slog.Logger
	now    func() time.Time // injectable for tests

	mu      sync.RWMutex
	inMem   map[string]*OverrideRecord // key: tenant ID
}

// NewDispatchOverrideServer constructs a DispatchOverrideServer.
//
// redis must be non-nil (the handler persists records to Redis so they
// survive daemon restarts). auditWriter should be non-nil in production;
// when nil, audit events are logged but not durably written (acceptable
// only in tests).
func NewDispatchOverrideServer(redis goredis.UniversalClient, auditWriter *audit.Writer, logger *slog.Logger) *DispatchOverrideServer {
	if logger == nil {
		logger = slog.Default()
	}
	return &DispatchOverrideServer{
		redis:  redis,
		audit:  auditWriter,
		logger: logger.With("component", "dispatch_override"),
		now:    time.Now,
		inMem:  make(map[string]*OverrideRecord),
	}
}

// OverrideDispatchPolicy creates or revokes a time-bounded policy override
// for the given tenant.
//
// The gate decision audit event is emitted synchronously before the response
// is returned, per R3.5.
func (s *DispatchOverrideServer) OverrideDispatchPolicy(
	ctx context.Context,
	req *platformv1.OverrideDispatchPolicyRequest,
) (*platformv1.OverrideDispatchPolicyResponse, error) {
	// ── Input validation ─────────────────────────────────────────────────────
	if req.GetTenantId() == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetReason() == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "reason is required and must not be empty")
	}

	// ── Operator identity from auth context (x-gibson-user-id header) ────────
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil || callerID.Subject == "" {
		return nil, grpcstatus.Error(codes.Unauthenticated, "operator identity not found in context")
	}
	operatorID := callerID.Subject

	tenantID := req.GetTenantId()
	now := s.now()
	auditEventID := uuid.NewString()

	if !req.GetAllow() {
		// ── Revoke path ──────────────────────────────────────────────────────
		return s.revokeOverride(ctx, tenantID, operatorID, req.GetReason(), auditEventID, now)
	}

	// ── Install path ─────────────────────────────────────────────────────────
	// Clamp TTL to the hard upper bound.
	requestedTTL := time.Duration(req.GetTtlSeconds()) * time.Second
	appliedTTL := requestedTTL
	if appliedTTL <= 0 || appliedTTL > maxOverrideTTL {
		appliedTTL = maxOverrideTTL
	}
	expiresAt := now.Add(appliedTTL)

	record := &OverrideRecord{
		TenantID:     tenantID,
		OperatorID:   operatorID,
		Reason:       req.GetReason(),
		ExpiresAt:    expiresAt,
		AuditEventID: auditEventID,
	}

	// ── Synchronous audit emit (R3.5) ────────────────────────────────────────
	auditMeta, _ := json.Marshal(map[string]interface{}{
		"tenant_id":       tenantID,
		"applied_ttl_sec": int64(appliedTTL.Seconds()),
		"expires_at_unix": expiresAt.Unix(),
		"reason":          req.GetReason(),
		"operator_id":     operatorID,
		"audit_event_id":  auditEventID,
		"action":          "install",
	})
	auditEvent := audit.Event{
		TenantID:   tenantID,
		ActorID:    operatorID,
		ActorType:  "user",
		Action:     "dispatch_policy_override",
		TargetType: "tenant",
		TargetID:   tenantID,
		Decision:   "allow",
		Metadata:   auditMeta,
	}
	if s.audit != nil {
		if werr := s.audit.WriteSync(ctx, auditEvent); werr != nil {
			// Audit failure is fatal: we must not proceed without a durable record.
			s.logger.ErrorContext(ctx, "dispatch_override: audit write failed; aborting override install",
				slog.String("tenant_id", tenantID),
				slog.String("error", werr.Error()))
			return nil, grpcstatus.Errorf(codes.Internal,
				"override aborted: audit write failed: %v", werr)
		}
	} else {
		s.logger.WarnContext(ctx, "dispatch_override: no audit writer wired; override proceeds without durable record",
			slog.String("tenant_id", tenantID))
	}

	// ── Persist to Redis ──────────────────────────────────────────────────────
	if err := s.persistToRedis(ctx, record, appliedTTL); err != nil {
		s.logger.ErrorContext(ctx, "dispatch_override: Redis persist failed; override is in-memory only",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()))
		// Non-fatal: the in-memory record still works for this process.
		// A daemon restart would lose the override (safe-side failure).
	}

	// ── Update in-memory cache ────────────────────────────────────────────────
	s.mu.Lock()
	s.inMem[tenantID] = record
	s.mu.Unlock()

	s.logger.InfoContext(ctx, "dispatch_override: override installed",
		slog.String("tenant_id", tenantID),
		slog.String("operator_id", operatorID),
		slog.Duration("applied_ttl", appliedTTL),
		slog.Time("expires_at", expiresAt),
		slog.String("audit_event_id", auditEventID))

	return &platformv1.OverrideDispatchPolicyResponse{
		AppliedTtlSeconds: int32(appliedTTL.Seconds()),
		ExpiresAtUnix:     expiresAt.Unix(),
		AuditEventId:      auditEventID,
	}, nil
}

// revokeOverride handles the revoke path (req.allow=false).
func (s *DispatchOverrideServer) revokeOverride(
	ctx context.Context,
	tenantID, operatorID, reason, auditEventID string,
	now time.Time,
) (*platformv1.OverrideDispatchPolicyResponse, error) {
	auditMeta, _ := json.Marshal(map[string]interface{}{
		"tenant_id":      tenantID,
		"reason":         reason,
		"operator_id":    operatorID,
		"audit_event_id": auditEventID,
		"action":         "revoke",
	})
	auditEvent := audit.Event{
		TenantID:   tenantID,
		ActorID:    operatorID,
		ActorType:  "user",
		Action:     "dispatch_policy_override",
		TargetType: "tenant",
		TargetID:   tenantID,
		Decision:   "deny", // revoke reinstates the deny
		Metadata:   auditMeta,
	}
	if s.audit != nil {
		if werr := s.audit.WriteSync(ctx, auditEvent); werr != nil {
			s.logger.ErrorContext(ctx, "dispatch_override: audit write failed on revoke",
				slog.String("tenant_id", tenantID),
				slog.String("error", werr.Error()))
			return nil, grpcstatus.Errorf(codes.Internal,
				"revoke aborted: audit write failed: %v", werr)
		}
	}

	// Remove from Redis.
	if s.redis != nil {
		key := overrideRedisKeyPrefix + tenantID
		if err := s.redis.Del(ctx, key).Err(); err != nil && err != goredis.Nil {
			s.logger.WarnContext(ctx, "dispatch_override: Redis delete failed on revoke",
				slog.String("tenant_id", tenantID),
				slog.String("error", err.Error()))
		}
	}

	// Remove from in-memory cache.
	s.mu.Lock()
	delete(s.inMem, tenantID)
	s.mu.Unlock()

	s.logger.InfoContext(ctx, "dispatch_override: override revoked",
		slog.String("tenant_id", tenantID),
		slog.String("operator_id", operatorID),
		slog.String("audit_event_id", auditEventID))

	return &platformv1.OverrideDispatchPolicyResponse{
		AppliedTtlSeconds: 0,
		ExpiresAtUnix:     0,
		AuditEventId:      auditEventID,
	}, nil
}

// persistToRedis writes the override record to Redis with the given TTL.
func (s *DispatchOverrideServer) persistToRedis(ctx context.Context, record *OverrideRecord, ttl time.Duration) error {
	if s.redis == nil {
		return nil
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal override record: %w", err)
	}
	key := overrideRedisKeyPrefix + record.TenantID
	return s.redis.Set(ctx, key, data, ttl).Err()
}

// LookupOverride returns the active override record for a tenant, consulting
// the in-memory cache first and falling back to Redis on a miss.
//
// Returns nil when no active override exists (either none was set, or the
// TTL has expired and the in-memory entry was purged). The caller is
// responsible for evicting stale entries — this method evicts them from the
// in-memory map on read if the record has expired.
//
// This method is goroutine-safe and is called by the dispatch package's
// OverrideLookup (Task 30) to populate Input.OverrideActive before the gate
// evaluates each dispatch.
func (s *DispatchOverrideServer) LookupOverride(ctx context.Context, tenantID string) *OverrideRecord {
	// ── Fast path: in-memory cache ────────────────────────────────────────────
	s.mu.RLock()
	rec, ok := s.inMem[tenantID]
	s.mu.RUnlock()

	if ok {
		if rec.Active() {
			return rec
		}
		// Expired — evict from in-memory map.
		s.mu.Lock()
		delete(s.inMem, tenantID)
		s.mu.Unlock()
	}

	// ── Slow path: Redis fallback (process restart recovery) ─────────────────
	if s.redis == nil {
		return nil
	}
	key := overrideRedisKeyPrefix + tenantID
	raw, err := s.redis.Get(ctx, key).Result()
	if err == goredis.Nil {
		return nil // no override in Redis
	}
	if err != nil {
		s.logger.WarnContext(ctx, "dispatch_override: Redis lookup failed",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()))
		return nil
	}

	var r OverrideRecord
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		s.logger.WarnContext(ctx, "dispatch_override: unmarshal failed",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()))
		return nil
	}
	if !r.Active() {
		// Redis TTL should have already evicted it; treat as absent.
		return nil
	}

	// Populate in-memory cache for subsequent lookups.
	s.mu.Lock()
	s.inMem[tenantID] = &r
	s.mu.Unlock()

	return &r
}

// ── dispatch.OverrideLookup adapter ──────────────────────────────────────────

// DispatchOverrideLookup adapts DispatchOverrideServer to satisfy the
// dispatch.OverrideLookup interface. It is returned by
// DispatchOverrideServer.AsOverrideLookup() and passed to the harness factory
// as the HarnessConfig.OverrideLookup so the harness can populate
// Input.OverrideActive before calling Policy.Decide.
//
// The daemon package imports dispatch (dispatch does not import daemon —
// dispatch only imports context + componentpb), so there is no import cycle.
type DispatchOverrideLookup struct {
	srv *DispatchOverrideServer
}

// LookupTenantOverride checks the DispatchOverrideServer for an active
// override for tenantID and returns the result as a dispatch.OverrideState.
// Satisfies dispatch.OverrideLookup.
func (l *DispatchOverrideLookup) LookupTenantOverride(ctx context.Context, tenantID string) dispatch.OverrideState {
	rec := l.srv.LookupOverride(ctx, tenantID)
	if rec == nil {
		return dispatch.OverrideState{}
	}
	return dispatch.OverrideState{Active: true, AuditEventID: rec.AuditEventID}
}

// AsOverrideLookup returns a dispatch.OverrideLookup adapter backed by this
// DispatchOverrideServer. The returned *DispatchOverrideLookup satisfies the
// dispatch.OverrideLookup interface.
func (s *DispatchOverrideServer) AsOverrideLookup() *DispatchOverrideLookup {
	return &DispatchOverrideLookup{srv: s}
}

// Compile-time assertion that *DispatchOverrideLookup satisfies dispatch.OverrideLookup.
var _ dispatch.OverrideLookup = (*DispatchOverrideLookup)(nil)
