// Package admin — secrets_admin.go
//
// SecretsAdminServer is the daemon-side implementation of
// gibson.admin.v1.SecretsAdminService — the dashboard's tenant-admin CRUD
// surface for secrets. It delegates to the daemon's secrets.Service (Spec 1
// R7), which itself delegates to the tenant's configured SecretsBroker.
//
// SECURITY: this handler is the principal guard against plaintext leakage on
// the read side — every Get/List response MUST be metadata-only. Plaintext
// values cross the wire only on Set / Rotate (request bytes, TLS in transit)
// and on the plugin-only HarnessCallbackService.GetCredential RPC. The
// dashboard never invokes the latter.
//
// Spec: secrets-tenant-lifecycle Requirement 8.1, 8.3.
package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// SecretsAdminBroker is the narrow read-side interface SecretsAdminServer
// needs to call when it wants metadata directly off a tenant's broker. The
// production implementation is a closure over secrets.Registry that returns
// (broker, err) for a given tenant.
type SecretsAdminBroker interface {
	For(ctx context.Context, tenant auth.TenantID) (sdksecrets.Broker, error)
}

// SecretsAdminPluginAssociations resolves which plugin install IDs hold an
// FGA can_resolve tuple against a given (tenant, secret_name) pair. The
// production implementation walks FGA tuples; tests inject a fake.
type SecretsAdminPluginAssociations interface {
	PluginsBoundTo(ctx context.Context, tenant auth.TenantID, secretName string) ([]string, error)
}

// SecretsAdminAuditQuery is the narrow read-side interface used by
// GetMissionAudit. The production implementation is *audit.Query.
type SecretsAdminAuditQuery interface {
	List(ctx context.Context, tenantID string, filters audit.Filters, limit, offset int) ([]audit.PgEntry, int, error)
}

// SecretsAdminServer implements the secrets-CRUD portion of tenantv1.SecretsServiceServer (ADR-0039).
// Broker-config methods (GetBrokerConfig/ProbeBrokerConfig/SetBrokerConfig/CountSecrets) are
// handled by CombinedSecretsServer, which delegates to TenantAdminServer for those RPCs.
//
// The handler delegates to secrets.Service for write paths (Set / Rotate /
// Delete) and to the broker for read-side enumeration (List). Plugin
// associations are read via the PluginAssociations bridge; per-mission
// audit aggregation reads the audit_log via AuditQuery.
type SecretsAdminServer struct {
	tenantv1.UnimplementedSecretsServiceServer

	service        *secrets.Service
	broker         SecretsAdminBroker
	pluginAssocs   SecretsAdminPluginAssociations
	auditQuery     SecretsAdminAuditQuery
	now            func() time.Time
	rotatedAuditor secrets.ServiceAuditWriter
}

// SecretsAdminConfig groups the constructor's required dependencies.
type SecretsAdminConfig struct {
	// Service is the daemon's secrets.Service (Spec 1). Required.
	Service *secrets.Service

	// Broker resolves the per-tenant SecretsBroker for read-side metadata
	// listing. Required.
	Broker SecretsAdminBroker

	// PluginAssociations resolves plugin install IDs bound to a secret.
	// Required.
	PluginAssociations SecretsAdminPluginAssociations

	// AuditQuery is the audit_log reader used by GetMissionAudit. Required.
	AuditQuery SecretsAdminAuditQuery

	// RotatedAuditor receives the secret_rotated event on RotateSecret and
	// secret_revoked on DeleteSecret. Optional — when nil, no event is
	// emitted (the underlying secrets.Service still emits its
	// secret_write / secret_delete event regardless).
	RotatedAuditor secrets.ServiceAuditWriter

	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// NewSecretsAdminServer constructs a SecretsAdminServer. All fields in cfg
// except Now and RotatedAuditor are required.
func NewSecretsAdminServer(cfg SecretsAdminConfig) (*SecretsAdminServer, error) {
	if cfg.Service == nil {
		return nil, errors.New("secrets admin: Service is required")
	}
	if cfg.Broker == nil {
		return nil, errors.New("secrets admin: Broker is required")
	}
	if cfg.PluginAssociations == nil {
		return nil, errors.New("secrets admin: PluginAssociations is required")
	}
	if cfg.AuditQuery == nil {
		return nil, errors.New("secrets admin: AuditQuery is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &SecretsAdminServer{
		service:        cfg.Service,
		broker:         cfg.Broker,
		pluginAssocs:   cfg.PluginAssociations,
		auditQuery:     cfg.AuditQuery,
		rotatedAuditor: cfg.RotatedAuditor,
		now:            now,
	}, nil
}

// ---------------------------------------------------------------------------
// SecretsAdminService RPC implementations
// ---------------------------------------------------------------------------

// ListSecrets returns the metadata-only list of secrets for the tenant
// derived from the call context.
func (s *SecretsAdminServer) ListSecrets(ctx context.Context, req *tenantv1.ListSecretsRequest) (*tenantv1.ListSecretsResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 50
	}
	offset := int(req.GetOffset())
	if offset < 0 {
		offset = 0
	}

	// Build the broker-side filter prefix. Secrets are stored under "user/"
	// in Vault (e.g. "user/cred:foo", "user/provider_config:bar:field").
	// categoryPrefix() already includes the "user/" segment, so the combined
	// prefix is correct for the broker.
	// When only a name_prefix is supplied (no category filter), translate any
	// caller-facing prefix (e.g. "cred:") to stored form ("user/cred:").
	callerPrefix := req.GetNamePrefix()
	var prefix string
	if cat := req.GetCategoryFilter(); cat != tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED {
		// categoryPrefix returns "user/cred:" or "user/provider_config:" —
		// append the caller-supplied name sub-prefix.
		prefix = categoryPrefix(cat) + callerPrefix
	} else {
		// No category filter: translate the raw caller prefix to stored form
		// so that e.g. "cred:" becomes "user/cred:".
		prefix = toStoredName(callerPrefix)
	}

	names, err := s.service.List(ctx, sdksecrets.Filter{
		Prefix: prefix,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, err // already a gRPC status from secrets.Service
	}

	out := make([]*tenantv1.SecretMetadata, 0, len(names))
	for _, stored := range names {
		md, mdErr := s.buildMetadata(ctx, tenant, stored)
		if mdErr != nil {
			// A metadata-build failure for a single row should not poison
			// the whole list response; surface a degraded entry that has
			// at least the name + category populated.
			md = &tenantv1.SecretMetadata{
				Name:     callerName(stored),
				Category: parseCategory(stored),
			}
		}
		out = append(out, md)
	}

	return &tenantv1.ListSecretsResponse{
		Secrets: out,
		Total:   int32(len(out) + offset),
	}, nil
}

// GetSecret returns metadata-only information for one named secret.
//
// SECURITY: the response carries no value field — by proto contract.
func (s *SecretsAdminServer) GetSecret(ctx context.Context, req *tenantv1.GetSecretRequest) (*tenantv1.GetSecretResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	// The caller uses the caller-facing name (e.g. "cred:openai-prod").
	// Internally secrets are stored under "user/<name>". Translate before
	// querying the broker.
	callerReq := req.GetName()
	storedReq := toStoredName(callerReq)

	// Existence check: List with a tight prefix containing the exact name.
	// We cannot call Resolve here — that would require can_read_credential
	// and would log a secret_read audit row, both inappropriate for a
	// dashboard metadata fetch.
	names, err := s.service.List(ctx, sdksecrets.Filter{Prefix: storedReq, Limit: 1})
	if err != nil {
		return nil, err
	}
	found := false
	for _, n := range names {
		if n == storedReq {
			found = true
			break
		}
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "secret %q not found", callerReq)
	}

	md, err := s.buildMetadata(ctx, tenant, storedReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build metadata: %v", err)
	}
	return &tenantv1.GetSecretResponse{Metadata: md}, nil
}

// SetSecret creates or overwrites a secret with the supplied value bytes.
// The response never contains the value.
func (s *SecretsAdminServer) SetSecret(ctx context.Context, req *tenantv1.SetSecretRequest) (*tenantv1.SetSecretResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if len(req.GetValue()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "value is required")
	}
	if req.GetCategory() == tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "category is required")
	}

	// Enforce the category prefix on the stored name. The dashboard's
	// form sends the unprefixed name; the daemon namespaces it.
	stored := storedName(req.GetCategory(), req.GetName())

	if err := s.service.Put(ctx, stored, req.GetValue()); err != nil {
		return nil, err
	}

	md, err := s.buildMetadata(ctx, tenant, stored)
	if err != nil {
		// Write succeeded; metadata read-back failed. Return a minimal
		// metadata so the dashboard can still render its toast.
		md = &tenantv1.SecretMetadata{
			Name:          stored,
			Category:      req.GetCategory(),
			UpdatedAtUnix: s.now().UTC().Unix(),
		}
	}
	return &tenantv1.SetSecretResponse{Metadata: md}, nil
}

// RotateSecret writes a new value to an existing secret. It additionally
// emits a secret_rotated audit event so the dashboard's audit page shows
// rotations distinctly from initial creates.
func (s *SecretsAdminServer) RotateSecret(ctx context.Context, req *tenantv1.RotateSecretRequest) (*tenantv1.RotateSecretResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if len(req.GetValue()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "value is required")
	}

	callerReq := req.GetName()
	storedReq := toStoredName(callerReq)

	// Existence precondition — Rotate refuses to create a new secret.
	names, err := s.service.List(ctx, sdksecrets.Filter{Prefix: storedReq, Limit: 1})
	if err != nil {
		return nil, err
	}
	exists := false
	for _, n := range names {
		if n == storedReq {
			exists = true
			break
		}
	}
	if !exists {
		return nil, status.Errorf(codes.NotFound, "secret %q not found; cannot rotate", callerReq)
	}

	start := s.now()
	if err := s.service.Put(ctx, storedReq, req.GetValue()); err != nil {
		return nil, err
	}

	if s.rotatedAuditor != nil {
		s.rotatedAuditor.Audit(ctx, secrets.AuditEvent{
			ActorTenantID: tenant.String(),
			Action:        "secret_rotated",
			Effect:        secrets.EffectAllow,
			ResourceType:  "secret",
			ResourceURI:   fmt.Sprintf("secret:tenant-%s:%s", tenant, callerReq),
			Decision:      "allow",
			Success:       true,
			LatencyMS:     time.Since(start).Milliseconds(),
			OccurredAt:    s.now().UTC(),
		})
	}

	md, err := s.buildMetadata(ctx, tenant, storedReq)
	if err != nil {
		md = &tenantv1.SecretMetadata{
			Name:          callerReq,
			Category:      parseCategory(storedReq),
			UpdatedAtUnix: s.now().UTC().Unix(),
		}
	}
	return &tenantv1.RotateSecretResponse{Metadata: md}, nil
}

// DeleteSecret removes a secret and emits a secret_revoked audit event.
func (s *SecretsAdminServer) DeleteSecret(ctx context.Context, req *tenantv1.DeleteSecretRequest) (*tenantv1.DeleteSecretResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	callerReq := req.GetName()
	storedReq := toStoredName(callerReq)

	start := s.now()
	if err := s.service.Delete(ctx, storedReq); err != nil {
		return nil, err
	}

	if s.rotatedAuditor != nil {
		s.rotatedAuditor.Audit(ctx, secrets.AuditEvent{
			ActorTenantID: tenant.String(),
			Action:        "secret_revoked",
			Effect:        secrets.EffectAllow,
			ResourceType:  "secret",
			ResourceURI:   fmt.Sprintf("secret:tenant-%s:%s", tenant, callerReq),
			Decision:      "allow",
			Success:       true,
			LatencyMS:     time.Since(start).Milliseconds(),
			OccurredAt:    s.now().UTC(),
		})
	}

	return &tenantv1.DeleteSecretResponse{}, nil
}

// GetMissionAudit returns the per-mission resolved-secret refs for the
// dashboard's mission detail "Secrets accessed" panel. Refs only — never
// values.
func (s *SecretsAdminServer) GetMissionAudit(ctx context.Context, req *tenantv1.GetMissionAuditRequest) (*tenantv1.GetMissionAuditResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetMissionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "mission_id is required")
	}

	// Read all secret_read events for the tenant; aggregate by ref. The
	// audit_log table doesn't carry mission_id as a top-level column —
	// it lives in the metadata JSONB. We pull a generous page and filter
	// in Go. Acceptable for v1; can be moved to a SQL query when the
	// audit pipeline gains a mission_id index.
	const maxScan = 5000

	entries, _, err := s.auditQuery.List(ctx, tenant.String(), audit.Filters{
		Action: secrets.ActionSecretRead,
	}, maxScan, 0)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "audit query: %v", err)
	}

	// aggregate maps ref -> aggregated stats.
	type aggRow struct {
		firstAt  time.Time
		lastAt   time.Time
		count    int32
		installs map[string]struct{}
		category tenantv1.SecretCategory
	}
	agg := map[string]*aggRow{}

	var oldestSeen time.Time
	for _, e := range entries {
		// Filter by mission_id from metadata JSONB. The audit writer
		// emits mission_id when the operation occurred within a mission.
		md := parseAuditMetadata(e.Metadata)
		if md["mission_id"] != req.GetMissionId() {
			continue
		}

		ref := uriToRef(e.TargetID)
		if ref == "" {
			ref = uriToRef(string(md["resource_uri"]))
		}
		if ref == "" {
			continue
		}

		row, ok := agg[ref]
		if !ok {
			row = &aggRow{
				firstAt:  e.CreatedAt,
				lastAt:   e.CreatedAt,
				installs: map[string]struct{}{},
				category: parseCategory(ref),
			}
			agg[ref] = row
		}
		if e.CreatedAt.Before(row.firstAt) {
			row.firstAt = e.CreatedAt
		}
		if e.CreatedAt.After(row.lastAt) {
			row.lastAt = e.CreatedAt
		}
		row.count++
		if e.ActorID != "" {
			row.installs[e.ActorID] = struct{}{}
		}
		if oldestSeen.IsZero() || e.CreatedAt.Before(oldestSeen) {
			oldestSeen = e.CreatedAt
		}
	}

	out := make([]*tenantv1.MissionSecretAccess, 0, len(agg))
	for ref, row := range agg {
		installs := make([]string, 0, len(row.installs))
		for id := range row.installs {
			installs = append(installs, id)
		}
		out = append(out, &tenantv1.MissionSecretAccess{
			Ref:               ref,
			Category:          row.category,
			FirstAccessAtUnix: row.firstAt.Unix(),
			LastAccessAtUnix:  row.lastAt.Unix(),
			Count:             row.count,
			PluginInstallIds:  installs,
		})
	}

	// Approximate aggregation lag: time between now and the most recent
	// secret_read event we observed for this mission. Saturates at 0 if
	// the mission has no events yet.
	lag := int32(0)
	if !oldestSeen.IsZero() {
		l := s.now().Sub(oldestSeen).Seconds()
		if l > 0 && l < float64(int32(^uint32(0)>>1)) {
			lag = int32(l)
		}
	}

	return &tenantv1.GetMissionAuditResponse{
		Accesses:              out,
		AggregationLagSeconds: lag,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildMetadata constructs a SecretMetadata for one stored name. It does
// NOT call Resolve (which would log a secret_read). Versions / created_at
// are best-effort; broker providers don't expose them through the v1
// SecretsBroker interface, so for v1 we report zero values.
//
// The Name field in the returned metadata uses callerName(stored) so that the
// internal "user/" Vault prefix is never exposed to dashboard callers.
func (s *SecretsAdminServer) buildMetadata(ctx context.Context, tenant auth.TenantID, stored string) (*tenantv1.SecretMetadata, error) {
	if stored == "" {
		return nil, errors.New("name must not be empty")
	}

	cat := parseCategory(stored)
	name := callerName(stored) // strip "user/" for caller-facing name

	plugins, err := s.pluginAssocs.PluginsBoundTo(ctx, tenant, stored)
	if err != nil {
		// Plugin associations are best-effort metadata.
		plugins = nil
	}

	return &tenantv1.SecretMetadata{
		Name:               name,
		Category:           cat,
		Version:            0,
		CreatedAtUnix:      0,
		CreatedBy:          "",
		UpdatedAtUnix:      0,
		UpdatedBy:          "",
		LastAccessedAtUnix: 0,
		PluginAssociations: plugins,
	}, nil
}

// userPrefix is the Vault KV sub-path under which all user-supplied secrets
// are stored. This separates user secrets from operator-written infra secrets
// (infra/postgres, infra/neo4j, etc.) which live at the root of the per-tenant
// mount. The new Vault ACL (tenant-operator#271) enforces this boundary.
//
// Spec: secrets-blast-radius-reduction / gibson#404.
const userPrefix = "user/"

// parseCategory inspects the name's prefix and returns the corresponding
// SecretCategory enum value. Names may carry the userPrefix ("user/") at the
// front (stored form) or omit it (caller-facing form); both are handled.
// Names that don't carry a recognised category prefix are classified as
// SECRET_CATEGORY_UNSPECIFIED (rendered as "uncategorised" in the dashboard).
func parseCategory(name string) tenantv1.SecretCategory {
	n := strings.TrimPrefix(name, userPrefix)
	switch {
	case strings.HasPrefix(n, "cred:"):
		return tenantv1.SecretCategory_SECRET_CATEGORY_CRED
	case strings.HasPrefix(n, "provider_config:"):
		return tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG
	default:
		return tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED
	}
}

// categoryPrefix returns the full broker-namespace prefix for a category enum
// value, including the userPrefix. Used to convert ListSecrets category_filter
// into a broker List filter so that only the correct sub-path is scanned.
func categoryPrefix(cat tenantv1.SecretCategory) string {
	switch cat {
	case tenantv1.SecretCategory_SECRET_CATEGORY_CRED:
		return userPrefix + "cred:"
	case tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG:
		return userPrefix + "provider_config:"
	default:
		return ""
	}
}

// storedName returns the broker-namespaced name for a SetSecret request.
// User secrets are stored under "user/<category>:<name>" so the Vault ACL can
// distinguish them from infra secrets at the mount root.
// If the supplied name already carries the full stored prefix it is returned
// as-is to preserve idempotency.
func storedName(cat tenantv1.SecretCategory, name string) string {
	prefix := categoryPrefix(cat)
	if prefix == "" {
		return name
	}
	if strings.HasPrefix(name, prefix) {
		return name
	}
	// Strip a bare category prefix if the caller passed "cred:<name>" instead
	// of the bare name — ensures a double-prefix is never written.
	barePrefix := strings.TrimPrefix(prefix, userPrefix)
	name = strings.TrimPrefix(name, barePrefix)
	return prefix + name
}

// callerName strips the userPrefix from a stored name so that the name
// returned to the dashboard caller does not expose the internal Vault layout.
// "user/cred:openai-prod" → "cred:openai-prod".
// Names that do not carry userPrefix are returned unchanged.
func callerName(stored string) string {
	return strings.TrimPrefix(stored, userPrefix)
}

// toStoredName converts a caller-facing name to the stored form by prepending
// userPrefix when the name does not already start with it.
// "cred:openai-prod"       → "user/cred:openai-prod"
// "user/cred:openai-prod"  → "user/cred:openai-prod" (idempotent)
// Names without a recognised category prefix (unspecified) are returned as-is.
func toStoredName(name string) string {
	if strings.HasPrefix(name, userPrefix) {
		return name // already in stored form
	}
	// Only namespace known category-prefixed names; leave unrecognised names
	// (e.g. infra secrets) untouched.
	if strings.HasPrefix(name, "cred:") || strings.HasPrefix(name, "provider_config:") {
		return userPrefix + name
	}
	return name
}

// uriToRef parses a "secret:tenant-${id}:${ref}" URI and returns the ref
// portion. Empty string when the URI doesn't match.
func uriToRef(uri string) string {
	const prefix = "secret:tenant-"
	if !strings.HasPrefix(uri, prefix) {
		return ""
	}
	rest := uri[len(prefix):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	return rest[colon+1:]
}

// parseAuditMetadata parses the JSONB metadata column into a flat
// map[string]string. Best-effort — unknown / nested values are dropped.
func parseAuditMetadata(raw []byte) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	out := map[string]string{}
	// Use a one-off jsonish decode without importing encoding/json at the
	// top-level (already imported via audit.PgEntry). Inline import via
	// init is overkill; we use the standard library directly here.
	if err := jsonUnmarshalToStringMap(raw, out); err != nil {
		return map[string]string{}
	}
	return out
}
