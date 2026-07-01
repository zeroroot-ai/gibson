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
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
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

	// Build the broker-side filter prefix. Tenant secrets are stored
	// colon-flat at the KV root (e.g. "cred:foo",
	// "provider_config:bar:field") — the same layout as the LLM
	// provider_cred:… keys that already list correctly. This is the H1 fix
	// (gibson#1106): the retired "user/<category>:<name>" layout was invisible
	// to a namespace-mode root LIST, so Put succeeded while List returned empty.
	callerPrefix := req.GetNamePrefix()
	var prefix string
	if cat := req.GetCategoryFilter(); cat != tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED {
		// categoryPrefix returns "cred:" or "provider_config:" — append the
		// caller-supplied name sub-prefix.
		prefix = categoryPrefix(cat) + callerPrefix
	} else {
		// No category filter: the caller prefix is already the stored form
		// (colon-flat at root).
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

	// Tenant secrets are stored colon-flat at the KV root, so the caller name
	// (e.g. "cred:openai-prod") is already the stored form. toStoredName is
	// kept as an idempotent normaliser for defensive call-site symmetry.
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
// Tenant secrets are stored colon-flat at the KV root, so the stored name is
// already the caller-facing name; callerName is an identity normaliser.
func (s *SecretsAdminServer) buildMetadata(ctx context.Context, tenant auth.TenantID, stored string) (*tenantv1.SecretMetadata, error) {
	if stored == "" {
		return nil, errors.New("name must not be empty")
	}

	cat := parseCategory(stored)
	name := callerName(stored)

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

// Tenant secrets are stored colon-flat at the KV root, keyed by
// "<category>:<name>" (e.g. "cred:openai-prod",
// "provider_config:openai:default"). This mirrors the LLM provider_cred:…
// layout that already lists correctly and is the H1 fix (gibson#1106 / PRD
// gibson#1105): the retired "user/<category>:<name>" layout put secrets under
// a Vault pseudo-directory that a Hosted namespace-mode root LIST skips, so a
// Put succeeded while Get/List came back empty.
//
// Because the stored key equals the caller-facing name, callerName /
// toStoredName are identity normalisers kept for call-site symmetry.

// parseCategory inspects the name's prefix and returns the corresponding
// SecretCategory enum value. Names that don't carry a recognised category
// prefix are classified as SECRET_CATEGORY_UNSPECIFIED (rendered as
// "uncategorised" in the dashboard).
func parseCategory(name string) tenantv1.SecretCategory {
	switch {
	case strings.HasPrefix(name, "cred:"):
		return tenantv1.SecretCategory_SECRET_CATEGORY_CRED
	case strings.HasPrefix(name, "provider_config:"):
		return tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG
	default:
		return tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED
	}
}

// categoryPrefix returns the colon-flat key prefix for a category enum value.
// Used to convert ListSecrets category_filter into a broker List filter so
// that only the correct category is scanned.
func categoryPrefix(cat tenantv1.SecretCategory) string {
	switch cat {
	case tenantv1.SecretCategory_SECRET_CATEGORY_CRED:
		return "cred:"
	case tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG:
		return "provider_config:"
	default:
		return ""
	}
}

// storedName returns the broker key for a SetSecret request. Tenant secrets
// are stored colon-flat at the KV root as "<category>:<name>". If the supplied
// name already carries the category prefix it is returned as-is (idempotent).
func storedName(cat tenantv1.SecretCategory, name string) string {
	prefix := categoryPrefix(cat)
	if prefix == "" {
		return name
	}
	if strings.HasPrefix(name, prefix) {
		return name
	}
	return prefix + name
}

// callerName returns the caller-facing name for a stored key. With the
// colon-flat root layout the stored key already equals the caller-facing
// name, so this is an identity normaliser retained for call-site symmetry.
func callerName(stored string) string {
	return stored
}

// toStoredName converts a caller-facing name to the stored key. With the
// colon-flat root layout the caller name is already the stored key, so this is
// an identity normaliser retained for call-site symmetry.
func toStoredName(name string) string {
	return name
}

// uriToRef parses a "secret:tenant-${id}/${ref}" URI and returns the ref
// portion. The canonical separator between tenant-id and ref is "/" (NOT ":"
// — OpenFGA rejects a colon inside an object id; see gibson#1024 and
// authz.TenantQualifiedSep).
//
// uriToRef also accepts the legacy "secret:tenant-${id}:${ref}" form (colon
// separator) for backward compatibility with audit log entries written before
// gibson#1024; newly written FGA objects and audit events use the slash form.
// Empty string when the URI doesn't match either form.
func uriToRef(uri string) string {
	const prefix = "secret:tenant-"
	if !strings.HasPrefix(uri, prefix) {
		return ""
	}
	rest := uri[len(prefix):]
	// Try the canonical slash separator first (gibson#1024).
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		return rest[slash+1:]
	}
	// Fall back to legacy colon separator for pre-#1024 audit log data.
	if colon := strings.IndexByte(rest, ':'); colon >= 0 {
		return rest[colon+1:]
	}
	return ""
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
