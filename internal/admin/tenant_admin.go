// Package admin — tenant_admin.go
//
// TenantAdminServer implements gibson.admin.v1.TenantAdminService — the
// dashboard's tenant-admin surface for broker configuration and member
// enumeration. Pairs with secrets_admin.go (secrets), plugin_admin.go
// (plugin installs), and grants_admin.go (capability grants).
//
// Get / Probe / Set semantics:
//   - GetBrokerConfig returns the redacted current configuration. Sensitive
//     fields are NEVER returned — the redactor strips them before this
//     handler builds the response.
//   - ProbeBrokerConfig validates a candidate config without persisting.
//     Constructs a candidate provider via the registered factory and calls
//     Probe; the structured success/error result is returned.
//   - SetBrokerConfig probes the candidate (per Spec 1 R6.4) and persists
//     it on success. Emits a tenant_secrets_backend_configured audit event.
//
// ListMembers semantics:
//   - Queries OpenFGA for all users with the "member" relation on the
//     tenant, then batch-checks admin role for each, then enriches from
//     the IdP (display_name + email). name_filter applies a
//     case-insensitive prefix match. Pagination is offset-based with a
//     base64-encoded cursor.
//
// SECURITY: sensitive auth fields (Vault token, AWS keys, GCP SA JSON,
// Azure client secret) are write-only from the dashboard's perspective.
// They flow inbound on Set/Probe; they NEVER appear in any read response.
//
// Spec: secrets-tenant-lifecycle Requirement 8.1, Requirement 3.
package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/idp"
	"github.com/zero-day-ai/gibson/internal/secrets"

	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
	adminv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/admin/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// TenantConfigStoreReader is the narrow contract this handler uses to read
// the current persisted config. The production wiring is *secrets.ConfigStore.
type TenantConfigStoreReader interface {
	Get(ctx context.Context, tenant auth.TenantID) (secrets.BrokerConfig, error)
}

// TenantConfigStoreWriter is the narrow contract used by SetBrokerConfig.
// It is implemented by *secrets.ConfigStore.Set in production.
type TenantConfigStoreWriter interface {
	Set(ctx context.Context, tenant auth.TenantID, cfg secrets.BrokerConfig, actor string) error
}

// ProviderProbeFactory constructs a candidate provider from a JSON config
// blob and returns the SecretsBroker so the handler can call Probe. The
// production wiring delegates to secrets.Registry's per-provider factories.
type ProviderProbeFactory interface {
	// Construct builds a candidate provider for one provider name. Returns
	// an error when the provider name is unknown or the config blob fails
	// validation.
	Construct(provider string, configBlob []byte) (sdksecrets.Broker, error)
}

// Reloader invalidates the per-tenant cached SecretsBroker so the next
// Resolve/Put/Delete/List call rebuilds it from the just-persisted config
// row. Production wiring is *secrets.Registry; tests inject a fake.
//
// The signature mirrors *secrets.Registry.Reload exactly so the production
// type satisfies the interface implicitly. Reload is best-effort — a
// failure does not fail SetBrokerConfig because the next Registry.For
// call rebuilds the cache from the persisted row regardless.
type Reloader interface {
	Reload(ctx context.Context, tenant auth.TenantID)
}

// SecretsLister returns the names of all secrets stored in the tenant's
// active broker. Used only by CountSecrets, which projects len(names).
// Production wiring is *secrets.Service; the signature matches
// secrets.Service.List exactly.
type SecretsLister interface {
	List(ctx context.Context, filter sdksecrets.Filter) ([]string, error)
}

// ReservedNamesProvider returns the (exact, prefix) denylist used by the
// GetReservedNames handler. The production wiring is
// *reservednames.Provider; tests inject a fake. The interface is satisfied
// by any type with a ReservedNames(ctx) ([]string, []string, error) method.
type ReservedNamesProvider interface {
	ReservedNames(ctx context.Context) (exact, prefix []string, err error)
}

// TenantAdminServer implements adminv1.TenantAdminServiceServer.
type TenantAdminServer struct {
	adminv1.UnimplementedTenantAdminServiceServer

	reader        TenantConfigStoreReader
	writer        TenantConfigStoreWriter
	probeFac      ProviderProbeFactory
	auditor       BootstrapTokenAuditor
	reloader      Reloader
	svc           SecretsLister
	now           func() time.Time
	authorizer    authz.Authorizer      // optional; ListMembers returns empty when nil
	idpClient     idp.AdminClient       // optional; members have empty display_name/email when nil
	reservedNames ReservedNamesProvider // optional; GetReservedNames returns empty when nil
	logger        *slog.Logger
}

// TenantAdminConfig groups the constructor's required dependencies.
type TenantAdminConfig struct {
	Reader         TenantConfigStoreReader
	Writer         TenantConfigStoreWriter
	ProbeFactory   ProviderProbeFactory
	Auditor        BootstrapTokenAuditor
	Reloader       Reloader
	SecretsService SecretsLister
	Now            func() time.Time
	// Authorizer is optional. When nil, ListMembers returns an empty list.
	Authorizer authz.Authorizer
	// IdPAdminClient is optional. When nil, display_name and email fields are
	// left empty in ListMembers responses.
	IdPAdminClient idp.AdminClient
	// ReservedNames is optional. When nil, GetReservedNames returns empty lists.
	ReservedNames ReservedNamesProvider
	// Logger is optional; falls back to slog.Default() when nil.
	Logger *slog.Logger
}

// NewTenantAdminServer constructs a TenantAdminServer. Reader, Writer,
// ProbeFactory, Auditor, Reloader, SecretsService are required.
// Authorizer, IdPAdminClient, and Logger are optional.
func NewTenantAdminServer(cfg TenantAdminConfig) (*TenantAdminServer, error) {
	if cfg.Reader == nil {
		return nil, errors.New("tenant admin: Reader is required")
	}
	if cfg.Writer == nil {
		return nil, errors.New("tenant admin: Writer is required")
	}
	if cfg.ProbeFactory == nil {
		return nil, errors.New("tenant admin: ProbeFactory is required")
	}
	if cfg.Auditor == nil {
		return nil, errors.New("tenant admin: Auditor is required")
	}
	if cfg.Reloader == nil {
		return nil, errors.New("tenant admin: Reloader is required")
	}
	if cfg.SecretsService == nil {
		return nil, errors.New("tenant admin: SecretsService is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &TenantAdminServer{
		reader:        cfg.Reader,
		writer:        cfg.Writer,
		probeFac:      cfg.ProbeFactory,
		auditor:       cfg.Auditor,
		reloader:      cfg.Reloader,
		svc:           cfg.SecretsService,
		now:           now,
		authorizer:    cfg.Authorizer,
		idpClient:     cfg.IdPAdminClient,
		reservedNames: cfg.ReservedNames,
		logger:        logger,
	}, nil
}

// ---------------------------------------------------------------------------
// TenantAdminService RPC implementations
// ---------------------------------------------------------------------------

// GetBrokerConfig returns the redacted current configuration. Sensitive
// fields are NEVER returned.
func (s *TenantAdminServer) GetBrokerConfig(ctx context.Context, _ *adminv1.GetBrokerConfigRequest) (*adminv1.GetBrokerConfigResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	cfg, err := s.reader.Get(ctx, tenant)
	if err != nil {
		if errors.Is(err, secrets.ErrBrokerConfigNotFound) {
			return &adminv1.GetBrokerConfigResponse{Configured: false}, nil
		}
		return nil, status.Errorf(codes.Internal, "read broker config: %v", err)
	}

	redacted, err := redactConfig(cfg.Provider, cfg.ConfigBlob)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "redact: %v", err)
	}
	return &adminv1.GetBrokerConfigResponse{
		Config:     redacted,
		Configured: true,
	}, nil
}

// ProbeBrokerConfig tests a candidate config without persisting.
func (s *TenantAdminServer) ProbeBrokerConfig(ctx context.Context, req *adminv1.ProbeBrokerConfigRequest) (*adminv1.ProbeBrokerConfigResponse, error) {
	if _, ok := auth.TenantFromContext(ctx); !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetCandidate() == nil {
		return nil, status.Error(codes.InvalidArgument, "candidate is required")
	}

	providerName, blob, err := candidateToBlob(req.GetCandidate())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "encode candidate: %v", err)
	}

	start := s.now()
	probeRes := s.probeOnce(ctx, providerName, blob)
	probeRes.DurationMs = time.Since(start).Milliseconds()
	return &adminv1.ProbeBrokerConfigResponse{Result: probeRes}, nil
}

// SetBrokerConfig probes then persists.
func (s *TenantAdminServer) SetBrokerConfig(ctx context.Context, req *adminv1.SetBrokerConfigRequest) (*adminv1.SetBrokerConfigResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetCandidate() == nil {
		return nil, status.Error(codes.InvalidArgument, "candidate is required")
	}
	identity, _ := auth.IdentityFromContext(ctx)

	providerName, blob, err := candidateToBlob(req.GetCandidate())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "encode candidate: %v", err)
	}

	// Probe first.
	start := s.now()
	probeRes := s.probeOnce(ctx, providerName, blob)
	probeRes.DurationMs = time.Since(start).Milliseconds()
	if !probeRes.GetOk() {
		// Return PreconditionFailed with the structured probe result.
		return &adminv1.SetBrokerConfigResponse{ProbeResult: probeRes},
			status.Errorf(codes.FailedPrecondition, "probe failed: %s", probeRes.GetErrorClass())
	}

	// Persist on probe success.
	if err := s.writer.Set(ctx, tenant, secrets.BrokerConfig{
		Provider:   providerName,
		ConfigBlob: blob,
	}, identity.Subject); err != nil {
		return nil, status.Errorf(codes.Internal, "persist broker config: %v", err)
	}

	// Invalidate the per-tenant cached SecretsBroker so the next
	// Resolve/Put/Delete/List call rebuilds it from the just-persisted row.
	// Without this, in-flight callers keep hitting the previously-cached
	// provider until the daemon restarts.
	s.reloader.Reload(ctx, tenant)

	// Audit the change as tenant_secrets_backend_configured.
	s.auditor.Audit(ctx, secrets.AuditEvent{
		ActorID:       identity.Subject,
		ActorTenantID: tenant.String(),
		Action:        "tenant_secrets_backend_configured",
		Effect:        secrets.EffectAllow,
		ResourceType:  "secret_broker_config",
		ResourceURI:   fmt.Sprintf("secret_broker_config:tenant-%s", tenant),
		Decision:      "allow",
		Success:       true,
		OccurredAt:    s.now().UTC(),
	})

	// Build the redacted view of what was saved.
	redacted, err := redactConfig(providerName, blob)
	if err != nil {
		// Persistence succeeded; redaction read-back failed. Return
		// success with a minimal redacted view.
		redacted = &adminv1.RedactedConfig{
			Provider:      candidateProvider(req.GetCandidate()),
			UpdatedAtUnix: s.now().UTC().Unix(),
			UpdatedBy:     identity.Subject,
		}
	}
	return &adminv1.SetBrokerConfigResponse{
		Config:      redacted,
		ProbeResult: probeRes,
	}, nil
}

// CountSecrets returns the number of secrets currently stored in the
// tenant's active broker. The response carries no names, values, or
// per-row metadata — only an integer count. Used by the dashboard to gate
// the migration-warning UX when switching providers (Spec
// tenant-secrets-broker-completion R3).
//
// No dedicated audit event is emitted here; the underlying
// secrets.Service.List path already audits via the existing AuditWriter
// pipeline. Double-auditing on a count surface would inflate the audit
// stream for an essentially-free read.
func (s *TenantAdminServer) CountSecrets(ctx context.Context, _ *adminv1.CountSecretsRequest) (*adminv1.CountSecretsResponse, error) {
	if _, ok := auth.TenantFromContext(ctx); !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	names, err := s.svc.List(ctx, sdksecrets.Filter{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list secrets: %v", err)
	}
	return &adminv1.CountSecretsResponse{Count: int64(len(names))}, nil
}

// ListMembers enumerates the members of the caller's tenant. It:
//  1. Queries OpenFGA for all user references with the "member" relation on
//     the tenant object.
//  2. Batch-checks which of those users also have the "admin" relation.
//  3. Enriches each entry with display_name and email from the IdP.
//  4. Applies name_filter (case-insensitive prefix on display_name or email).
//  5. Sorts by display_name, applies offset-based pagination via a
//     base64-encoded integer page_token.
//
// When the authorizer is nil (not wired), an empty list is returned.
// When the IdP client is nil, members are returned with empty display_name
// and email fields.
func (s *TenantAdminServer) ListMembers(ctx context.Context, req *adminv1.ListMembersRequest) (*adminv1.ListMembersResponse, error) {
	if _, ok := auth.TenantFromContext(ctx); !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	tenant, _ := auth.TenantFromContext(ctx)

	if s.authorizer == nil {
		s.logger.WarnContext(ctx, "ListMembers: authorizer not wired; returning empty list")
		return &adminv1.ListMembersResponse{}, nil
	}

	// 1. List all users with the "member" relation on this tenant.
	tenantObject := "tenant:" + tenant.String()
	userRefs, err := s.authorizer.ListUsers(ctx, "tenant", tenantObject, "member")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list tenant members from FGA: %v", err)
	}

	if len(userRefs) == 0 {
		return &adminv1.ListMembersResponse{}, nil
	}

	// 2. Batch-check which users are also admins.
	adminChecks := make([]authz.CheckRequest, len(userRefs))
	for i, ref := range userRefs {
		adminChecks[i] = authz.CheckRequest{
			User:     ref,
			Relation: "admin",
			Object:   tenantObject,
		}
	}
	isAdmin, err := s.authorizer.BatchCheck(ctx, adminChecks)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "batch-check admin roles from FGA: %v", err)
	}

	// 3. Build member structs enriched from the IdP.
	members := make([]*adminv1.TenantMember, 0, len(userRefs))
	for i, ref := range userRefs {
		// FGA user refs have the form "user:<id>".
		userID := strings.TrimPrefix(ref, "user:")

		role := "member"
		if isAdmin[i] {
			role = "admin"
		}

		m := &adminv1.TenantMember{
			UserId: userID,
			Role:   role,
		}

		if s.idpClient != nil {
			profile, profileErr := s.idpClient.GetUserProfile(ctx, userID)
			if profileErr != nil {
				// Non-fatal: log and continue without IdP data for this user.
				s.logger.WarnContext(ctx, "ListMembers: GetUserProfile failed",
					slog.String("user_id", userID),
					slog.String("error", profileErr.Error()))
			} else {
				m.DisplayName = profile.DisplayName
				m.Email = profile.Email
			}
		}

		members = append(members, m)
	}

	// 4. Apply name_filter (case-insensitive prefix on display_name or email).
	if filter := req.GetNameFilter(); filter != "" {
		filtered := members[:0]
		for _, m := range members {
			if hasPrefixFold(m.GetDisplayName(), filter) || hasPrefixFold(m.GetEmail(), filter) {
				filtered = append(filtered, m)
			}
		}
		members = filtered
	}

	// 5. Sort by display_name (fall back to user_id for stable ordering).
	sort.Slice(members, func(i, j int) bool {
		ni := members[i].GetDisplayName()
		if ni == "" {
			ni = members[i].GetUserId()
		}
		nj := members[j].GetDisplayName()
		if nj == "" {
			nj = members[j].GetUserId()
		}
		return ni < nj
	})

	// Decode page_token as a base64-encoded decimal offset.
	offset := 0
	if tok := req.GetPageToken(); tok != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(tok)
		if decErr == nil {
			if n, parseErr := strconv.Atoi(string(decoded)); parseErr == nil && n >= 0 {
				offset = n
			}
		}
	}

	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = 50 // server-chosen default
	}

	if offset >= len(members) {
		return &adminv1.ListMembersResponse{}, nil
	}

	end := offset + pageSize
	var nextToken string
	if end < len(members) {
		nextToken = base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(end)))
		members = members[offset:end]
	} else {
		members = members[offset:]
	}

	return &adminv1.ListMembersResponse{
		Members:       members,
		NextPageToken: nextToken,
	}, nil
}

// hasPrefixFold reports whether s has prefix p, case-insensitively.
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// probeOnce constructs a candidate provider and probes it. Result.Ok is
// true on success.
func (s *TenantAdminServer) probeOnce(ctx context.Context, providerName string, blob []byte) *adminv1.ProbeResult {
	candidate, err := s.probeFac.Construct(providerName, blob)
	if err != nil {
		return &adminv1.ProbeResult{
			Ok:           false,
			ErrorClass:   "provider_construct_failed",
			ErrorMessage: redactProbeMessage(err.Error()),
		}
	}
	if err := candidate.Probe(ctx); err != nil {
		return &adminv1.ProbeResult{
			Ok:           false,
			ErrorClass:   classifyProbeError(err),
			ErrorMessage: redactProbeMessage(err.Error()),
		}
	}
	return &adminv1.ProbeResult{Ok: true}
}

// candidateProvider returns the provider name for a candidate without
// converting to the canonical lowercase string. Used in fallback paths.
func candidateProvider(c *adminv1.CandidateConfig) adminv1.BrokerProvider {
	if c == nil {
		return adminv1.BrokerProvider_BROKER_PROVIDER_UNSPECIFIED
	}
	return c.GetProvider()
}

// candidateToBlob converts a CandidateConfig into the (provider_name,
// configBlob) shape the secrets package expects. configBlob is JSON. The
// shape is provider-specific; we use a generic dictionary the production
// factories also accept (the same blob shape Spec 1 task 19 documents).
func candidateToBlob(c *adminv1.CandidateConfig) (string, []byte, error) {
	providerName := providerEnumToString(c.GetProvider())
	if providerName == "" {
		return "", nil, errors.New("unknown provider")
	}

	// Build a generic dict carrying every non-zero field. Provider
	// factories pluck the keys they care about.
	dict := map[string]any{
		"provider": providerName,
	}
	if c.GetAddress() != "" {
		dict["address"] = c.GetAddress()
	}
	if c.GetNamespaceOrPath() != "" {
		dict["namespace_or_path"] = c.GetNamespaceOrPath()
	}
	if c.GetMount() != "" {
		dict["mount"] = c.GetMount()
	}
	if c.GetAuthMethod() != "" {
		dict["auth_method"] = c.GetAuthMethod()
	}
	if c.GetRegion() != "" {
		dict["region"] = c.GetRegion()
	}
	if c.GetProject() != "" {
		dict["project"] = c.GetProject()
	}
	if c.GetTenantIdExternal() != "" {
		dict["tenant_id_external"] = c.GetTenantIdExternal()
	}
	if c.GetClientId() != "" {
		dict["client_id"] = c.GetClientId()
	}
	if c.GetRoleArn() != "" {
		dict["role_arn"] = c.GetRoleArn()
	}
	if len(c.GetVaultToken()) > 0 {
		dict["vault_token"] = string(c.GetVaultToken())
	}
	if c.GetApproleRoleId() != "" {
		dict["approle_role_id"] = c.GetApproleRoleId()
	}
	if len(c.GetApproleSecretId()) > 0 {
		dict["approle_secret_id"] = string(c.GetApproleSecretId())
	}
	if len(c.GetAwsAccessKeyId()) > 0 {
		dict["aws_access_key_id"] = string(c.GetAwsAccessKeyId())
	}
	if len(c.GetAwsSecretAccessKey()) > 0 {
		dict["aws_secret_access_key"] = string(c.GetAwsSecretAccessKey())
	}
	if len(c.GetAwsExternalId()) > 0 {
		dict["aws_external_id"] = string(c.GetAwsExternalId())
	}
	if len(c.GetGcpServiceAccountJson()) > 0 {
		dict["gcp_service_account_json"] = string(c.GetGcpServiceAccountJson())
	}
	if len(c.GetAzureClientSecret()) > 0 {
		dict["azure_client_secret"] = string(c.GetAzureClientSecret())
	}

	blob, err := json.Marshal(dict)
	if err != nil {
		return "", nil, err
	}
	return providerName, blob, nil
}

// redactConfig parses a stored config blob and emits a RedactedConfig with
// every sensitive field stripped. The sensitive_fields_set list records
// which sensitive fields were present so the dashboard can render
// "(configured)" placeholders.
func redactConfig(providerName string, blob []byte) (*adminv1.RedactedConfig, error) {
	dict := map[string]any{}
	if len(blob) > 0 {
		if err := json.Unmarshal(blob, &dict); err != nil {
			return nil, fmt.Errorf("config blob not valid JSON: %w", err)
		}
	}

	out := &adminv1.RedactedConfig{
		Provider:         providerStringToEnum(providerName),
		Address:          stringField(dict, "address"),
		NamespaceOrPath:  stringField(dict, "namespace_or_path"),
		Mount:            stringField(dict, "mount"),
		AuthMethod:       stringField(dict, "auth_method"),
		Region:           stringField(dict, "region"),
		Project:          stringField(dict, "project"),
		TenantIdExternal: stringField(dict, "tenant_id_external"),
		ClientId:         stringField(dict, "client_id"),
		RoleArn:          stringField(dict, "role_arn"),
	}

	for _, sk := range sensitiveKeys {
		if v, ok := dict[sk]; ok {
			if s, isStr := v.(string); isStr && s == "" {
				continue
			}
			out.SensitiveFieldsSet = append(out.SensitiveFieldsSet, sk)
		}
	}

	return out, nil
}

// sensitiveKeys is the set of config keys whose values must never appear in
// a redacted response.
var sensitiveKeys = []string{
	"vault_token",
	"approle_secret_id",
	"aws_access_key_id",
	"aws_secret_access_key",
	"aws_external_id",
	"gcp_service_account_json",
	"azure_client_secret",
}

// stringField returns dict[key] as a string, or "" when missing or
// not-a-string.
func stringField(dict map[string]any, key string) string {
	v, ok := dict[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// providerEnumToString maps the proto enum to the registry string name.
// Returns "" for UNSPECIFIED.
func providerEnumToString(p adminv1.BrokerProvider) string {
	switch p {
	case adminv1.BrokerProvider_BROKER_PROVIDER_POSTGRES:
		return "postgres"
	case adminv1.BrokerProvider_BROKER_PROVIDER_VAULT:
		return "vault"
	case adminv1.BrokerProvider_BROKER_PROVIDER_AWSSM:
		return "awssm"
	case adminv1.BrokerProvider_BROKER_PROVIDER_GCPSM:
		return "gcpsm"
	case adminv1.BrokerProvider_BROKER_PROVIDER_AZUREKV:
		return "azurekv"
	default:
		return ""
	}
}

// providerStringToEnum maps the registry string name back to the proto
// enum. Returns UNSPECIFIED for unknown values.
func providerStringToEnum(s string) adminv1.BrokerProvider {
	switch s {
	case "postgres":
		return adminv1.BrokerProvider_BROKER_PROVIDER_POSTGRES
	case "vault":
		return adminv1.BrokerProvider_BROKER_PROVIDER_VAULT
	case "awssm":
		return adminv1.BrokerProvider_BROKER_PROVIDER_AWSSM
	case "gcpsm":
		return adminv1.BrokerProvider_BROKER_PROVIDER_GCPSM
	case "azurekv":
		return adminv1.BrokerProvider_BROKER_PROVIDER_AZUREKV
	default:
		return adminv1.BrokerProvider_BROKER_PROVIDER_UNSPECIFIED
	}
}

// classifyProbeError maps a probe error to a structured class for the
// dashboard UI. The categories are best-effort string matching against
// known error messages from the SDK secrets providers.
func classifyProbeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case containsAny(msg, "unauthorized", "permission denied", "authentication", "auth_failed"):
		return "auth_failed"
	case containsAny(msg, "connection refused", "no such host", "timeout", "unreachable"):
		return "network_unreachable"
	case containsAny(msg, "mount", "path"):
		return "mount_path_invalid"
	default:
		return "internal"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if indexFold(s, sub) >= 0 {
			return true
		}
	}
	return false
}

// indexFold is a simple case-insensitive substring search.
func indexFold(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 || n < m {
		if m == 0 {
			return 0
		}
		return -1
	}
	for i := 0; i+m <= n; i++ {
		if foldEqual(s[i:i+m], sub) {
			return i
		}
	}
	return -1
}

func foldEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// redactProbeMessage scrubs likely-secret substrings from a probe error
// message so the dashboard displays a useful diagnostic without leaking
// the candidate's auth credentials. We strip any token-shaped substring
// (32+ alphanumeric / dot / dash characters) — heuristic but effective
// for Vault tokens, AWS keys, GCP SA JSON nested values.
func redactProbeMessage(msg string) string {
	out := []byte(msg)
	const minTokenLen = 24
	tokenStart := -1
	for i, c := range out {
		isTok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
		if isTok {
			if tokenStart < 0 {
				tokenStart = i
			}
		} else {
			if tokenStart >= 0 && i-tokenStart >= minTokenLen {
				for j := tokenStart; j < i; j++ {
					out[j] = '*'
				}
			}
			tokenStart = -1
		}
	}
	if tokenStart >= 0 && len(out)-tokenStart >= minTokenLen {
		for j := tokenStart; j < len(out); j++ {
			out[j] = '*'
		}
	}
	return string(out)
}
