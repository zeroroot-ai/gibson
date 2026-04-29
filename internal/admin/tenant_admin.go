// Package admin — tenant_admin.go
//
// TenantAdminServer implements gibson.admin.v1.TenantAdminService — the
// dashboard's tenant-admin surface for broker configuration. Pairs with
// secrets_admin.go (secrets), plugin_admin.go (plugin installs), and
// grants_admin.go (capability grants).
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
// SECURITY: sensitive auth fields (Vault token, AWS keys, GCP SA JSON,
// Azure client secret) are write-only from the dashboard's perspective.
// They flow inbound on Set/Probe; they NEVER appear in any read response.
//
// Spec: secrets-tenant-lifecycle Requirement 8.1, Requirement 3.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/secrets"

	adminv1 "github.com/zero-day-ai/sdk/api/gen/gibson/admin/v1"
	"github.com/zero-day-ai/sdk/auth"
	sdksecrets "github.com/zero-day-ai/sdk/secrets"
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
	Construct(provider string, configBlob []byte) (sdksecrets.SecretsBroker, error)
}

// TenantAdminServer implements adminv1.TenantAdminServiceServer.
type TenantAdminServer struct {
	adminv1.UnimplementedTenantAdminServiceServer

	reader   TenantConfigStoreReader
	writer   TenantConfigStoreWriter
	probeFac ProviderProbeFactory
	auditor  BootstrapTokenAuditor
	now      func() time.Time
}

// TenantAdminConfig groups the constructor's required dependencies.
type TenantAdminConfig struct {
	Reader        TenantConfigStoreReader
	Writer        TenantConfigStoreWriter
	ProbeFactory  ProviderProbeFactory
	Auditor       BootstrapTokenAuditor
	Now           func() time.Time
}

// NewTenantAdminServer constructs a TenantAdminServer. Reader, Writer,
// ProbeFactory, Auditor are required.
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
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &TenantAdminServer{
		reader:   cfg.Reader,
		writer:   cfg.Writer,
		probeFac: cfg.ProbeFactory,
		auditor:  cfg.Auditor,
		now:      now,
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
		Provider:          providerStringToEnum(providerName),
		Address:           stringField(dict, "address"),
		NamespaceOrPath:   stringField(dict, "namespace_or_path"),
		Mount:             stringField(dict, "mount"),
		AuthMethod:        stringField(dict, "auth_method"),
		Region:            stringField(dict, "region"),
		Project:           stringField(dict, "project"),
		TenantIdExternal:  stringField(dict, "tenant_id_external"),
		ClientId:          stringField(dict, "client_id"),
		RoleArn:           stringField(dict, "role_arn"),
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
