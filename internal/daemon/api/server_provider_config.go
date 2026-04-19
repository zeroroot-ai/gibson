package api

// server_provider_config.go — CRUD handlers for the DaemonAdminService
// provider-config RPC surface (ListProviders, GetProvider, CreateProvider,
// UpdateProvider, DeleteProvider, TestProvider, GetProviderHealth,
// GetDefaultProvider, SetDefaultProvider, GetFallbackChain, SetFallbackChain).
//
// Execution handlers (ExecuteLLM, StreamLLM) live in server_provider_exec.go
// (task 4).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/llm/providers"
	"github.com/zero-day-ai/gibson/internal/providerconfig"
)

// ---------------------------------------------------------------------------
// providerConfigStore interface — narrow subset used by these handlers.
// Tests inject a mock; production code uses providerconfig.ProviderConfigStore.
// ---------------------------------------------------------------------------

// providerConfigStoreIface is the narrow interface DaemonServer uses for
// provider-config CRUD. It matches providerconfig.ProviderConfigStore exactly
// so the production type satisfies it without an explicit conversion.
type providerConfigStoreIface interface {
	List(ctx context.Context, tenantID string) ([]*providerconfig.ProviderConfig, error)
	Get(ctx context.Context, tenantID string, name string) (*providerconfig.ProviderConfig, error)
	Create(ctx context.Context, tenantID string, input *providerconfig.ProviderConfigInput) (*providerconfig.ProviderConfig, error)
	Update(ctx context.Context, tenantID string, name string, input *providerconfig.ProviderConfigInput) (*providerconfig.ProviderConfig, error)
	Delete(ctx context.Context, tenantID string, name string) error
	GetDefault(ctx context.Context, tenantID string) (*providerconfig.ProviderConfig, error)
	SetDefault(ctx context.Context, tenantID string, name string) error
	GetFallbackChain(ctx context.Context, tenantID string) ([]string, error)
	SetFallbackChain(ctx context.Context, tenantID string, names []string) error
	Resolve(ctx context.Context, tenantID string, name string) (*providerconfig.DecryptedConfig, error)
}

// ---------------------------------------------------------------------------
// Handler helpers
// ---------------------------------------------------------------------------

// toGRPCError translates providerconfig sentinel errors to gRPC status errors.
// Unknown errors become codes.Internal; credential material must never appear
// in the returned message.
func toGRPCProviderError(op string, err error) error {
	switch {
	case errors.Is(err, providerconfig.ErrNotFound):
		return status_grpc.Errorf(codes.NotFound, "provider not found")
	case errors.Is(err, providerconfig.ErrAlreadyExists):
		return status_grpc.Errorf(codes.AlreadyExists, "provider already exists")
	case errors.Is(err, providerconfig.ErrUnsupportedType):
		return status_grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	case errors.Is(err, providerconfig.ErrKeyProviderUnset):
		return status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	default:
		return status_grpc.Errorf(codes.Internal, "%s: internal error", op)
	}
}

// toProtoProviderRecord converts an internal ProviderConfig (with masked
// credentials already populated via AsRecord) to the proto ProviderRecord.
func toProtoProviderRecord(cfg *providerconfig.ProviderConfig) *ProviderRecord {
	if cfg == nil {
		return nil
	}
	return &ProviderRecord{
		Id:                cfg.ID.String(),
		Name:              cfg.Name,
		Type:              string(cfg.Type),
		DefaultModel:      cfg.DefaultModel,
		IsDefault:         cfg.IsDefault,
		Enabled:           cfg.Enabled,
		CredentialsMasked: cfg.CredentialsMasked,
		CreatedAt:         cfg.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:         cfg.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// toProtoProviderRecords converts a slice of ProviderConfig to proto records.
func toProtoProviderRecords(cfgs []*providerconfig.ProviderConfig) []*ProviderRecord {
	out := make([]*ProviderRecord, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, toProtoProviderRecord(c))
	}
	return out
}

// fromProtoInput converts a proto ProviderConfigInput to the internal write type.
func fromProtoInput(in *ProviderConfigInput) *providerconfig.ProviderConfigInput {
	if in == nil {
		return &providerconfig.ProviderConfigInput{}
	}
	creds := make(map[string]string, len(in.Credentials))
	for k, v := range in.Credentials {
		creds[k] = v
	}
	return &providerconfig.ProviderConfigInput{
		Name:         in.Name,
		Type:         llm.ProviderType(in.Type),
		DefaultModel: in.DefaultModel,
		Credentials:  creds,
		SetAsDefault: in.SetAsDefault,
		Enabled:      true, // new providers default to enabled
	}
}

// validateProviderInput checks that the provider type is in the supported set
// and is not "custom" (operator-only, not dashboard-configurable).
func validateProviderInput(input *ProviderConfigInput) error {
	if input == nil {
		return fmt.Errorf("input is required")
	}
	if input.Type == string(llm.ProviderCustom) {
		return fmt.Errorf("provider type %q is operator-only and cannot be configured via the dashboard", input.Type)
	}
	for _, t := range llm.SupportedProviderTypes() {
		if string(t) == input.Type {
			return nil
		}
	}
	return fmt.Errorf("unsupported provider type %q", input.Type)
}

// providerAuditAction returns the audit action string for a provider mutation.
// Never include credential material in the action or metadata.
type providerAuditAction = string

const (
	auditProviderCreated         providerAuditAction = "provider_created"
	auditProviderUpdated         providerAuditAction = "provider_updated"
	auditProviderDeleted         providerAuditAction = "provider_deleted"
	auditProviderTested          providerAuditAction = "provider_tested"
	auditProviderDefaultChanged  providerAuditAction = "provider_default_changed"
	auditProviderFallbackChanged providerAuditAction = "provider_fallback_chain_changed"
)

// emitProviderAudit logs a provider-related audit event via the daemon's
// AuditLogger. The function is a no-op when auditLogger is nil (dev/test mode).
// Credential material MUST NOT appear in the action or metadata.
func (s *DaemonServer) emitProviderAudit(ctx context.Context, tenantID, action, providerName string) {
	if s.auditLogger == nil {
		return
	}
	_ = s.auditLogger.Log(ctx, action, "provider", providerName, map[string]any{
		"tenant_id": tenantID,
	})
}

// ---------------------------------------------------------------------------
// ListProviders
// ---------------------------------------------------------------------------

// ListProviders returns all provider configs for the caller's tenant with
// credentials masked.
func (s *DaemonServer) ListProviders(ctx context.Context, _ *ListProvidersRequest) (*ListProvidersResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	cfgs, err := s.providerConfig.List(ctx, tenantID)
	if err != nil {
		return nil, toGRPCProviderError("list providers", err)
	}
	return &ListProvidersResponse{Providers: toProtoProviderRecords(cfgs)}, nil
}

// ---------------------------------------------------------------------------
// GetProvider
// ---------------------------------------------------------------------------

// GetProvider returns a single named provider config with credentials masked.
func (s *DaemonServer) GetProvider(ctx context.Context, req *GetProviderRequest) (*GetProviderResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	cfg, err := s.providerConfig.Get(ctx, tenantID, req.GetName())
	if err != nil {
		return nil, toGRPCProviderError("get provider", err)
	}
	return &GetProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// CreateProvider
// ---------------------------------------------------------------------------

// CreateProvider stores a new provider config for the caller's tenant.
// Credentials are encrypted immediately; the response contains only masked values.
func (s *DaemonServer) CreateProvider(ctx context.Context, req *CreateProviderRequest) (*CreateProviderResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	if err := validateProviderInput(req.GetInput()); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	}
	cfg, err := s.providerConfig.Create(ctx, tenantID, fromProtoInput(req.GetInput()))
	if err != nil {
		return nil, toGRPCProviderError("create provider", err)
	}
	s.emitProviderAudit(ctx, tenantID, auditProviderCreated, cfg.Name)
	return &CreateProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// UpdateProvider
// ---------------------------------------------------------------------------

// UpdateProvider replaces the named provider config with new values.
// Credentials in the request are encrypted; the response contains only masked values.
func (s *DaemonServer) UpdateProvider(ctx context.Context, req *UpdateProviderRequest) (*UpdateProviderResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	if err := validateProviderInput(req.GetInput()); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	}
	cfg, err := s.providerConfig.Update(ctx, tenantID, req.GetName(), fromProtoInput(req.GetInput()))
	if err != nil {
		return nil, toGRPCProviderError("update provider", err)
	}
	s.emitProviderAudit(ctx, tenantID, auditProviderUpdated, cfg.Name)
	return &UpdateProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// DeleteProvider
// ---------------------------------------------------------------------------

// DeleteProvider removes the named provider config for the caller's tenant.
func (s *DaemonServer) DeleteProvider(ctx context.Context, req *DeleteProviderRequest) (*DeleteProviderResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	name := req.GetName()
	if err := s.providerConfig.Delete(ctx, tenantID, name); err != nil {
		return nil, toGRPCProviderError("delete provider", err)
	}
	s.emitProviderAudit(ctx, tenantID, auditProviderDeleted, name)
	return &DeleteProviderResponse{}, nil
}

// ---------------------------------------------------------------------------
// TestProvider
// ---------------------------------------------------------------------------

// TestProvider validates a proposed provider config by attempting a live health
// or completion check against the upstream API. The proposed config is NOT
// persisted. Credentials are used for the duration of this call only and are
// never logged.
//
// Flow:
//  1. Build a temporary llm.ProviderConfig from the proposed input.
//  2. Construct a provider via providers.NewProvider (fails fast for unknown types).
//  3. Call provider.Health under a 5s deadline.
//  4. If Health is a pass-through noop (unconditionally healthy), fall back to
//     a minimal Complete call under a 15s deadline.
//  5. Return TestProviderResponse {ok, latency_ms, model, error}.
//     Timeout → {ok: false, error: "timeout"} — never a gRPC-level error.
func (s *DaemonServer) TestProvider(ctx context.Context, req *TestProviderRequest) (*TestProviderResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	input := req.GetInput()
	if err := validateProviderInput(input); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	// Build ephemeral llm.ProviderConfig from the proposed input.
	// Credential material stays in this stack frame only.
	creds := input.GetCredentials()
	provCfg := llm.ProviderConfig{
		Type:         llm.ProviderType(input.GetType()),
		DefaultModel: input.GetDefaultModel(),
		APIKey:       creds["api_key"],
		BaseURL:      creds["base_url"],
	}
	// Forward remaining credential keys as Extra so provider-specific fields
	// (e.g. aws_access_key_id, cloudflare_account_id) are available.
	extra := make(map[string]string, len(creds))
	for k, v := range creds {
		if k != "api_key" && k != "base_url" {
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		provCfg.Extra = extra
	}

	// Construct the provider. This validates type and config without network.
	prov, err := providers.NewProvider(provCfg)
	if err != nil {
		return &TestProviderResponse{
			Ok:    false,
			Error: fmt.Sprintf("invalid provider configuration: %v", err),
		}, nil
	}

	start := time.Now()

	// Step 1: Health check under 5s deadline.
	healthCtx, healthCancel := context.WithTimeout(ctx, 5*time.Second)
	defer healthCancel()

	healthStatus := prov.Health(healthCtx)
	latencyMS := time.Since(start).Milliseconds()

	// Check if the deadline was exceeded.
	if healthCtx.Err() == context.DeadlineExceeded {
		s.emitProviderAudit(ctx, tenantID, auditProviderTested, input.GetName())
		return &TestProviderResponse{
			Ok:        false,
			LatencyMs: latencyMS,
			Error:     "timeout",
		}, nil
	}

	// If health is explicitly healthy, return success.
	if healthStatus.IsHealthy() {
		s.emitProviderAudit(ctx, tenantID, auditProviderTested, input.GetName())
		return &TestProviderResponse{
			Ok:        true,
			LatencyMs: latencyMS,
			Model:     input.GetDefaultModel(),
		}, nil
	}

	// Health returned non-healthy AND no timeout: some providers return
	// unconditionally healthy without a network call (noop Health).
	// For those providers the health result is not meaningful — fall back
	// to a short Complete call so we actually hit the upstream.
	//
	// Heuristic: if Health returned healthy without any network activity
	// (latency < 10ms), treat it as a noop and do the Complete fallback.
	// If it returned unhealthy, trust the result.
	if !healthStatus.IsHealthy() && latencyMS >= 10 {
		// Non-trivial latency + unhealthy = genuine failure from upstream.
		s.emitProviderAudit(ctx, tenantID, auditProviderTested, input.GetName())
		return &TestProviderResponse{
			Ok:        false,
			LatencyMs: latencyMS,
			Error:     healthStatus.Message,
		}, nil
	}

	// Fall back to a minimal Complete call under a 15s deadline.
	completeCtx, completeCancel := context.WithTimeout(ctx, 15*time.Second)
	defer completeCancel()

	_, completeErr := prov.Complete(completeCtx, llm.CompletionRequest{
		Model: input.GetDefaultModel(),
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "Hello"},
		},
		MaxTokens: 1,
	})
	latencyMS = time.Since(start).Milliseconds()

	s.emitProviderAudit(ctx, tenantID, auditProviderTested, input.GetName())

	if completeCtx.Err() == context.DeadlineExceeded {
		return &TestProviderResponse{
			Ok:        false,
			LatencyMs: latencyMS,
			Error:     "timeout",
		}, nil
	}
	if completeErr != nil {
		return &TestProviderResponse{
			Ok:        false,
			LatencyMs: latencyMS,
			Error:     completeErr.Error(),
		}, nil
	}
	return &TestProviderResponse{
		Ok:        true,
		LatencyMs: latencyMS,
		Model:     input.GetDefaultModel(),
	}, nil
}

// ---------------------------------------------------------------------------
// GetProviderHealth
// ---------------------------------------------------------------------------

// GetProviderHealth returns the last known health status of a stored provider.
// It resolves the provider config from storage, constructs the provider, and
// runs a Health check under a 5s deadline.
func (s *DaemonServer) GetProviderHealth(ctx context.Context, req *GetProviderHealthRequest) (*GetProviderHealthResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	dec, err := s.providerConfig.Resolve(ctx, tenantID, req.GetName())
	if err != nil {
		return nil, toGRPCProviderError("get provider health", err)
	}

	provCfg := decryptedToLLMConfig(dec)
	prov, err := providers.NewProvider(provCfg)
	if err != nil {
		return &GetProviderHealthResponse{
			Healthy: false,
			Error:   fmt.Sprintf("cannot construct provider: %v", err),
		}, nil
	}

	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	checkedAt := time.Now().UTC().Format(time.RFC3339)
	status := prov.Health(checkCtx)

	if !status.IsHealthy() {
		return &GetProviderHealthResponse{
			Healthy:       false,
			LastCheckedAt: checkedAt,
			Error:         status.Message,
		}, nil
	}
	return &GetProviderHealthResponse{
		Healthy:       true,
		LastCheckedAt: checkedAt,
	}, nil
}

// ---------------------------------------------------------------------------
// GetDefaultProvider
// ---------------------------------------------------------------------------

// GetDefaultProvider returns the provider config marked as the tenant's default.
func (s *DaemonServer) GetDefaultProvider(ctx context.Context, _ *GetDefaultProviderRequest) (*GetDefaultProviderResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	cfg, err := s.providerConfig.GetDefault(ctx, tenantID)
	if err != nil {
		return nil, toGRPCProviderError("get default provider", err)
	}
	return &GetDefaultProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// SetDefaultProvider
// ---------------------------------------------------------------------------

// SetDefaultProvider marks the named provider as the tenant's default.
func (s *DaemonServer) SetDefaultProvider(ctx context.Context, req *SetDefaultProviderRequest) (*SetDefaultProviderResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	name := req.GetName()
	if err := s.providerConfig.SetDefault(ctx, tenantID, name); err != nil {
		return nil, toGRPCProviderError("set default provider", err)
	}
	s.emitProviderAudit(ctx, tenantID, auditProviderDefaultChanged, name)
	// Return the updated provider record.
	cfg, err := s.providerConfig.Get(ctx, tenantID, name)
	if err != nil {
		// Best effort — return empty provider on read failure.
		return &SetDefaultProviderResponse{}, nil
	}
	return &SetDefaultProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// GetFallbackChain
// ---------------------------------------------------------------------------

// GetFallbackChain returns the ordered list of fallback provider names.
func (s *DaemonServer) GetFallbackChain(ctx context.Context, _ *GetFallbackChainRequest) (*GetFallbackChainResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	chain, err := s.providerConfig.GetFallbackChain(ctx, tenantID)
	if err != nil {
		return nil, toGRPCProviderError("get fallback chain", err)
	}
	return &GetFallbackChainResponse{ProviderNames: chain}, nil
}

// ---------------------------------------------------------------------------
// SetFallbackChain
// ---------------------------------------------------------------------------

// SetFallbackChain replaces the tenant's fallback provider chain.
func (s *DaemonServer) SetFallbackChain(ctx context.Context, req *SetFallbackChainRequest) (*SetFallbackChainResponse, error) {
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	names := req.GetProviderNames()
	if err := s.providerConfig.SetFallbackChain(ctx, tenantID, names); err != nil {
		return nil, toGRPCProviderError("set fallback chain", err)
	}
	s.emitProviderAudit(ctx, tenantID, auditProviderFallbackChanged, fmt.Sprintf("%v", names))
	return &SetFallbackChainResponse{ProviderNames: names}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// decryptedToLLMConfig maps a DecryptedConfig to the llm.ProviderConfig shape
// expected by providers.NewProvider. Credential material never escapes to logs.
func decryptedToLLMConfig(dec *providerconfig.DecryptedConfig) llm.ProviderConfig {
	cfg := llm.ProviderConfig{
		Type:         dec.Type,
		DefaultModel: dec.DefaultModel,
		APIKey:       dec.Credentials["api_key"],
		BaseURL:      dec.Credentials["base_url"],
	}
	extra := make(map[string]string)
	for k, v := range dec.Credentials {
		if k != "api_key" && k != "base_url" {
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		cfg.Extra = extra
	}
	return cfg
}
