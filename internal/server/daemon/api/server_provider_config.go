package api

// server_provider_config.go — CRUD handlers for TenantAdminService
// provider-config RPC surface (ListProviders, GetProvider, CreateProvider,
// UpdateProvider, DeleteProvider, TestProvider, GetProviderHealth,
// GetDefaultProvider, SetDefaultProvider).
//
// Execution handlers (ExecuteLLM, StreamLLM) live in server_provider_exec.go
// (task 4).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/providers"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
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
		slog.Default().Error("providerconfig op failed", "op", op, "error", err)
		return status_grpc.Errorf(codes.Internal, "%s: internal error", op)
	}
}

// toProtoProviderRecord converts an internal ProviderConfig (with masked
// credentials already populated via AsRecord) to the proto ProviderRecord.
func toProtoProviderRecord(cfg *providerconfig.ProviderConfig) *tenantv1.ProviderRecord {
	if cfg == nil {
		return nil
	}
	return &tenantv1.ProviderRecord{
		Id:                    cfg.ID.String(),
		Name:                  cfg.Name,
		Type:                  string(cfg.Type),
		DefaultModel:          cfg.DefaultModel,
		IsDefault:             cfg.IsDefault,
		Enabled:               cfg.Enabled,
		Capabilities:          capabilitiesToProto(cfg.Capabilities),
		DefaultEmbeddingModel: cfg.DefaultEmbeddingModel,
		CredentialsMasked:     cfg.CredentialsMasked,
		CreatedAt:             cfg.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:             cfg.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// capabilityToString maps a proto Capability enum to the lower-cased string the
// providerconfig model stores. CAPABILITY_UNSPECIFIED and unknown values are
// dropped.
func capabilityToString(c tenantv1.Capability) (string, bool) {
	switch c {
	case tenantv1.Capability_CAPABILITY_CHAT:
		return providerconfig.CapabilityChat, true
	case tenantv1.Capability_CAPABILITY_EMBEDDING:
		return providerconfig.CapabilityEmbedding, true
	default:
		return "", false
	}
}

// stringToCapability maps a stored capability string back to its proto enum.
func stringToCapability(s string) (tenantv1.Capability, bool) {
	switch s {
	case providerconfig.CapabilityChat:
		return tenantv1.Capability_CAPABILITY_CHAT, true
	case providerconfig.CapabilityEmbedding:
		return tenantv1.Capability_CAPABILITY_EMBEDDING, true
	default:
		return tenantv1.Capability_CAPABILITY_UNSPECIFIED, false
	}
}

// capabilitiesFromProto converts a proto capability slice to the model's
// lower-cased string slice, dropping unspecified/unknown values.
func capabilitiesFromProto(caps []tenantv1.Capability) []string {
	if len(caps) == 0 {
		return nil
	}
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		if s, ok := capabilityToString(c); ok {
			out = append(out, s)
		}
	}
	return out
}

// capabilitiesToProto converts the model's capability strings to proto enums,
// dropping unknown values.
func capabilitiesToProto(caps []string) []tenantv1.Capability {
	if len(caps) == 0 {
		return nil
	}
	out := make([]tenantv1.Capability, 0, len(caps))
	for _, s := range caps {
		if c, ok := stringToCapability(s); ok {
			out = append(out, c)
		}
	}
	return out
}

// toProtoProviderRecords converts a slice of ProviderConfig to proto records.
func toProtoProviderRecords(cfgs []*providerconfig.ProviderConfig) []*tenantv1.ProviderRecord {
	out := make([]*tenantv1.ProviderRecord, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, toProtoProviderRecord(c))
	}
	return out
}

// fromProtoInput converts a proto ProviderConfigInput to the internal write type.
func fromProtoInput(in *tenantv1.ProviderConfigInput) *providerconfig.ProviderConfigInput {
	if in == nil {
		return &providerconfig.ProviderConfigInput{}
	}
	creds := make(map[string]string, len(in.Credentials))
	for k, v := range in.Credentials {
		creds[k] = v
	}
	return &providerconfig.ProviderConfigInput{
		Name:                  in.Name,
		Type:                  llm.ProviderType(in.Type),
		DefaultModel:          in.DefaultModel,
		Capabilities:          capabilitiesFromProto(in.Capabilities),
		DefaultEmbeddingModel: in.DefaultEmbeddingModel,
		Credentials:           creds,
		SetAsDefault:          in.SetAsDefault,
		Enabled:               true, // new providers default to enabled
	}
}

// validateProviderInput checks that the provider type is in the supported set
// and is not "custom" (operator-only, not dashboard-configurable), and that an
// embedding-capable provider declares a model whose vector dimension is known.
func validateProviderInput(input *tenantv1.ProviderConfigInput) error {
	if input == nil {
		return fmt.Errorf("input is required")
	}
	if input.Type == string(llm.ProviderCustom) {
		return fmt.Errorf("provider type %q is operator-only and cannot be configured via the dashboard", input.Type)
	}
	supported := false
	for _, t := range llm.SupportedProviderTypes() {
		if string(t) == input.Type {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("unsupported provider type %q", input.Type)
	}
	return validateEmbeddingCapability(input)
}

// validateEmbeddingCapability fails closed when a provider declares the
// embedding capability but does not carry a default_embedding_model whose vector
// dimension is known (E11 BYO-embedder, gibson#810). A wrong/unknown dimension
// would silently fail RediSearch indexing of the whole document
// ([[project_redisearch_json_indexing_type_mismatch]]), so the unknown-model
// case is rejected at write time rather than discovered at index time.
func validateEmbeddingCapability(input *tenantv1.ProviderConfigInput) error {
	servesEmbedding := false
	for _, c := range input.Capabilities {
		if c == tenantv1.Capability_CAPABILITY_EMBEDDING {
			servesEmbedding = true
			break
		}
	}
	if !servesEmbedding {
		return nil
	}
	model := strings.TrimSpace(input.DefaultEmbeddingModel)
	if model == "" {
		return fmt.Errorf("provider declares the embedding capability but has no default_embedding_model")
	}
	if _, ok := embedder.DimensionForModel(model); !ok {
		return fmt.Errorf("embedding model %q has no known vector dimension — the index dimension cannot be derived; configure a supported embedding model", model)
	}
	return nil
}

// providerAuditAction returns the audit action string for a provider mutation.
// Never include credential material in the action or metadata.
type providerAuditAction = string

const (
	auditProviderCreated        providerAuditAction = "provider_created"
	auditProviderUpdated        providerAuditAction = "provider_updated"
	auditProviderDeleted        providerAuditAction = "provider_deleted"
	auditProviderTested         providerAuditAction = "provider_tested"
	auditProviderDefaultChanged providerAuditAction = "provider_default_changed"
)

// emitProviderAudit logs a provider-related audit event via the daemon's
// AuditLogger. The function is a no-op when auditLogger is nil (dev/test mode).
// Credential material MUST NOT appear in the action or metadata.
func (s *DaemonServer) emitProviderAudit(ctx context.Context, tenantID, action, providerName string) {
	if s.auditLogger == nil {
		return
	}
	s.auditLogger.Log(ctx, action, "provider", providerName, map[string]any{
		"tenant_id": tenantID,
	})
}

// ---------------------------------------------------------------------------
// ListProviders
// ---------------------------------------------------------------------------

// ListProviders returns all provider configs for the caller's tenant with
// credentials masked.
func (s *DaemonServer) ListProviders(ctx context.Context, _ *tenantv1.ListProvidersRequest) (*tenantv1.ListProvidersResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
	return &tenantv1.ListProvidersResponse{Providers: toProtoProviderRecords(cfgs)}, nil
}

// ---------------------------------------------------------------------------
// GetProvider
// ---------------------------------------------------------------------------

// GetProvider returns a single named provider config with credentials masked.
func (s *DaemonServer) GetProvider(ctx context.Context, req *tenantv1.GetProviderRequest) (*tenantv1.GetProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
	return &tenantv1.GetProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// CreateProvider
// ---------------------------------------------------------------------------

// CreateProvider stores a new provider config for the caller's tenant.
// Credentials are encrypted immediately; the response contains only masked values.
func (s *DaemonServer) CreateProvider(ctx context.Context, req *tenantv1.CreateProviderRequest) (*tenantv1.CreateProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
	s.invalidateEmbedderCache(tenantID)
	s.emitProviderAudit(ctx, tenantID, auditProviderCreated, cfg.Name)
	return &tenantv1.CreateProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// invalidateEmbedderCache drops the per-tenant embedder cache after a
// provider-config mutation so the next vector operation resolves the tenant's
// current embedding provider (e.g. a tenant that just configured one clears the
// onboarding gate; a tenant that switched embedding models picks up the new
// dimension). nil-safe when no resolver is wired.
func (s *DaemonServer) invalidateEmbedderCache(tenantID string) {
	if s.embedderResolver != nil {
		s.embedderResolver.Invalidate(tenantID)
	}
}

// ---------------------------------------------------------------------------
// UpdateProvider
// ---------------------------------------------------------------------------

// UpdateProvider replaces the named provider config with new values.
// Credentials in the request are encrypted; the response contains only masked values.
func (s *DaemonServer) UpdateProvider(ctx context.Context, req *tenantv1.UpdateProviderRequest) (*tenantv1.UpdateProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
	s.invalidateEmbedderCache(tenantID)
	s.emitProviderAudit(ctx, tenantID, auditProviderUpdated, cfg.Name)
	return &tenantv1.UpdateProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// DeleteProvider
// ---------------------------------------------------------------------------

// DeleteProvider removes the named provider config for the caller's tenant.
func (s *DaemonServer) DeleteProvider(ctx context.Context, req *tenantv1.DeleteProviderRequest) (*tenantv1.DeleteProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
	s.invalidateEmbedderCache(tenantID)
	s.emitProviderAudit(ctx, tenantID, auditProviderDeleted, name)
	return &tenantv1.DeleteProviderResponse{}, nil
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
func (s *DaemonServer) TestProvider(ctx context.Context, req *tenantv1.TestProviderRequest) (*tenantv1.TestProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
		return &tenantv1.TestProviderResponse{
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
		return &tenantv1.TestProviderResponse{
			Ok:        false,
			LatencyMs: latencyMS,
			Error:     "timeout",
		}, nil
	}

	// If health is explicitly healthy, return success — and try to surface the
	// live model catalogue so the dashboard's wizard can populate its model
	// picker without a second round-trip. Spec: providers-wizard. Models() is
	// best-effort: providers that don't expose a list endpoint return an empty
	// slice or an error; the test still passes either way.
	if healthStatus.IsHealthy() {
		s.emitProviderAudit(ctx, tenantID, auditProviderTested, input.GetName())
		var modelList []llm.ModelInfo
		modelsCtx, modelsCancel := context.WithTimeout(ctx, 10*time.Second)
		modelList, _ = prov.Models(modelsCtx)
		modelsCancel()
		return &tenantv1.TestProviderResponse{
			Ok:        true,
			LatencyMs: latencyMS,
			Model:     input.GetDefaultModel(),
			Models:    modelsToProto(modelList),
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
		return &tenantv1.TestProviderResponse{
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
		return &tenantv1.TestProviderResponse{
			Ok:        false,
			LatencyMs: latencyMS,
			Error:     "timeout",
		}, nil
	}
	if completeErr != nil {
		return &tenantv1.TestProviderResponse{
			Ok:        false,
			LatencyMs: latencyMS,
			Error:     completeErr.Error(),
		}, nil
	}
	// Best-effort live model fetch on the Complete-fallback success path —
	// same rationale as the Health-success branch above.
	var modelList []llm.ModelInfo
	modelsCtx, modelsCancel := context.WithTimeout(ctx, 10*time.Second)
	modelList, _ = prov.Models(modelsCtx)
	modelsCancel()
	return &tenantv1.TestProviderResponse{
		Ok:        true,
		LatencyMs: latencyMS,
		Model:     input.GetDefaultModel(),
		Models:    modelsToProto(modelList),
	}, nil
}

// ---------------------------------------------------------------------------
// GetProviderHealth
// ---------------------------------------------------------------------------

// GetProviderHealth returns the last known health status of a stored provider.
// It resolves the provider config from storage, constructs the provider, and
// runs a Health check under a 5s deadline.
func (s *DaemonServer) GetProviderHealth(ctx context.Context, req *tenantv1.GetProviderHealthRequest) (*tenantv1.GetProviderHealthResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
		return &tenantv1.GetProviderHealthResponse{
			Healthy: false,
			Error:   fmt.Sprintf("cannot construct provider: %v", err),
		}, nil
	}

	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	checkedAt := time.Now().UTC().Format(time.RFC3339)
	status := prov.Health(checkCtx)

	if !status.IsHealthy() {
		return &tenantv1.GetProviderHealthResponse{
			Healthy:       false,
			LastCheckedAt: checkedAt,
			Error:         status.Message,
		}, nil
	}
	return &tenantv1.GetProviderHealthResponse{
		Healthy:       true,
		LastCheckedAt: checkedAt,
	}, nil
}

// ---------------------------------------------------------------------------
// GetDefaultProvider
// ---------------------------------------------------------------------------

// GetDefaultProvider returns the provider config marked as the tenant's default.
func (s *DaemonServer) GetDefaultProvider(ctx context.Context, _ *tenantv1.GetDefaultProviderRequest) (*tenantv1.GetDefaultProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
	return &tenantv1.GetDefaultProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// SetDefaultProvider
// ---------------------------------------------------------------------------

// SetDefaultProvider marks the named provider as the tenant's default.
func (s *DaemonServer) SetDefaultProvider(ctx context.Context, req *tenantv1.SetDefaultProviderRequest) (*tenantv1.SetDefaultProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
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
	s.invalidateEmbedderCache(tenantID)
	s.emitProviderAudit(ctx, tenantID, auditProviderDefaultChanged, name)
	// Return the updated provider record.
	cfg, err := s.providerConfig.Get(ctx, tenantID, name)
	if err != nil {
		// Best effort — return empty provider on read failure.
		return &tenantv1.SetDefaultProviderResponse{}, nil
	}
	return &tenantv1.SetDefaultProviderResponse{Provider: toProtoProviderRecord(cfg)}, nil
}

// ---------------------------------------------------------------------------
// Provider catalogue (spec: providers-wizard)
// ---------------------------------------------------------------------------

// GetSupportedProviders returns the daemon's static catalogue of LLM provider
// types in the same deterministic order as llm.SupportedProviderTypes(). No
// tenant context required at the data layer (the catalogue is process-wide),
// but the auth interceptor still asserts tenant membership so unauthenticated
// callers can't enumerate the surface.
func (s *DaemonServer) GetSupportedProviders(ctx context.Context, _ *tenantv1.GetSupportedProvidersRequest) (*tenantv1.GetSupportedProvidersResponse, error) {
	if auth.TenantStringFromContext(ctx) == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	descriptors := providers.SupportedProviderDescriptors()
	out := make([]*tenantv1.SupportedProvider, 0, len(descriptors))
	for _, d := range descriptors {
		out = append(out, descriptorToProto(d))
	}
	return &tenantv1.GetSupportedProvidersResponse{Providers: out}, nil
}

// ListProviderModels fetches the live model catalogue for an already-stored
// provider config — credentials are read from the encrypted store; the caller
// does not pass them. Mirrors TestProvider's "construct + call" pattern but
// against a persisted record. Spec: providers-wizard.
func (s *DaemonServer) ListProviderModels(ctx context.Context, req *tenantv1.ListProviderModelsRequest) (*tenantv1.ListProviderModelsResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	name := req.GetName()
	if name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "name is required")
	}

	// Decrypt the stored config via the store's Resolve helper. The decrypted
	// credential map lives only on this goroutine's stack — we never log it or
	// persist it.
	dec, err := s.providerConfig.Resolve(ctx, tenantID, name)
	if err != nil {
		return nil, toGRPCProviderError("resolve provider", err)
	}
	provCfg := decryptedToLLMConfig(dec)

	prov, err := providers.NewProvider(provCfg)
	if err != nil {
		return &tenantv1.ListProviderModelsResponse{
			Ok:           false,
			ErrorMessage: fmt.Sprintf("invalid provider configuration: %v", err),
			ErrorClass:   "invalid_argument",
		}, nil
	}

	// Bound the upstream call so a hung provider doesn't pin the gRPC handler.
	modelsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	start := time.Now()
	models, mErr := prov.Models(modelsCtx)
	latency := time.Since(start).Milliseconds()
	if mErr != nil {
		return &tenantv1.ListProviderModelsResponse{
			Ok:           false,
			ErrorMessage: mErr.Error(),
			ErrorClass:   classifyProviderError(mErr),
			LatencyMs:    latency,
		}, nil
	}
	return &tenantv1.ListProviderModelsResponse{
		Ok:        true,
		Models:    modelsToProto(models),
		LatencyMs: latency,
	}, nil
}

// descriptorToProto translates the in-Go ProviderDescriptor to its proto
// equivalent. Kept narrow on purpose: this is the only place the two shapes
// touch each other.
func descriptorToProto(d providers.ProviderDescriptor) *tenantv1.SupportedProvider {
	creds := make([]*tenantv1.CredentialField, 0, len(d.Credentials))
	for _, c := range d.Credentials {
		creds = append(creds, &tenantv1.CredentialField{
			Key:         c.Key,
			Label:       c.Label,
			Required:    c.Required,
			Secret:      c.Secret,
			Placeholder: c.Placeholder,
			Help:        c.Help,
		})
	}
	return &tenantv1.SupportedProvider{
		Type:          string(d.Type),
		DisplayName:   d.DisplayName,
		DocsUrl:       d.DocsURL,
		SelfHosted:    d.SelfHosted,
		Credentials:   creds,
		DefaultModels: modelsToProto(d.DefaultModels),
	}
}

// modelsToProto translates llm.ModelInfo entries into the proto shape used
// by both ProbeProvider/TestProvider and ListProviderModels.
func modelsToProto(models []llm.ModelInfo) []*tenantv1.ModelDescriptor {
	out := make([]*tenantv1.ModelDescriptor, 0, len(models))
	for _, m := range models {
		out = append(out, &tenantv1.ModelDescriptor{
			Name:          m.Name,
			ContextWindow: int32(m.ContextWindow), //nolint:gosec // model context windows are at most ~10M
		})
	}
	return out
}

// classifyProviderError translates a provider-side error into a stable
// error_class string the dashboard can dispatch on. Keep the set tight —
// add new classes only when the dashboard wants different UX for them.
func classifyProviderError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case containsAny(msg, "invalid_api_key", "401", "unauthorized", "authentication"):
		return "auth_failed"
	case containsAny(msg, "rate", "429", "quota"):
		return "rate_limited"
	case containsAny(msg, "timeout", "deadline"):
		return "timeout"
	case containsAny(msg, "dial", "connection refused", "no such host", "network"):
		return "network"
	default:
		return "unknown"
	}
}

func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
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
