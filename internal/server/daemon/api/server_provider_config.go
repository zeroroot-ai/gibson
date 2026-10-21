// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	case errors.Is(err, providerconfig.ErrInvalidCredentials):
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
		Name:                      in.Name,
		Type:                      llm.ProviderType(in.Type),
		DefaultModel:              in.DefaultModel,
		DefaultModelContextWindow: int(in.DefaultModelContextWindow),
		Capabilities:              capabilitiesFromProto(in.Capabilities),
		DefaultEmbeddingModel:     in.DefaultEmbeddingModel,
		Credentials:               creds,
		SetAsDefault:              in.SetAsDefault,
		Enabled:                   true, // new providers default to enabled
	}
}

// validateProviderInput checks that the provider type is in the supported set,
// is not "custom" (operator-only, not dashboard-configurable), and that
// embedding-capable providers declare a model with a known vector dimension.
// Embedding-only types (voyage, openai-compatible, tei) must declare
// CAPABILITY_EMBEDDING and cannot be used as chat-only providers.
func validateProviderInput(input *tenantv1.ProviderConfigInput) error {
	if input == nil {
		return fmt.Errorf("input is required")
	}
	if input.Type == string(llm.ProviderCustom) {
		return fmt.Errorf("provider type %q is operator-only and cannot be configured via the dashboard", input.Type)
	}
	supported := false
	for _, t := range llm.AcceptedProviderTypes() {
		if string(t) == input.Type {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("unsupported provider type %q", input.Type)
	}
	// Embedding-only provider types cannot serve chat completions. They must
	// declare CAPABILITY_EMBEDDING (and may not declare CAPABILITY_CHAT).
	embeddingOnly := input.Type == string(llm.ProviderVoyage) ||
		input.Type == string(llm.ProviderOpenAICompatible) ||
		input.Type == string(llm.ProviderTEI)
	if embeddingOnly {
		hasEmbedding := false
		for _, c := range input.Capabilities {
			if c == tenantv1.Capability_CAPABILITY_EMBEDDING {
				hasEmbedding = true
			}
		}
		if !hasEmbedding {
			return fmt.Errorf("provider type %q is embedding-only and must declare the embedding capability", input.Type)
		}
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
// AuditLogger. The audit logger is required: the daemon wires it at start.
// Credential material MUST NOT appear in the action or metadata.
func (s *DaemonServer) emitProviderAudit(ctx context.Context, tenantID, action, providerName string) {
	s.auditLogger.Log(ctx, action, "provider", providerName, map[string]any{
		"tenant_id": tenantID,
	})
}

// recordProviderAudit writes the audit record of a provider change durably,
// BEFORE the change takes effect. The change fails when the record cannot be
// written, so no provider change exists without its record (gibson#676).
func (s *DaemonServer) recordProviderAudit(ctx context.Context, tenantID, action, providerName string) error {
	if _, err := s.auditLogger.Record(ctx, action, "provider", providerName, map[string]any{
		"tenant_id": tenantID,
	}); err != nil {
		s.logger.Error("provider audit: durable write failed", "action", action, "error", err.Error())
		return fmt.Errorf("provider audit %s: %w", action, err)
	}
	return nil
}

// recordProviderFailure records that a provider change failed after its
// audit record was written.
func (s *DaemonServer) recordProviderFailure(ctx context.Context, tenantID, action, providerName string) {
	if s.auditLogger != nil {
		s.auditLogger.LogWithResult(ctx, action, "provider", providerName, "failure", map[string]any{
			"tenant_id": tenantID,
		})
	}
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
	if err := s.fillDefaultModelWindow(ctx, req.GetInput(), nil); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	}
	if err := s.recordProviderAudit(ctx, tenantID, auditProviderCreated, req.GetInput().GetName()); err != nil {
		return nil, status_grpc.Error(codes.Unavailable, "the audit record of the provider change could not be written; nothing changed")
	}
	cfg, err := s.providerConfig.Create(ctx, tenantID, fromProtoInput(req.GetInput()))
	if err != nil {
		s.recordProviderFailure(ctx, tenantID, auditProviderCreated, req.GetInput().GetName())
		return nil, toGRPCProviderError("create provider", err)
	}
	s.invalidateEmbedderCache(tenantID)
	// Reconcile the tenant's vector index against its new embedding config when
	// this provider serves embeddings (gibson#940). Async + idempotent: a no-op
	// when the index marker already matches.
	s.maybeTriggerReembed(tenantID, req.GetInput())
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
	existing, err := s.providerConfig.Get(ctx, tenantID, req.GetName())
	if err != nil {
		return nil, toGRPCProviderError("update provider", err)
	}
	if err := s.fillDefaultModelWindow(ctx, req.GetInput(), existing); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	}
	if err := s.recordProviderAudit(ctx, tenantID, auditProviderUpdated, req.GetName()); err != nil {
		return nil, status_grpc.Error(codes.Unavailable, "the audit record of the provider change could not be written; nothing changed")
	}
	cfg, err := s.providerConfig.Update(ctx, tenantID, req.GetName(), fromProtoInput(req.GetInput()))
	if err != nil {
		s.recordProviderFailure(ctx, tenantID, auditProviderUpdated, req.GetName())
		return nil, toGRPCProviderError("update provider", err)
	}
	s.invalidateEmbedderCache(tenantID)
	// Reconcile the tenant's vector index against its (possibly changed) embedding
	// config when this provider serves embeddings (gibson#940). Async + idempotent.
	s.maybeTriggerReembed(tenantID, req.GetInput())
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
	if err := s.recordProviderAudit(ctx, tenantID, auditProviderDeleted, name); err != nil {
		return nil, status_grpc.Error(codes.Unavailable, "the audit record of the provider change could not be written; nothing changed")
	}
	if err := s.providerConfig.Delete(ctx, tenantID, name); err != nil {
		s.recordProviderFailure(ctx, tenantID, auditProviderDeleted, name)
		return nil, toGRPCProviderError("delete provider", err)
	}
	s.invalidateEmbedderCache(tenantID)
	return &tenantv1.DeleteProviderResponse{}, nil
}

// ---------------------------------------------------------------------------
// TestProvider
// ---------------------------------------------------------------------------

// providerFromInput builds a transient provider from the credentials and the
// default model of a proposed config. Nothing is persisted and no network call
// is made.
func (s *DaemonServer) providerFromInput(input *tenantv1.ProviderConfigInput) (llm.LLMProvider, error) {
	creds := input.GetCredentials()
	provCfg := s.withEgressPolicy(llm.ProviderConfig{
		Type:         llm.ProviderType(input.GetType()),
		DefaultModel: input.GetDefaultModel(),
		APIKey:       creds["api_key"],
		BaseURL:      creds["base_url"],
	})
	// Forward the remaining credential keys as Extra so provider-specific
	// fields (aws_access_key_id, cloudflare_account_id, ...) reach the provider.
	extra := make(map[string]string, len(creds))
	for k, v := range creds {
		if k != "api_key" && k != "base_url" {
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		provCfg.Extra = extra
	}
	factory := s.providerFactory
	if factory == nil {
		factory = providers.NewProvider
	}
	return factory(provCfg)
}

// isEmbeddingOnlyType reports whether the provider type serves embeddings only.
func isEmbeddingOnlyType(t llm.ProviderType) bool {
	return t == llm.ProviderVoyage || t == llm.ProviderOpenAICompatible || t == llm.ProviderTEI
}

// servesChat reports whether a proposed config serves chat: it declares the
// chat capability, or it declares none (the legacy chat-only default) and is
// not an embedding-only type.
func servesChat(input *tenantv1.ProviderConfigInput) bool {
	if isEmbeddingOnlyType(llm.ProviderType(input.GetType())) {
		return false
	}
	if len(input.GetCapabilities()) == 0 {
		return true
	}
	for _, c := range input.GetCapabilities() {
		if c == tenantv1.Capability_CAPABILITY_CHAT {
			return true
		}
	}
	return false
}

// maxContextWindow bounds a stated context window, in tokens.
const maxContextWindow = 10_000_000

// listedWindow asks the live model list of the provider for the window of the
// model. It reports the window (0 when the list names the model but reports no
// window), whether the list named the model, and the error of the list call.
func (s *DaemonServer) listedWindow(ctx context.Context, input *tenantv1.ProviderConfigInput, model string) (window int, named bool, err error) {
	prov, err := s.providerFromInput(input)
	if err != nil {
		return 0, false, fmt.Errorf("the provider could not be built (%w)", err)
	}
	listCtx, cancel := context.WithTimeout(ctx, providerCheckTimeout)
	defer cancel()
	models, err := prov.Models(listCtx)
	if err != nil {
		return 0, false, fmt.Errorf("the model list of the provider failed (%w)", err)
	}
	for _, m := range models {
		if m.Name == model {
			if m.ContextWindowUnreported {
				return 0, true, nil
			}
			return m.ContextWindow, true, nil
		}
	}
	return 0, false, nil
}

// fillDefaultModelWindow stores the context window with the saved model. The
// daemon never guesses a window and no mission reads a model list, so the
// window is fixed here, at save time:
//  1. a window the caller states must be in 1..maxContextWindow. When the live
//     list reports a window for the model, the stated one must equal it;
//  2. else an update that keeps the same model keeps the stored window and makes
//     no list call, so a rename or a key rotation works during a list outage;
//  3. else the window that the live list reports for default_model is used;
//  4. else the save is refused, and the message tells the caller to state it.
//
// existing is the stored config on an update, and nil on a create. A config that
// serves no chat, or names no default model, has no window to fix.
func (s *DaemonServer) fillDefaultModelWindow(ctx context.Context, input *tenantv1.ProviderConfigInput, existing *providerconfig.ProviderConfig) error {
	model := strings.TrimSpace(input.GetDefaultModel())
	if model == "" || !servesChat(input) {
		return nil
	}
	refuse := func(cause string) error {
		return fmt.Errorf("the context window of model %q is unknown: %s. State it in default_model_context_window", model, cause)
	}

	if stated := input.GetDefaultModelContextWindow(); stated != 0 {
		if stated < 1 || stated > maxContextWindow {
			return fmt.Errorf("default_model_context_window %d is out of range: it must be 1 to %d tokens", stated, maxContextWindow)
		}
		if listed, named, err := s.listedWindow(ctx, input, model); err == nil && named && listed > 0 && listed != int(stated) {
			return fmt.Errorf("default_model_context_window %d does not match the %d tokens that the provider reports for model %q",
				stated, listed, model)
		}
		return nil
	}

	unchanged := existing != nil && existing.DefaultModel == model && string(existing.Type) == input.GetType()
	if unchanged && existing.DefaultModelContextWindow > 0 {
		input.DefaultModelContextWindow = int32(existing.DefaultModelContextWindow) //nolint:gosec // bounded by maxContextWindow at save
		return nil
	}

	listed, named, err := s.listedWindow(ctx, input, model)
	switch {
	case err == nil && listed > 0:
		input.DefaultModelContextWindow = int32(listed) //nolint:gosec // a context window is at most ~10M tokens
		return nil
	case unchanged:
		// A provider saved before the window was stored: fill it when the list
		// can, and keep saving when it cannot. Nothing is refused for an edit
		// that does not touch the model.
		return nil
	case err != nil:
		return refuse(err.Error())
	case named:
		return refuse("the provider does not report a context window for it")
	default:
		return refuse("the provider does not list it")
	}
}

// TestProvider validates a proposed provider config by calling the model list
// endpoint of the provider with the proposed credentials. The call needs no
// model ID and sends no completion. The proposed config is NOT persisted.
// Credentials are used for the duration of this call only and are never
// logged. A provider with no list call is checked with a one-token completion
// against default_model.
//
// Flow:
//  1. Build a temporary llm.ProviderConfig from the proposed input.
//  2. For embedding-only providers (voyage, openai-compatible, tei): skip the
//     chat probe and run only the embedding probe (step 5).
//  3. For chat-capable providers: construct a provider via providers.NewProvider
//     and call provider.Models under a 10s deadline.
//  4. A success gives ok=true and the live models. A failure gives ok=false and
//     the error text of the provider.
//  5. If the input declares CAPABILITY_EMBEDDING and default_embedding_model is
//     set, call embedder.NewFromProvider and EmbedBatch(["ping"]) under a 10s
//     deadline. The embedding result (ok + dimension + error) is attached to the
//     response; a failure does not negate a successful chat probe.
//  6. Return TestProviderResponse {ok, latency_ms, model, error, embedding_ok,
//     embedding_dimension, embedding_error}.
//     A failure is never a gRPC-level error.
func (s *DaemonServer) TestProvider(ctx context.Context, req *tenantv1.TestProviderRequest) (*tenantv1.TestProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	input := req.GetInput()
	if err := validateProviderInput(input); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	provType := llm.ProviderType(input.GetType())
	embeddingOnly := provType == llm.ProviderVoyage ||
		provType == llm.ProviderOpenAICompatible ||
		provType == llm.ProviderTEI

	start := time.Now()

	var (
		chatOK    bool
		modelList []llm.ModelInfo
		latencyMS int64
	)

	if !embeddingOnly {
		// Build the ephemeral provider from the proposed input. Credential
		// material stays in this stack frame only. This validates type and
		// config without network, and routes through s.providerFactory so
		// tests can inject a stub.
		prov, err := s.providerFromInput(input)
		if err != nil {
			return &tenantv1.TestProviderResponse{
				Ok:    false,
				Error: fmt.Sprintf("invalid provider configuration: %v", err),
			}, nil
		}

		// The credential check is the model list call of the provider. It
		// sends no completion and needs no model ID.
		models, listErr := checkProviderCredentials(ctx, prov, input.GetDefaultModel())
		latencyMS = time.Since(start).Milliseconds()
		if listErr != nil {
			s.emitProviderAudit(ctx, tenantID, auditProviderTested, input.GetName())
			return &tenantv1.TestProviderResponse{
				Ok:        false,
				LatencyMs: latencyMS,
				Error:     listErr.Error(),
			}, nil
		}
		chatOK = true
		modelList = models
	}

	// Embedding probe: run when the provider declares CAPABILITY_EMBEDDING and
	// default_embedding_model is set, OR when it is an embedding-only provider.
	embeddingOK, embeddingDim, embeddingErr := s.probeEmbedding(ctx, input)
	latencyMS = time.Since(start).Milliseconds()

	s.emitProviderAudit(ctx, tenantID, auditProviderTested, input.GetName())

	// For embedding-only providers: ok=true iff the embedding probe passed.
	// For dual-capability or chat-only providers: ok=true iff chat passed.
	finalOK := chatOK
	if embeddingOnly {
		finalOK = embeddingOK
	}

	return &tenantv1.TestProviderResponse{
		Ok:                 finalOK,
		LatencyMs:          latencyMS,
		Model:              input.GetDefaultModel(),
		Models:             modelsToProto(modelList),
		EmbeddingOk:        embeddingOK,
		EmbeddingDimension: int32(embeddingDim), //nolint:gosec // dimension is always small positive int
		EmbeddingError:     embeddingErr,
	}, nil
}

// probeEmbedding runs a minimal embedding probe for the given input when it
// declares CAPABILITY_EMBEDDING and has a default_embedding_model set. It
// returns (ok, dimension, errorMessage). When no embedding probe is needed it
// returns (false, 0, "").
func (s *DaemonServer) probeEmbedding(ctx context.Context, input *tenantv1.ProviderConfigInput) (ok bool, dim int, errMsg string) {
	// Check if the provider declares the embedding capability.
	hasEmbedding := false
	for _, c := range input.GetCapabilities() {
		if c == tenantv1.Capability_CAPABILITY_EMBEDDING {
			hasEmbedding = true
			break
		}
	}
	// Also run for embedding-only provider types (voyage/openai-compatible/tei)
	// even if capabilities is empty (they are embedding-only by definition).
	provType := llm.ProviderType(input.GetType())
	embeddingOnly := provType == llm.ProviderVoyage ||
		provType == llm.ProviderOpenAICompatible ||
		provType == llm.ProviderTEI
	if !hasEmbedding && !embeddingOnly {
		return false, 0, ""
	}

	embModel := strings.TrimSpace(input.GetDefaultEmbeddingModel())
	if embModel == "" {
		return false, 0, ""
	}

	creds := input.GetCredentials()
	extra := make(map[string]string)
	for k, v := range creds {
		switch k {
		case "api_key", "base_url", "region":
		default:
			extra[k] = v
		}
	}
	embCfg := embedder.Config{
		Kind:    embedder.Kind(string(provType)),
		Model:   embModel,
		APIKey:  creds["api_key"],
		BaseURL: creds["base_url"],
		Region:  creds["region"],
		Extra:   extra,
	}

	factory := s.embedderFactory
	if factory == nil {
		factory = embedder.NewFromProvider
	}
	emb, err := factory(embCfg)
	if err != nil {
		return false, 0, fmt.Sprintf("failed to build embedder: %v", err)
	}

	embedCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	vecs, err := emb.EmbedBatch(embedCtx, []string{"ping"})
	if err != nil {
		if embedCtx.Err() == context.DeadlineExceeded {
			return false, 0, "embedding probe: timeout"
		}
		return false, 0, fmt.Sprintf("embedding probe failed: %v", err)
	}
	if len(vecs) == 0 || len(vecs[0]) == 0 {
		return false, 0, "embedding probe: empty vector returned"
	}
	return true, len(vecs[0]), ""
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

	provCfg := s.withEgressPolicy(decryptedToLLMConfig(dec))
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
	if err := s.recordProviderAudit(ctx, tenantID, auditProviderDefaultChanged, name); err != nil {
		return nil, status_grpc.Error(codes.Unavailable, "the audit record of the provider change could not be written; nothing changed")
	}
	if err := s.providerConfig.SetDefault(ctx, tenantID, name); err != nil {
		s.recordProviderFailure(ctx, tenantID, auditProviderDefaultChanged, name)
		return nil, toGRPCProviderError("set default provider", err)
	}
	s.invalidateEmbedderCache(tenantID)
	// Flipping the default provider can change which embedder the tenant resolves
	// (and thus the index dimension), so reconcile unconditionally (gibson#940).
	// Async + idempotent: a no-op when the resolved embedder still matches the marker.
	s.triggerReembed(tenantID)
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

// ---------------------------------------------------------------------------
// ProbeProvider
// ---------------------------------------------------------------------------

// ProbeProvider validates candidate provider credentials WITHOUT persisting them
// and returns the live model catalogue + (when requested) an embedding probe
// result. Used by the wizard's "Test connection" step.
//
// A provider with no list call (Foundry) is tested with a one-token completion
// against request.default_model, which that provider then requires.
//
// SECURITY: credentials transit memory only — they are passed to the transient
// provider client and embedding client, the calls are made, and the values are
// dropped when the request returns. They are never logged, never persisted, and
// never returned to the caller.
//
// Flow:
//  1. Build ephemeral configs from type + credentials.
//  2. For embedding-only providers (voyage, openai-compatible, tei): only run
//     the embedding probe (if default_embedding_model is set).
//  3. For chat-capable providers: call the model list endpoint of the provider
//     under a 10s deadline. It needs no model ID and sends no completion.
//  4. If default_embedding_model is set (on any provider type): also run the
//     embedding probe and attach embedding_dimension to the response.
//  5. Return ProbeProviderResponse {ok, error_message, error_class, models,
//     latency_ms, embedding_dimension}.
func (s *DaemonServer) ProbeProvider(ctx context.Context, req *tenantv1.ProbeProviderRequest) (*tenantv1.ProbeProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}

	provType := req.GetType()
	if provType == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "type is required")
	}

	// Validate against the known type list (reuse logic without a full input struct).
	supported := false
	for _, t := range llm.AcceptedProviderTypes() {
		if string(t) == provType {
			supported = true
			break
		}
	}
	if !supported {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "unsupported provider type %q", provType)
	}
	if provType == string(llm.ProviderCustom) {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "provider type %q is operator-only", provType)
	}

	creds := req.GetCredentials()
	embModel := strings.TrimSpace(req.GetDefaultEmbeddingModel())
	pt := llm.ProviderType(provType)
	embeddingOnly := pt == llm.ProviderVoyage ||
		pt == llm.ProviderOpenAICompatible ||
		pt == llm.ProviderTEI

	start := time.Now()

	if embeddingOnly {
		// Embedding-only provider: run embedding probe if a model is given.
		if embModel == "" {
			return &tenantv1.ProbeProviderResponse{
				Ok:           false,
				ErrorMessage: "default_embedding_model is required for embedding-only providers",
				ErrorClass:   "invalid_argument",
			}, nil
		}
		ok, dim, errMsg := s.probeEmbeddingFromCreds(ctx, pt, embModel, creds)
		latencyMS := time.Since(start).Milliseconds()
		if !ok {
			return &tenantv1.ProbeProviderResponse{
				Ok:           false,
				ErrorMessage: errMsg,
				ErrorClass:   classifyProviderError(errors.New(errMsg)),
				LatencyMs:    latencyMS,
			}, nil
		}
		return &tenantv1.ProbeProviderResponse{
			Ok:                 true,
			LatencyMs:          latencyMS,
			EmbeddingDimension: int32(dim), //nolint:gosec // dimension is always small positive int
		}, nil
	}

	// Chat-capable provider: delegate to probeChatProvider which handles
	// health + fallback Complete under appropriate deadlines.
	chatOK, chatErr, modelList, latencyMS := s.probeChatProvider(ctx, pt, creds, req.GetDefaultModel(), start)
	if !chatOK {
		return &tenantv1.ProbeProviderResponse{
			Ok:           false,
			ErrorMessage: chatErr,
			ErrorClass:   classifyProviderError(errors.New(chatErr)),
			LatencyMs:    latencyMS,
		}, nil
	}

	// Embedding probe (best-effort, does not affect ok when chat succeeded).
	var embeddingDim int
	if embModel != "" {
		_, embeddingDim, _ = s.probeEmbeddingFromCreds(ctx, pt, embModel, creds)
	}

	latencyMS = time.Since(start).Milliseconds()
	return &tenantv1.ProbeProviderResponse{
		Ok:                 true,
		Models:             modelsToProto(modelList),
		LatencyMs:          latencyMS,
		EmbeddingDimension: int32(embeddingDim), //nolint:gosec // dimension is always small positive int
	}, nil
}

// probeChatProvider constructs a chat provider from credentials and checks it
// with the model list call of the provider. Returns
// (ok, errMsg, modelList, latencyMs). A non-empty errMsg implies ok=false.
func (s *DaemonServer) probeChatProvider(ctx context.Context, pt llm.ProviderType, creds map[string]string, model string, start time.Time) (ok bool, errMsg string, modelList []llm.ModelInfo, latencyMS int64) {
	provCfg := s.withEgressPolicy(llm.ProviderConfig{
		Type:         pt,
		DefaultModel: model,
		APIKey:       creds["api_key"],
		BaseURL:      creds["base_url"],
	})
	extra := make(map[string]string)
	for k, v := range creds {
		if k != "api_key" && k != "base_url" {
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		provCfg.Extra = extra
	}

	chatFactory := s.providerFactory
	if chatFactory == nil {
		chatFactory = providers.NewProvider
	}
	prov, err := chatFactory(provCfg)
	if err != nil {
		return false, fmt.Sprintf("invalid provider configuration: %v", err), nil, time.Since(start).Milliseconds()
	}

	models, listErr := checkProviderCredentials(ctx, prov, model)
	latencyMS = time.Since(start).Milliseconds()
	if listErr != nil {
		return false, listErr.Error(), nil, latencyMS
	}
	return true, "", models, latencyMS
}

// checkProviderCredentials checks the credentials of a provider with its model
// list call and returns the models that the provider reports. The call sends no
// completion and needs no model ID. A failure carries the text of the provider.
//
// A provider with no list call (Foundry) is checked with a one-token completion
// against the model that the person typed. It then needs that model, and the
// result holds that one model.
func checkProviderCredentials(ctx context.Context, prov llm.LLMProvider, typedModel string) ([]llm.ModelInfo, error) {
	listCtx, cancel := context.WithTimeout(ctx, providerCheckTimeout)
	defer cancel()
	models, err := prov.Models(listCtx)
	if err == nil {
		return models, nil
	}
	if !errors.Is(err, llm.ErrModelListUnsupported) {
		return nil, err //nolint:wrapcheck // the provider error text is shown to the caller as is
	}
	prober, ok := prov.(llm.ModelProber)
	if !ok {
		return nil, err //nolint:wrapcheck // the provider error text is shown to the caller as is
	}
	typedModel = strings.TrimSpace(typedModel)
	if typedModel == "" {
		return nil, fmt.Errorf("provider %s has no model list call. Enter a model name to test the connection", prov.Name())
	}
	if err := prober.ProbeModel(listCtx, typedModel); err != nil {
		return nil, err //nolint:wrapcheck // the provider error text is shown to the caller as is
	}
	return []llm.ModelInfo{{Name: typedModel, ContextWindowUnreported: true}}, nil
}

// providerCheckTimeout bounds the credential check.
const providerCheckTimeout = 10 * time.Second

// probeEmbeddingFromCreds builds an embedder from raw credentials and probes
// it with a single-element batch. Returns (ok, dimension, errorMessage).
func (s *DaemonServer) probeEmbeddingFromCreds(ctx context.Context, pt llm.ProviderType, embModel string, creds map[string]string) (ok bool, dim int, errMsg string) {
	extra := make(map[string]string)
	for k, v := range creds {
		switch k {
		case "api_key", "base_url", "region":
		default:
			extra[k] = v
		}
	}
	embCfg := embedder.Config{
		Kind:    embedder.Kind(string(pt)),
		Model:   embModel,
		APIKey:  creds["api_key"],
		BaseURL: creds["base_url"],
		Region:  creds["region"],
		Extra:   extra,
	}
	factory := s.embedderFactory
	if factory == nil {
		factory = embedder.NewFromProvider
	}
	emb, err := factory(embCfg)
	if err != nil {
		return false, 0, fmt.Sprintf("failed to build embedder: %v", err)
	}
	embedCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	vecs, err := emb.EmbedBatch(embedCtx, []string{"ping"})
	if err != nil {
		if embedCtx.Err() == context.DeadlineExceeded {
			return false, 0, "embedding probe: timeout"
		}
		return false, 0, fmt.Sprintf("embedding probe failed: %v", err)
	}
	if len(vecs) == 0 || len(vecs[0]) == 0 {
		return false, 0, "embedding probe: empty vector returned"
	}
	return true, len(vecs[0]), ""
}

// ---------------------------------------------------------------------------
// ListProviderModels
// ---------------------------------------------------------------------------

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
	provCfg := s.withEgressPolicy(decryptedToLLMConfig(dec))

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

// credentialFieldTypeToProto maps the input kind of a credential field to the
// proto enum (gibson#701). A kind with no mapping gives UNSPECIFIED, and
// TestEveryCredentialFieldHasAType fails on it.
func credentialFieldTypeToProto(t llm.CredentialFieldType) tenantv1.CredentialFieldType {
	switch t {
	case llm.FieldText:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_TEXT
	case llm.FieldPassword:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_PASSWORD
	case llm.FieldURL:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_URL
	case llm.FieldRegion:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_REGION
	case llm.FieldBool:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_BOOL
	default:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_UNSPECIFIED
	}
}

// descriptorToProto translates the in-Go ProviderDescriptor to its proto
// equivalent. It carries provider metadata only. The model lists come from the
// provider through TestProvider, ProbeProvider and ListProviderModels.
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
			Type:        credentialFieldTypeToProto(c.Type),
		})
	}

	// The embedding models are the ones the save path accepts for the provider
	// kind: the embedder dimension table. It is not a second list.
	kindModels := embedder.ModelsForKind(embedder.Kind(string(d.Type)))
	embeddingModels := make([]*tenantv1.ModelDescriptor, 0, len(kindModels))
	for _, name := range kindModels {
		embeddingModels = append(embeddingModels, &tenantv1.ModelDescriptor{
			Name:         name,
			Capabilities: []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING},
		})
	}

	return &tenantv1.SupportedProvider{
		Type:            string(d.Type),
		DisplayName:     d.DisplayName,
		DocsUrl:         d.DocsURL,
		SelfHosted:      d.SelfHosted,
		Credentials:     creds,
		EmbeddingModels: embeddingModels,
	}
}

// modelToProto converts a single llm.ModelInfo to its proto ModelDescriptor,
// forwarding the capabilities from ModelInfo.Features.
func modelToProto(m llm.ModelInfo) *tenantv1.ModelDescriptor {
	return &tenantv1.ModelDescriptor{
		Name:          m.Name,
		ContextWindow: int32(m.ContextWindow), //nolint:gosec // model context windows are at most ~10M
		Capabilities:  capabilitiesToProto(m.Features),
	}
}

// modelsToProto translates llm.ModelInfo entries into the proto shape used
// by both ProbeProvider/TestProvider and ListProviderModels.
func modelsToProto(models []llm.ModelInfo) []*tenantv1.ModelDescriptor {
	out := make([]*tenantv1.ModelDescriptor, 0, len(models))
	for _, m := range models {
		out = append(out, modelToProto(m))
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
		Type:                      dec.Type,
		DefaultModel:              dec.DefaultModel,
		DefaultModelContextWindow: dec.DefaultModelContextWindow,
		APIKey:                    dec.Credentials["api_key"],
		BaseURL:                   dec.Credentials["base_url"],
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
