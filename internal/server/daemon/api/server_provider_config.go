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
	case errors.Is(err, providerconfig.ErrInvalidName):
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
		Type:                      providerconfig.ProviderType(in.Type),
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
	if input.Type == string(providerconfig.ProviderCustom) {
		return fmt.Errorf("provider type %q is operator-only and cannot be configured via the dashboard", input.Type)
	}
	supported := false
	for _, t := range providerconfig.SupportedProviderTypes() {
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
	embeddingOnly := input.Type == string(providerconfig.ProviderVoyage) ||
		input.Type == string(providerconfig.ProviderOpenAICompatible) ||
		input.Type == string(providerconfig.ProviderTEI)
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
	s.listCache().drop(tenantID, req.GetInput().GetName())
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
	s.listCache().drop(tenantID, req.GetName())
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
	s.listCache().drop(tenantID, name)
	return &tenantv1.DeleteProviderResponse{}, nil
}

// ---------------------------------------------------------------------------
// TestProvider
// ---------------------------------------------------------------------------

// isEmbeddingOnlyType reports whether the provider type serves embeddings only.
func isEmbeddingOnlyType(t providerconfig.ProviderType) bool {
	return t == providerconfig.ProviderVoyage || t == providerconfig.ProviderOpenAICompatible || t == providerconfig.ProviderTEI
}

// servesChat reports whether a proposed config serves chat: it declares the
// chat capability, or it declares none (the legacy chat-only default) and is
// not an embedding-only type.
func servesChat(input *tenantv1.ProviderConfigInput) bool {
	if isEmbeddingOnlyType(providerconfig.ProviderType(input.GetType())) {
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

// fillDefaultModelWindow checks the context window that is stored with the saved
// model. The save path calls no provider (gibson#1394, ADR-0172): the daemon
// holds no provider client and no credential that is not saved yet. The caller
// states the window, so:
//  1. a window that the caller states must be in 1..maxContextWindow;
//  2. else an update that keeps the same model keeps the stored window;
//  3. else the save is refused, and the message tells the caller to state it.
//
// existing is the stored config on an update, and nil on a create. A config that
// serves no chat, or names no default model, has no window to fix.
func (s *DaemonServer) fillDefaultModelWindow(_ context.Context, input *tenantv1.ProviderConfigInput, existing *providerconfig.ProviderConfig) error {
	model := strings.TrimSpace(input.GetDefaultModel())
	if model == "" || !servesChat(input) {
		return nil
	}
	if stated := input.GetDefaultModelContextWindow(); stated != 0 {
		if stated < 1 || stated > maxContextWindow {
			return fmt.Errorf("default_model_context_window %d is out of range: it must be 1 to %d tokens", stated, maxContextWindow)
		}
		return nil
	}
	if existing != nil && existing.DefaultModel == model && string(existing.Type) == input.GetType() &&
		existing.DefaultModelContextWindow > 0 {
		input.DefaultModelContextWindow = int32(existing.DefaultModelContextWindow) //nolint:gosec // bounded by maxContextWindow at save
		return nil
	}
	if existing != nil && existing.DefaultModel == model && string(existing.Type) == input.GetType() {
		// A provider saved before the window was stored. An edit that does not
		// touch the model is not refused.
		return nil
	}
	return fmt.Errorf("the context window of model %q is unknown. State it in default_model_context_window", model)
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
// types in the same deterministic order as providerconfig.SupportedProviderTypes(). No
// tenant context required at the data layer (the catalogue is process-wide),
// but the auth interceptor still asserts tenant membership so unauthenticated
// callers can't enumerate the surface.
func (s *DaemonServer) GetSupportedProviders(ctx context.Context, _ *tenantv1.GetSupportedProvidersRequest) (*tenantv1.GetSupportedProvidersResponse, error) {
	if auth.TenantStringFromContext(ctx) == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	descriptors := providerconfig.SupportedProviderDescriptors()
	out := make([]*tenantv1.SupportedProvider, 0, len(descriptors))
	for _, d := range descriptors {
		out = append(out, descriptorToProto(d))
	}
	return &tenantv1.GetSupportedProvidersResponse{Providers: out}, nil
}

// credentialFieldTypeToProto maps the input kind of a credential field to the
// proto enum (gibson#701). A kind with no mapping gives UNSPECIFIED, and
// TestEveryCredentialFieldHasAType fails on it.
func credentialFieldTypeToProto(t providerconfig.CredentialFieldType) tenantv1.CredentialFieldType {
	switch t {
	case providerconfig.FieldText:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_TEXT
	case providerconfig.FieldPassword:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_PASSWORD
	case providerconfig.FieldURL:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_URL
	case providerconfig.FieldRegion:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_REGION
	case providerconfig.FieldBool:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_BOOL
	default:
		return tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_UNSPECIFIED
	}
}

// descriptorToProto translates the in-Go ProviderDescriptor to its proto
// equivalent. It carries provider metadata only. The model lists come from the
// provider through TestProvider and ListProviderModels.
func descriptorToProto(d providerconfig.ProviderDescriptor) *tenantv1.SupportedProvider {
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
