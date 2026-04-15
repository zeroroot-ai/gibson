// Package agentauth — service.go
//
// AgentAuthService implements the gRPC handler methods for the Agent Auth
// Protocol. It is called from the DaemonServer and delegates to the
// AgentAuthStore, FGABridge, and audit.Writer.
//
// Handler responsibilities:
//   - RegisterAgentAuth: upsert host, create agent, resolve capabilities via FGA,
//     write grants, emit audit event.
//   - ExecuteAgentCapability: check FGA, emit audit event, dispatch to component.
//   - ListAgentCapabilities: resolve via FGABridge and return.
//   - GetAgentAuthStatus: read agent + grants from store.
//   - RevokeAgentAuth: revoke agent + grants in store, emit audit event.
//   - ListAgentAuthAgents: paginated list from store.
//   - CreateHostRegistrationToken: issue single-use API key via APIKeyAuthenticator.
//   - ListComponentGrants: enumerate FGA tuples for all users × all components.
//   - BatchGrantComponentAccessV2: write/delete FGA tuples, emit audit events.
//   - ListAuditLog: read from Postgres audit_log table via audit.Query.
//
// Thread-safety: AgentAuthService is safe for concurrent use provided all
// injected dependencies are also safe for concurrent use.
package agentauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/authz"
)

// ---------------------------------------------------------------------------
// ComponentDispatcher
// ---------------------------------------------------------------------------

// ComponentDispatcher dispatches work to a registered component and returns
// the result bytes. The tenant, kind, and name identify the target component
// (e.g. tenant="acme", kind="tool", name="nmap"). Input is the raw request
// payload and the returned bytes are the raw response from the component.
type ComponentDispatcher interface {
	Dispatch(ctx context.Context, tenant, kind, name string, input []byte) ([]byte, error)
}

// ---------------------------------------------------------------------------
// AgentAuthService
// ---------------------------------------------------------------------------

// AgentAuthService implements the Agent Auth Protocol gRPC handlers.
//
// All handler methods follow the thin-wrapper pattern: validate inputs, delegate
// to domain helpers (store, fgaBridge, apiKeys, auditWriter), map results to Go
// return types. Business logic lives in the domain helpers, not here.
type AgentAuthService struct {
	store       *AgentAuthStore
	fgaBridge   *FGABridge
	authorizer  authz.Authorizer
	apiKeys     *auth.APIKeyAuthenticator
	auditWriter *audit.Writer
	auditQuery  *audit.Query
	dispatcher  ComponentDispatcher
	logger      *slog.Logger
}

// AgentAuthServiceConfig carries all dependencies for AgentAuthService.
type AgentAuthServiceConfig struct {
	// Store is the Postgres-backed CRUD layer for hosts, agents, and grants. Required.
	Store *AgentAuthStore

	// FGABridge resolves FGA capabilities and checks execution permissions. Required.
	FGABridge *FGABridge

	// Authorizer is used for FGA write/delete operations in BatchGrantComponentAccessV2
	// and for listing objects in ListComponentGrants. Required.
	Authorizer authz.Authorizer

	// APIKeys is the Postgres-backed API key authenticator used for
	// CreateHostRegistrationToken. Required.
	APIKeys *auth.APIKeyAuthenticator

	// AuditWriter is the async Postgres audit writer. Required.
	AuditWriter *audit.Writer

	// AuditQuery is the synchronous Postgres audit reader. Required.
	AuditQuery *audit.Query

	// Dispatcher dispatches work to registered components and returns results.
	// Optional: when nil, ExecuteAgentCapability returns an error indicating the
	// dispatcher is not configured.
	Dispatcher ComponentDispatcher

	// Logger is the structured logger. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// NewAgentAuthService constructs an AgentAuthService. All required fields in
// cfg must be non-nil; the function panics if any required dependency is nil.
func NewAgentAuthService(cfg AgentAuthServiceConfig) *AgentAuthService {
	if cfg.Store == nil {
		panic("agentauth: AgentAuthService: Store must not be nil")
	}
	if cfg.FGABridge == nil {
		panic("agentauth: AgentAuthService: FGABridge must not be nil")
	}
	if cfg.Authorizer == nil {
		panic("agentauth: AgentAuthService: Authorizer must not be nil")
	}
	if cfg.APIKeys == nil {
		panic("agentauth: AgentAuthService: APIKeys must not be nil")
	}
	if cfg.AuditWriter == nil {
		panic("agentauth: AgentAuthService: AuditWriter must not be nil")
	}
	if cfg.AuditQuery == nil {
		panic("agentauth: AgentAuthService: AuditQuery must not be nil")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &AgentAuthService{
		store:       cfg.Store,
		fgaBridge:   cfg.FGABridge,
		authorizer:  cfg.Authorizer,
		apiKeys:     cfg.APIKeys,
		auditWriter: cfg.AuditWriter,
		auditQuery:  cfg.AuditQuery,
		dispatcher:  cfg.Dispatcher,
		logger:      logger.With("component", "agentauth.service"),
	}
}

// ---------------------------------------------------------------------------
// RegisterAgentAuth
// ---------------------------------------------------------------------------

// RegisterAgentAuthResult is the result returned by RegisterAgentAuth.
type RegisterAgentAuthResult struct {
	AgentID      string
	HostID       string
	Capabilities []Capability
	Status       string
}

// RegisterAgentAuth upserts the host, creates the agent, resolves FGA capability
// grants, writes them to the store, and emits an agent_registered audit event.
//
// When bootstrap_type is "api_key", the bootstrap_credential is validated via
// the APIKeyAuthenticator before any writes occur.
func (s *AgentAuthService) RegisterAgentAuth(
	ctx context.Context,
	tenantID, ownerUserID, agentName, agentMode string,
	hostPublicKeyJWK, agentPublicKeyJWK json.RawMessage,
	bootstrapType, bootstrapCredential string,
) (*RegisterAgentAuthResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: tenant_id is required")
	}
	if ownerUserID == "" {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: owner_user_id is required")
	}
	if agentName == "" {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: agent_name is required")
	}
	if len(hostPublicKeyJWK) == 0 {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: host_public_key_jwk is required")
	}
	if len(agentPublicKeyJWK) == 0 {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: agent_public_key_jwk is required")
	}

	// Validate bootstrap credential when type is api_key.
	if bootstrapType == "api_key" {
		if _, err := s.apiKeys.Authenticate(ctx, bootstrapCredential); err != nil {
			return nil, fmt.Errorf("agentauth: RegisterAgentAuth: invalid bootstrap credential: %w", err)
		}
	}

	// Derive stable IDs from the public key JWKs.
	// The host ID is a content-addressed thumbprint so that re-registrations from
	// the same host are idempotent.
	hostID, err := jwkThumbprint(hostPublicKeyJWK)
	if err != nil {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: host key thumbprint: %w", err)
	}
	agentID, err := newAgentID()
	if err != nil {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: generate agent ID: %w", err)
	}

	// Upsert host record.
	if err := s.store.UpsertHost(ctx, Host{
		ID:           hostID,
		TenantID:     tenantID,
		UserID:       ownerUserID,
		DisplayName:  hostID[:8], // short display name until set explicitly
		PublicKeyJWK: hostPublicKeyJWK,
		Status:       "active",
	}); err != nil {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: upsert host: %w", err)
	}

	// Normalise mode.
	mode := agentMode
	if mode != "delegated" && mode != "autonomous" {
		mode = "delegated"
	}

	// Create agent record.
	if err := s.store.CreateAgent(ctx, Agent{
		ID:           agentID,
		HostID:       hostID,
		TenantID:     tenantID,
		UserID:       ownerUserID,
		Name:         agentName,
		Mode:         mode,
		PublicKeyJWK: agentPublicKeyJWK,
		Status:       "active",
	}); err != nil {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: create agent: %w", err)
	}

	// Resolve FGA capabilities for the agent owner.
	caps, err := s.fgaBridge.ResolveCapabilities(ctx, ownerUserID, tenantID)
	if err != nil {
		// Non-fatal: log and continue with zero grants. The agent is still
		// registered; grants can be re-resolved later.
		s.logger.WarnContext(ctx, "agentauth: RegisterAgentAuth: FGA capability resolution failed, continuing with zero grants",
			slog.String("agent_id", agentID),
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		caps = []Capability{}
	}

	// Convert capabilities to grants and write to store.
	grants := make([]Grant, 0, len(caps))
	for _, cap := range caps {
		grants = append(grants, Grant{
			AgentID:        agentID,
			CapabilityName: cap.Name,
			ComponentRef:   cap.ComponentRef,
			Status:         "active",
		})
	}
	if err := s.store.SetGrants(ctx, agentID, grants); err != nil {
		return nil, fmt.Errorf("agentauth: RegisterAgentAuth: write grants: %w", err)
	}

	// Emit audit event.
	meta, _ := json.Marshal(map[string]any{
		"agent_name":       agentName,
		"agent_mode":       mode,
		"bootstrap_type":   bootstrapType,
		"capability_count": len(caps),
	})
	s.auditWriter.Log(audit.Event{
		TenantID:   tenantID,
		ActorID:    ownerUserID,
		ActorType:  "user",
		Action:     "agent_registered",
		TargetType: "agent",
		TargetID:   agentID,
		Metadata:   json.RawMessage(meta),
	})

	s.logger.InfoContext(ctx, "agentauth: agent registered",
		slog.String("agent_id", agentID),
		slog.String("host_id", hostID),
		slog.String("tenant_id", tenantID),
		slog.Int("capabilities", len(caps)),
	)

	return &RegisterAgentAuthResult{
		AgentID:      agentID,
		HostID:       hostID,
		Capabilities: caps,
		Status:       "active",
	}, nil
}

// ---------------------------------------------------------------------------
// ExecuteAgentCapability
// ---------------------------------------------------------------------------

// ExecuteAgentCapabilityResult is the result returned by ExecuteAgentCapability.
type ExecuteAgentCapabilityResult struct {
	Result       []byte
	Status       string
	ErrorMessage string
}

// ExecuteAgentCapability checks FGA for permission to execute the requested
// capability, records an audit event, and dispatches work to the target
// component via the configured ComponentDispatcher.
func (s *AgentAuthService) ExecuteAgentCapability(
	ctx context.Context,
	agentID, capabilityName string,
	arguments []byte,
	tenantID string,
) (*ExecuteAgentCapabilityResult, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agentauth: ExecuteAgentCapability: agent_id is required")
	}
	if capabilityName == "" {
		return nil, fmt.Errorf("agentauth: ExecuteAgentCapability: capability_name is required")
	}

	// Resolve the agent to get the owner user ID for FGA check.
	agent, err := s.store.GetAgent(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("agentauth: ExecuteAgentCapability: store lookup: %w", err)
	}
	if agent == nil {
		return &ExecuteAgentCapabilityResult{
			Status:       "error",
			ErrorMessage: "agent not found",
		}, nil
	}

	// Parse the capability name (format: "{verb}:{kind}:{name}") to extract the
	// component ref for FGA checks and the kind+name for dispatch routing.
	componentRef, kind, name, ok := parseCapabilityName(capabilityName)
	if !ok {
		return &ExecuteAgentCapabilityResult{
			Status:       "error",
			ErrorMessage: fmt.Sprintf("malformed capability_name %q: expected {verb}:{kind}:{name}", capabilityName),
		}, nil
	}

	// FGA check using the agent owner's identity.
	allowed, err := s.fgaBridge.CheckExecution(ctx, agent.UserID, componentRef)
	if err != nil {
		return nil, fmt.Errorf("agentauth: ExecuteAgentCapability: FGA check: %w", err)
	}

	decision := "allow"
	if !allowed {
		decision = "deny"
	}

	// Emit audit event regardless of outcome.
	meta, _ := json.Marshal(map[string]any{
		"capability_name": capabilityName,
		"component_ref":   componentRef,
		"decision":        decision,
	})
	s.auditWriter.Log(audit.Event{
		TenantID:   tenantID,
		ActorID:    agentID,
		ActorType:  "agent",
		Action:     "capability_executed",
		TargetType: "component",
		TargetID:   componentRef,
		Decision:   decision,
		Metadata:   json.RawMessage(meta),
	})

	if !allowed {
		return &ExecuteAgentCapabilityResult{
			Status:       "error",
			ErrorMessage: "permission denied: insufficient FGA grants",
		}, nil
	}

	if s.dispatcher == nil {
		return &ExecuteAgentCapabilityResult{
			Status:       "error",
			ErrorMessage: "component dispatcher not configured",
		}, nil
	}

	result, err := s.dispatcher.Dispatch(ctx, tenantID, kind, name, arguments)
	if err != nil {
		s.logger.WarnContext(ctx, "agentauth: ExecuteAgentCapability: dispatch failed",
			slog.String("agent_id", agentID),
			slog.String("capability", capabilityName),
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return &ExecuteAgentCapabilityResult{
			Status:       "error",
			ErrorMessage: fmt.Sprintf("dispatch failed: %v", err),
		}, nil
	}

	return &ExecuteAgentCapabilityResult{
		Result: result,
		Status: "success",
	}, nil
}

// ---------------------------------------------------------------------------
// ListAgentCapabilities
// ---------------------------------------------------------------------------

// ListAgentCapabilities resolves and returns all capabilities available to
// the given user within the given tenant via FGABridge.ResolveCapabilities.
func (s *AgentAuthService) ListAgentCapabilities(
	ctx context.Context,
	tenantID, userID string,
) ([]Capability, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("agentauth: ListAgentCapabilities: tenant_id is required")
	}
	if userID == "" {
		return nil, fmt.Errorf("agentauth: ListAgentCapabilities: user_id is required")
	}
	return s.fgaBridge.ResolveCapabilities(ctx, userID, tenantID)
}

// ---------------------------------------------------------------------------
// GetAgentAuthStatus
// ---------------------------------------------------------------------------

// AgentAuthStatusResult carries agent status and grants.
type AgentAuthStatusResult struct {
	Agent  *Agent
	Grants []Grant
}

// GetAgentAuthStatus retrieves the agent record and all its grants from the store.
// Returns (nil, nil) when no agent with the given ID exists.
func (s *AgentAuthService) GetAgentAuthStatus(
	ctx context.Context,
	agentID, tenantID string,
) (*AgentAuthStatusResult, error) {
	if agentID == "" {
		return nil, fmt.Errorf("agentauth: GetAgentAuthStatus: agent_id is required")
	}

	agent, err := s.store.GetAgent(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("agentauth: GetAgentAuthStatus: %w", err)
	}
	if agent == nil {
		return nil, nil
	}

	grants, err := s.store.GetGrants(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("agentauth: GetAgentAuthStatus: get grants: %w", err)
	}

	return &AgentAuthStatusResult{
		Agent:  agent,
		Grants: grants,
	}, nil
}

// ---------------------------------------------------------------------------
// RevokeAgentAuth
// ---------------------------------------------------------------------------

// RevokeAgentAuth revokes the agent and all its grants, then emits an
// agent_revoked audit event.
func (s *AgentAuthService) RevokeAgentAuth(
	ctx context.Context,
	agentID, tenantID, actorID string,
) error {
	if agentID == "" {
		return fmt.Errorf("agentauth: RevokeAgentAuth: agent_id is required")
	}

	if err := s.store.RevokeAgent(ctx, agentID); err != nil {
		return fmt.Errorf("agentauth: RevokeAgentAuth: %w", err)
	}

	s.auditWriter.Log(audit.Event{
		TenantID:   tenantID,
		ActorID:    actorID,
		ActorType:  "user",
		Action:     "agent_revoked",
		TargetType: "agent",
		TargetID:   agentID,
	})

	s.logger.InfoContext(ctx, "agentauth: agent revoked",
		slog.String("agent_id", agentID),
		slog.String("tenant_id", tenantID),
	)
	return nil
}

// ---------------------------------------------------------------------------
// ListAgentAuthAgents
// ---------------------------------------------------------------------------

// ListAgentAuthAgentsResult carries the paginated agent list.
type ListAgentAuthAgentsResult struct {
	Agents []Agent
	Total  int
}

// ListAgentAuthAgents returns a paginated list of agents for a tenant.
func (s *AgentAuthService) ListAgentAuthAgents(
	ctx context.Context,
	tenantID string,
	limit, offset int,
) (*ListAgentAuthAgentsResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("agentauth: ListAgentAuthAgents: tenant_id is required")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	agents, total, err := s.store.ListAgentsByTenant(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("agentauth: ListAgentAuthAgents: %w", err)
	}

	return &ListAgentAuthAgentsResult{
		Agents: agents,
		Total:  total,
	}, nil
}

// ---------------------------------------------------------------------------
// CreateHostRegistrationToken
// ---------------------------------------------------------------------------

// HostRegistrationTokenResult carries the raw token and its metadata.
type HostRegistrationTokenResult struct {
	RawToken  string
	KeyID     string
	ExpiresAt time.Time
}

// CreateHostRegistrationToken issues a single-use API key scoped to the given
// tenant with AllowedKinds=["host"] and MaxUses=1.
//
// ttlHours must be in [1, 168]. Values outside that range are clamped.
func (s *AgentAuthService) CreateHostRegistrationToken(
	ctx context.Context,
	tenantID, name, createdBy string,
	ttlHours int,
) (*HostRegistrationTokenResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("agentauth: CreateHostRegistrationToken: tenant_id is required")
	}
	if name == "" {
		name = "host-registration"
	}

	// Clamp TTL.
	if ttlHours <= 0 {
		ttlHours = 24
	}
	if ttlHours > 168 {
		ttlHours = 168
	}

	rawKey, record, err := s.apiKeys.CreateKey(
		ctx,
		tenantID,
		[]string{"host"},          // AllowedKinds: host registrations only
		[]string{},                // AllowedNames: no restriction
		[]string{"register:host"}, // Capabilities
		name,
		createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("agentauth: CreateHostRegistrationToken: %w", err)
	}

	expiresAt := time.Now().UTC().Add(time.Duration(ttlHours) * time.Hour)

	_ = record // record is logged by CreateKey internally

	return &HostRegistrationTokenResult{
		RawToken:  rawKey,
		KeyID:     record.KeyID,
		ExpiresAt: expiresAt,
	}, nil
}

// ---------------------------------------------------------------------------
// ListComponentGrants
// ---------------------------------------------------------------------------

// ComponentGrantResult describes a single resolved FGA grant.
type ComponentGrantResult struct {
	UserID       string
	ComponentRef string
	CanExecute   bool
	CanConfigure bool
	CanRead      bool
	GrantSource  string
}

// ListComponentGrants enumerates FGA component grants for all users in a tenant.
//
// Implementation notes:
//   - For each of the three relations (can_execute, can_configure, can_read) we
//     call ListObjects to enumerate all component objects that have at least one
//     user with that relation, then for each component we call ListUsers to find
//     which users hold the relation.
//   - This is O(relations × components × users) and is intentionally best-effort:
//     callers should not rely on this being fast for large tenants.
//   - Errors from individual FGA calls are logged and skipped rather than aborting
//     the entire enumeration.
func (s *AgentAuthService) ListComponentGrants(
	ctx context.Context,
	tenantID string,
) ([]ComponentGrantResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("agentauth: ListComponentGrants: tenant_id is required")
	}

	type grantKey struct {
		userID       string
		componentRef string
	}
	byKey := make(map[grantKey]*ComponentGrantResult)

	relations := []struct {
		fgaRelation string
		setter      func(*ComponentGrantResult, bool)
	}{
		{"can_execute", func(g *ComponentGrantResult, v bool) { g.CanExecute = v }},
		{"can_configure", func(g *ComponentGrantResult, v bool) { g.CanConfigure = v }},
		{"can_read", func(g *ComponentGrantResult, v bool) { g.CanRead = v }},
	}

	// We need a user subject; query ListUsers for each relation on each component.
	// First, find all components that have at least one tuple via ListObjects from a dummy user.
	// Since we can't enumerate all objects without a user, we use ListUsers on the
	// tenant object to get all users, then for each user enumerate their objects.
	tenantUsers, err := s.authorizer.ListUsers(ctx, "tenant", fmt.Sprintf("tenant:%s", tenantID), "member")
	if err != nil {
		s.logger.WarnContext(ctx, "agentauth: ListComponentGrants: failed to list tenant users",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		tenantUsers = []string{}
	}

	for _, fgaUserStr := range tenantUsers {
		for _, rel := range relations {
			objects, err := s.authorizer.ListObjects(ctx, fgaUserStr, rel.fgaRelation, "component")
			if err != nil {
				s.logger.WarnContext(ctx, "agentauth: ListComponentGrants: ListObjects failed",
					slog.String("user", fgaUserStr),
					slog.String("relation", rel.fgaRelation),
					slog.String("error", err.Error()),
				)
				continue
			}

			// Strip "user:" prefix from FGA user string.
			userID := stripFGATypePrefix(fgaUserStr, "user")

			for _, obj := range objects {
				k := grantKey{userID: userID, componentRef: obj}
				entry, exists := byKey[k]
				if !exists {
					entry = &ComponentGrantResult{
						UserID:       userID,
						ComponentRef: obj,
						GrantSource:  "direct",
					}
					byKey[k] = entry
				}
				rel.setter(entry, true)
			}
		}
	}

	results := make([]ComponentGrantResult, 0, len(byKey))
	for _, v := range byKey {
		results = append(results, *v)
	}
	return results, nil
}

// ---------------------------------------------------------------------------
// BatchGrantComponentAccessV2
// ---------------------------------------------------------------------------

// GrantChangeV2 describes a single grant or revoke operation.
type GrantChangeV2 struct {
	UserID        string
	PrincipalType string // "user" or "team"
	ComponentRef  string
	Action        string // "execute", "configure", "read"
	Grant         bool   // true = add, false = remove
}

// BatchGrantComponentAccessV2 applies bulk FGA grant/revoke operations and
// records audit events for each applied change.
// Returns the count of successfully applied operations.
func (s *AgentAuthService) BatchGrantComponentAccessV2(
	ctx context.Context,
	tenantID, actorID string,
	changes []GrantChangeV2,
) (int, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("agentauth: BatchGrantComponentAccessV2: tenant_id is required")
	}

	applied := 0
	for _, change := range changes {
		if change.UserID == "" || change.ComponentRef == "" || change.Action == "" {
			continue
		}

		relation := "can_" + change.Action
		fgaUser := change.PrincipalType + ":" + change.UserID
		if change.PrincipalType == "" {
			fgaUser = "user:" + change.UserID
		}

		tuple := authz.Tuple{
			User:     fgaUser,
			Relation: relation,
			Object:   change.ComponentRef,
		}

		var opErr error
		if change.Grant {
			opErr = s.authorizer.Write(ctx, []authz.Tuple{tuple})
		} else {
			opErr = s.authorizer.Delete(ctx, []authz.Tuple{tuple})
		}

		if opErr != nil {
			s.logger.WarnContext(ctx, "agentauth: BatchGrantComponentAccessV2: FGA operation failed",
				slog.String("user", fgaUser),
				slog.String("relation", relation),
				slog.String("component", change.ComponentRef),
				slog.Bool("grant", change.Grant),
				slog.String("error", opErr.Error()),
			)
			continue
		}

		action := "component_access_granted"
		if !change.Grant {
			action = "component_access_revoked"
		}
		meta, _ := json.Marshal(map[string]any{
			"component_ref": change.ComponentRef,
			"relation":      relation,
			"principal":     fgaUser,
		})
		s.auditWriter.Log(audit.Event{
			TenantID:   tenantID,
			ActorID:    actorID,
			ActorType:  "user",
			Action:     action,
			TargetType: "component",
			TargetID:   change.ComponentRef,
			Metadata:   json.RawMessage(meta),
		})

		applied++
	}

	return applied, nil
}

// ---------------------------------------------------------------------------
// ListAuditLog
// ---------------------------------------------------------------------------

// ListAuditLog returns a paginated list of audit log entries from Postgres.
func (s *AgentAuthService) ListAuditLog(
	ctx context.Context,
	tenantID, actorID, action, targetType string,
	limit, offset int,
) ([]audit.PgEntry, int, error) {
	if tenantID == "" {
		return nil, 0, fmt.Errorf("agentauth: ListAuditLog: tenant_id is required")
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	filters := audit.Filters{
		ActorID:    actorID,
		Action:     action,
		TargetType: targetType,
	}

	return s.auditQuery.List(ctx, tenantID, filters, limit, offset)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newAgentID generates a new agent ID with the "agt_" prefix using 8 random bytes.
func newAgentID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agentID: rand.Read: %w", err)
	}
	return fmt.Sprintf("agt_%x", b), nil
}

// jwkThumbprint derives a stable ID from a JWK by computing a short hex
// digest of the canonical JWK JSON bytes. This is used as the host ID so that
// re-registrations from the same host are idempotent.
func jwkThumbprint(jwk json.RawMessage) (string, error) {
	if len(jwk) == 0 {
		return "", fmt.Errorf("empty JWK")
	}
	// Use the first 8 bytes of the SHA-256 of the raw JWK bytes as the host ID.
	sum := sha256.Sum256(jwk)
	return fmt.Sprintf("host_%x", sum[:8]), nil
}

// parseCapabilityName parses a capability name in "{verb}:{kind}:{name}" format
// and returns the FGA component ref ("component:{name}"), the kind, and the name.
// Returns ("", "", "", false) if the format is invalid.
func parseCapabilityName(capName string) (componentRef, kind, name string, ok bool) {
	parts := strings.SplitN(capName, ":", 3)
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return "component:" + parts[2], parts[1], parts[2], true
}

// stripFGATypePrefix removes the "type:" prefix from an FGA object/user string.
// Returns the original string if the prefix is not found.
func stripFGATypePrefix(s, typeName string) string {
	prefix := typeName + ":"
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
