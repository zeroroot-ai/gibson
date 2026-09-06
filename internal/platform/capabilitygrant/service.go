// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package capabilitygrant — service.go
//
// CapabilityGrantService implements the gRPC handler methods for the Agent Auth
// Protocol. It is called from the DaemonServer and delegates to the
// CapabilityGrantStore, FGABridge, and audit.Writer.
//
// Handler responsibilities:
//   - RegisterCapabilityGrant: upsert host, create agent, resolve capabilities via FGA,
//     write grants, emit audit event.
//   - ExecuteAgentCapability: check FGA, emit audit event, dispatch to component.
//   - ListAgentCapabilities: resolve via FGABridge and return.
//   - GetCapabilityGrantStatus: read agent + grants from store.
//   - RevokeCapabilityGrant: revoke agent + grants in store, emit audit event.
//   - ListCapabilityGrantAgents: paginated list from store.
//   - ListComponentGrants: enumerate FGA tuples for all users × all components.
//   - BatchGrantComponentAccessV2: write/delete FGA tuples, emit audit events.
//   - ListAuditLog: read from Postgres audit_log table via audit.Query.
//
// Note: CreateHostRegistrationToken and ValidateBootstrap (api_key path) have been
// removed. The architectural replacement is TenantAdminService.CreateAgentIdentity.
// Spec: agent-service-credentials Requirement 10.4.
//
// Thread-safety: CapabilityGrantService is safe for concurrent use provided all
// injected dependencies are also safe for concurrent use.
package capabilitygrant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/capname"
)

// hostReRegistrationBootstrapType is the bootstrap_type the register endpoint
// reports when the caller authenticated with a host key it ALREADY holds. That
// is proof of possession of a persistent key, not a one-time credential, so it
// is the only value that skips credential consumption. Every other value —
// including an unrecognised one — is treated as a one-time enrollment
// credential and consumed.
const hostReRegistrationBootstrapType = "host_jwt"

// BootstrapTypeSPIFFESVID marks an enrollment authenticated by a SPIFFE JWT-SVID
// (ADR-0066): a first-party in-cluster plugin proves its FIRST registration with
// its SPIRE SVID instead of a one-time bootstrap token. An SVID is re-presentable
// — the plugin fetches a fresh one from the Workload API on every start — so,
// like a host re-registration, an SVID enrollment is NOT a one-time credential
// and is never consumed.
const BootstrapTypeSPIFFESVID = "spiffe_svid"

// isSingleUseCredential reports whether an enrollment of the given bootstrap
// type consumes a one-time credential. A host re-registration (proof of a
// persistent key) and a SPIFFE-SVID enrollment (a re-presentable attested
// identity) are the two non-consuming types; every other value — including an
// unrecognised one — is treated as a one-time bootstrap token and burned. This
// is the single place that encodes which enrollment credentials are one-time.
func isSingleUseCredential(bootstrapType string) bool {
	return bootstrapType != hostReRegistrationBootstrapType &&
		bootstrapType != BootstrapTypeSPIFFESVID
}

// bootstrapCredentialHash is the value recorded to burn an enrollment
// credential: the hex SHA-256 of the credential itself. The credential never
// reaches the database, and an Ed25519 JWS is deterministic with every claim
// covered by the signature, so one credential has exactly one hash and no
// re-encoding of it can produce another.
func bootstrapCredentialHash(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

// capsWithinCeiling returns the capabilities named by ceiling. An EMPTY ceiling
// means the credential states no ceiling of its own, so the FGA resolution
// stands unmodified — the credential is not silently reduced to zero grants for
// having said nothing.
func capsWithinCeiling(caps []Capability, ceiling []string) []Capability {
	if len(ceiling) == 0 {
		return caps
	}
	allowed := make(map[string]struct{}, len(ceiling))
	for _, name := range ceiling {
		allowed[name] = struct{}{}
	}
	kept := make([]Capability, 0, len(caps))
	for _, c := range caps {
		if _, ok := allowed[c.Name]; ok {
			kept = append(kept, c)
		}
	}
	return kept
}

// appendSessionCapabilities adds the reserved, non-component capabilities
// (capname.MissionDelegate, capname.MissionOriginate) named by ceiling.
//
// Every other capability is FGA-derived: capsWithinCeiling can only REMOVE
// from that set, because the credential narrows what its bearer may become
// and must never widen it beyond what FGA already granted the principal. The
// two reserved names are the deliberate exception (gibson#1186 slice C owner
// decision): they are NOT relations on any FGA object, so FGA resolution
// never produces them — an empty ceiling therefore grants neither, and the
// ONLY way to obtain one is for the credential that minted this registration
// to have named it. That is exactly "a capability-grant bit, not a standing
// tuple": the bit lives on the Grant row this one registration writes, and
// revoking the agent (RevokeAgent) removes it with everything else. No FGA
// tuple is ever written for either name.
//
// Must run AFTER capsWithinCeiling so the narrowing pass never sees — and so
// can never accidentally drop — an entry capsWithinCeiling has no way to have
// produced in the first place.
func appendSessionCapabilities(caps []Capability, ceiling []string) []Capability {
	if len(ceiling) == 0 {
		return caps
	}
	have := make(map[string]struct{}, len(caps))
	for _, c := range caps {
		have[c.Name] = struct{}{}
	}
	for _, entry := range ceiling {
		if !capname.IsReserved(entry) {
			continue
		}
		if _, dup := have[entry]; dup {
			continue
		}
		caps = append(caps, Capability{
			Name:        entry,
			Description: capname.Description(entry),
		})
		have[entry] = struct{}{}
	}
	return caps
}

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
// CapabilityGrantService
// ---------------------------------------------------------------------------

// CapabilityGrantService implements the Capability Grant Protocol gRPC handlers.
//
// All handler methods follow the thin-wrapper pattern: validate inputs, delegate
// to domain helpers (store, fgaBridge, auditWriter), map results to Go
// return types. Business logic lives in the domain helpers, not here.
type CapabilityGrantService struct {
	store       *CapabilityGrantStore
	fgaBridge   *FGABridge
	authorizer  authz.Authorizer
	auditWriter *audit.Writer
	auditQuery  *audit.Query
	dispatcher  ComponentDispatcher
	logger      *slog.Logger
}

// CapabilityGrantServiceConfig carries all dependencies for CapabilityGrantService.
type CapabilityGrantServiceConfig struct {
	// Store is the Postgres-backed CRUD layer for hosts, agents, and grants. Required.
	Store *CapabilityGrantStore

	// FGABridge resolves FGA capabilities and checks execution permissions. Required.
	FGABridge *FGABridge

	// Authorizer is used for FGA write/delete operations in BatchGrantComponentAccessV2
	// and for listing objects in ListComponentGrants. Required.
	Authorizer authz.Authorizer

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

// NewCapabilityGrantService constructs an CapabilityGrantService. All required fields in
// cfg must be non-nil; the function panics if any required dependency is nil.
func NewCapabilityGrantService(cfg CapabilityGrantServiceConfig) *CapabilityGrantService {
	if cfg.Store == nil {
		panic("capabilitygrant: CapabilityGrantService: Store must not be nil")
	}
	if cfg.FGABridge == nil {
		panic("capabilitygrant: CapabilityGrantService: FGABridge must not be nil")
	}
	if cfg.Authorizer == nil {
		panic("capabilitygrant: CapabilityGrantService: Authorizer must not be nil")
	}
	if cfg.AuditWriter == nil {
		panic("capabilitygrant: CapabilityGrantService: AuditWriter must not be nil")
	}
	if cfg.AuditQuery == nil {
		panic("capabilitygrant: CapabilityGrantService: AuditQuery must not be nil")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &CapabilityGrantService{
		store:       cfg.Store,
		fgaBridge:   cfg.FGABridge,
		authorizer:  cfg.Authorizer,
		auditWriter: cfg.AuditWriter,
		auditQuery:  cfg.AuditQuery,
		dispatcher:  cfg.Dispatcher,
		logger:      logger.With("component", "capabilitygrant.service"),
	}
}

// ---------------------------------------------------------------------------
// RegisterCapabilityGrant
// ---------------------------------------------------------------------------

// RegisterCapabilityGrantResult is the result returned by RegisterCapabilityGrant.
type RegisterCapabilityGrantResult struct {
	AgentID      string
	HostID       string
	Capabilities []Capability
	Status       string
	// ComponentScope is the FGA component identifier bound to this installation
	// ("component:{name}"). The SDK requires it in the registration response and
	// the daemon stamps it into every per-RPC CG-JWT (gibson#648, ADR-0045).
	ComponentScope string
}

// RegisterCapabilityGrant resolves the capabilities a component principal
// actually holds, then writes the host, the agent, its grants, and — on a first
// registration — the record that spends the enrollment credential, all in one
// transaction. It emits an agent_registered audit event on success.
//
// Two invariants live here:
//
//   - The enrollment credential is one-time (ADR-0045). Presenting it a second
//     time is refused, so a credential that leaks after it has been used buys
//     nothing, and re-presenting one cannot resurrect a revoked host.
//     bootstrapType "host_jwt" is the sole exception: that caller authenticated
//     with a persistent host key it already holds.
//   - The grants written are the component principal's own, not its enroller's.
//     See ResolveComponentCapabilities.
//
// capabilityCeiling is the verified `scope` claim of the presented credential
// (see BootstrapClaims.CapabilityCeiling). When non-empty it caps the resolved
// set: a capability the credential does not name is not granted, however the
// FGA resolution turns out. The caller MUST pass only a ceiling it has verified
// — an attacker-supplied one would widen nothing (a ceiling can only remove),
// but it would still make the recorded grants a claim the daemon did not check.
func (s *CapabilityGrantService) RegisterCapabilityGrant(
	ctx context.Context,
	tenantID, ownerUserID, agentName, agentMode, principalRef string,
	hostPublicKeyJWK, agentPublicKeyJWK json.RawMessage,
	bootstrapType, bootstrapCredential string,
	capabilityCeiling []string,
) (*RegisterCapabilityGrantResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: tenant_id is required")
	}
	if ownerUserID == "" {
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: owner_user_id is required")
	}
	if agentName == "" {
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: agent_name is required")
	}
	if len(hostPublicKeyJWK) == 0 {
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: host_public_key_jwk is required")
	}
	if len(agentPublicKeyJWK) == 0 {
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: agent_public_key_jwk is required")
	}

	// A first registration must present the credential it is spending. Only a
	// caller re-registering with a host key it already holds arrives without
	// one, so anything else with an empty credential is refused rather than
	// enrolled un-metered.
	reRegistration := bootstrapType == hostReRegistrationBootstrapType
	if !reRegistration && bootstrapCredential == "" {
		return nil, errors.New("capabilitygrant: RegisterCapabilityGrant: enrollment credential is required")
	}

	// Derive stable IDs from the public key JWKs.
	// The host ID is a content-addressed thumbprint so that re-registrations from
	// the same host are idempotent.
	hostID, err := jwkThumbprint(hostPublicKeyJWK)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: host key thumbprint: %w", err)
	}
	agentID, err := newAgentID()
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: generate agent ID: %w", err)
	}

	// Normalise mode.
	mode := agentMode
	if mode != "delegated" && mode != "autonomous" {
		mode = "delegated"
	}

	// Resolve the capabilities this component principal actually holds, BEFORE
	// any write, so the whole registration can commit or fail as one unit.
	caps, err := s.fgaBridge.ResolveComponentCapabilities(ctx, principalRef, ownerUserID, tenantID)
	if err != nil {
		// Non-fatal: log and continue with zero grants. The agent is still
		// registered; grants can be re-resolved later.
		s.logger.WarnContext(ctx, "capabilitygrant: RegisterCapabilityGrant: FGA capability resolution failed, continuing with zero grants",
			slog.String("agent_id", agentID),
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		caps = []Capability{}
	}

	// Apply the credential's own ceiling. This runs AFTER the FGA resolution and
	// can only remove: the credential narrows what its bearer may become, it
	// never widens it. A capability granted to the enroller after the credential
	// was minted therefore cannot leak into a registration the credential did
	// not name.
	caps = capsWithinCeiling(caps, capabilityCeiling)

	// Add any reserved session capabilities (mission:delegate,
	// mission:originate) the credential's ceiling names. These are never
	// FGA-derived — see appendSessionCapabilities.
	caps = appendSessionCapabilities(caps, capabilityCeiling)

	grants := make([]Grant, 0, len(caps))
	for _, cap := range caps {
		grants = append(grants, Grant{
			AgentID:        agentID,
			CapabilityName: cap.Name,
			ComponentRef:   cap.ComponentRef,
			Status:         "active",
		})
	}

	enrollment := Enrollment{
		Host: Host{
			ID:           hostID,
			TenantID:     tenantID,
			UserID:       ownerUserID,
			DisplayName:  hostID[:8], // short display name until set explicitly
			PublicKeyJWK: hostPublicKeyJWK,
			Status:       "active",
			PrincipalRef: principalRef,
		},
		Agent: Agent{
			ID:           agentID,
			HostID:       hostID,
			TenantID:     tenantID,
			UserID:       ownerUserID,
			Name:         agentName,
			Mode:         mode,
			PublicKeyJWK: agentPublicKeyJWK,
			Status:       "active",
			PrincipalRef: principalRef,
		},
		Grants: grants,
	}
	if isSingleUseCredential(bootstrapType) {
		enrollment.BootstrapTokenHash = bootstrapCredentialHash(bootstrapCredential)
	}

	if err := s.store.Enroll(ctx, enrollment); err != nil {
		switch {
		case errors.Is(err, ErrBootstrapCredentialConsumed):
			s.logger.WarnContext(ctx, "capabilitygrant: RegisterCapabilityGrant: enrollment credential replayed",
				slog.String("tenant_id", tenantID),
				slog.String("host_id", hostID),
			)
		case errors.Is(err, ErrHostNotRegistrable):
			s.logger.WarnContext(ctx, "capabilitygrant: RegisterCapabilityGrant: host is not registrable by this tenant",
				slog.String("tenant_id", tenantID),
				slog.String("host_id", hostID),
			)
		}
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: enroll: %w", err)
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

	s.logger.InfoContext(ctx, "capabilitygrant: agent registered",
		slog.String("agent_id", agentID),
		slog.String("host_id", hostID),
		slog.String("tenant_id", tenantID),
		slog.Int("capabilities", len(caps)),
	)

	return &RegisterCapabilityGrantResult{
		AgentID:        agentID,
		HostID:         hostID,
		Capabilities:   caps,
		Status:         "active",
		ComponentScope: "component:" + agentName,
	}, nil
}

// ---------------------------------------------------------------------------
// ExecuteAgentCapability
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// HasCapability
// ---------------------------------------------------------------------------

// HasCapability reports whether principalRef (the FGA principal ref of the
// calling component, e.g. "agent_principal:<id>", exactly the value carried
// as the request's identity Subject once ext-authz has verified the caller's
// CG-JWT) holds an ACTIVE grant named capabilityName within tenantID, on an
// agent whose own status is also active.
//
// This is the read side of appendSessionCapabilities: it answers "does this
// grant carry mission:delegate / mission:originate" without going anywhere
// near FGA, because those two names are never FGA relations. It works
// equally well for any other capability_name already in the grants table
// (an execute:tool:x row resolves here too), which is intentional — a
// capability-gated RPC should not need to know whether the capability it
// checks happens to be FGA-derived.
//
// An empty principalRef or capabilityName reports false, false, nil rather
// than a query — an unauthenticated or malformed check must never be
// mistaken for "the store said no."
//
// Implements component.CapabilityChecker (structurally; component cannot
// import this package, see internal/platform/capname's doc comment for why).
func (s *CapabilityGrantService) HasCapability(ctx context.Context, tenantID, principalRef, capabilityName string) (bool, error) {
	if tenantID == "" || principalRef == "" || capabilityName == "" {
		return false, nil
	}
	has, err := s.store.HasActiveGrant(ctx, tenantID, principalRef, capabilityName)
	if err != nil {
		return false, fmt.Errorf("capabilitygrant: HasCapability: %w", err)
	}
	return has, nil
}

// ActiveGrantID returns the id of the ACTIVE grant that carries
// capabilityName for principalRef within tenantID, or "" when the principal
// does not hold it.
//
// This is the authorization answer AND the attribution answer in one call:
// gibson#1358's mission origination must record which grant permitted a
// mission, and asking twice (once "may I?", once "under which grant?") would
// leave a window where a revocation lands between the two and the recorded
// lineage names a grant that no longer allowed anything. An empty id means
// denied.
func (s *CapabilityGrantService) ActiveGrantID(ctx context.Context, tenantID, principalRef, capabilityName string) (string, error) {
	if tenantID == "" || principalRef == "" || capabilityName == "" {
		return "", nil
	}
	id, err := s.store.ActiveGrantID(ctx, tenantID, principalRef, capabilityName)
	if err != nil {
		return "", fmt.Errorf("capabilitygrant: ActiveGrantID: %w", err)
	}
	return id, nil
}

// ExecuteAgentCapabilityResult is the result returned by ExecuteAgentCapability.
type ExecuteAgentCapabilityResult struct {
	Result       []byte
	Status       string
	ErrorMessage string
}

// ExecuteAgentCapability checks FGA for permission to execute the requested
// capability, records an audit event, and dispatches work to the target
// component via the configured ComponentDispatcher.
func (s *CapabilityGrantService) ExecuteAgentCapability(
	ctx context.Context,
	agentID, capabilityName string,
	arguments []byte,
	tenantID string,
) (*ExecuteAgentCapabilityResult, error) {
	if agentID == "" {
		return nil, fmt.Errorf("capabilitygrant: ExecuteAgentCapability: agent_id is required")
	}
	if capabilityName == "" {
		return nil, fmt.Errorf("capabilitygrant: ExecuteAgentCapability: capability_name is required")
	}
	if tenantID == "" {
		return nil, errors.New("capabilitygrant: ExecuteAgentCapability: tenant_id is required")
	}

	// Resolve the agent WITHIN the caller's tenant: an agent id from another
	// tenant must read as absent, not as an executable identity.
	agent, err := s.store.GetAgentInTenant(ctx, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: ExecuteAgentCapability: store lookup: %w", err)
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

	// Authorize the COMPONENT PRINCIPAL that is executing — the identity minted
	// for this installation — not the human who enrolled it. Checking the
	// fetched row's owner asked "may the account that owns this agent execute
	// this?", which the owner of any agent answers yes to, and let the component
	// act with its enroller's whole authority for as long as it exists.
	//
	// An agent row with no principal has no identity to authorize, so it is
	// denied rather than falling back to a broader subject.
	if agent.PrincipalRef == "" {
		return &ExecuteAgentCapabilityResult{
			Status:       "error",
			ErrorMessage: "permission denied: agent has no component principal",
		}, nil
	}
	allowed, err := s.fgaBridge.CheckExecution(ctx, agent.PrincipalRef, componentRef)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: ExecuteAgentCapability: FGA check: %w", err)
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
		s.logger.WarnContext(ctx, "capabilitygrant: ExecuteAgentCapability: dispatch failed",
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
func (s *CapabilityGrantService) ListAgentCapabilities(
	ctx context.Context,
	tenantID, userID string,
) ([]Capability, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("capabilitygrant: ListAgentCapabilities: tenant_id is required")
	}
	if userID == "" {
		return nil, fmt.Errorf("capabilitygrant: ListAgentCapabilities: user_id is required")
	}
	return s.fgaBridge.ResolveCapabilities(ctx, userID, tenantID)
}

// ---------------------------------------------------------------------------
// GetCapabilityGrantStatus
// ---------------------------------------------------------------------------

// CapabilityGrantStatusResult carries agent status and grants.
type CapabilityGrantStatusResult struct {
	Agent  *Agent
	Grants []Grant
}

// GetCapabilityGrantStatus retrieves the agent record and all its grants from the store.
// Returns (nil, nil) when no agent with the given ID exists.
func (s *CapabilityGrantService) GetCapabilityGrantStatus(
	ctx context.Context,
	agentID, tenantID string,
) (*CapabilityGrantStatusResult, error) {
	if agentID == "" {
		return nil, fmt.Errorf("capabilitygrant: GetCapabilityGrantStatus: agent_id is required")
	}
	if tenantID == "" {
		return nil, errors.New("capabilitygrant: GetCapabilityGrantStatus: tenant_id is required")
	}

	agent, err := s.store.GetAgentInTenant(ctx, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: GetCapabilityGrantStatus: %w", err)
	}
	if agent == nil {
		return nil, nil
	}

	grants, err := s.store.GetGrants(ctx, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: GetCapabilityGrantStatus: get grants: %w", err)
	}

	return &CapabilityGrantStatusResult{
		Agent:  agent,
		Grants: grants,
	}, nil
}

// ---------------------------------------------------------------------------
// RevokeCapabilityGrant
// ---------------------------------------------------------------------------

// RevokeCapabilityGrant revokes the agent and all its grants, then emits an
// agent_revoked audit event.
func (s *CapabilityGrantService) RevokeCapabilityGrant(
	ctx context.Context,
	agentID, tenantID, actorID string,
) error {
	if agentID == "" {
		return fmt.Errorf("capabilitygrant: RevokeCapabilityGrant: agent_id is required")
	}
	if tenantID == "" {
		return errors.New("capabilitygrant: RevokeCapabilityGrant: tenant_id is required")
	}

	if err := s.store.RevokeAgent(ctx, tenantID, agentID); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeCapabilityGrant: %w", err)
	}

	s.auditWriter.Log(audit.Event{
		TenantID:   tenantID,
		ActorID:    actorID,
		ActorType:  "user",
		Action:     "agent_revoked",
		TargetType: "agent",
		TargetID:   agentID,
	})

	s.logger.InfoContext(ctx, "capabilitygrant: agent revoked",
		slog.String("agent_id", agentID),
		slog.String("tenant_id", tenantID),
	)
	return nil
}

// ---------------------------------------------------------------------------
// ListCapabilityGrantAgents
// ---------------------------------------------------------------------------

// ListCapabilityGrantAgentsResult carries the paginated agent list.
type ListCapabilityGrantAgentsResult struct {
	Agents []Agent
	Total  int
}

// ListCapabilityGrantAgents returns a paginated list of agents for a tenant.
func (s *CapabilityGrantService) ListCapabilityGrantAgents(
	ctx context.Context,
	tenantID string,
	limit, offset int,
) (*ListCapabilityGrantAgentsResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("capabilitygrant: ListCapabilityGrantAgents: tenant_id is required")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	agents, total, err := s.store.ListAgentsByTenant(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: ListCapabilityGrantAgents: %w", err)
	}

	return &ListCapabilityGrantAgentsResult{
		Agents: agents,
		Total:  total,
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
func (s *CapabilityGrantService) ListComponentGrants(
	ctx context.Context,
	tenantID string,
) ([]ComponentGrantResult, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("capabilitygrant: ListComponentGrants: tenant_id is required")
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
		s.logger.WarnContext(ctx, "capabilitygrant: ListComponentGrants: failed to list tenant users",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		tenantUsers = []string{}
	}

	for _, fgaUserStr := range tenantUsers {
		for _, rel := range relations {
			objects, err := s.authorizer.ListObjects(ctx, fgaUserStr, rel.fgaRelation, "component")
			if err != nil {
				s.logger.WarnContext(ctx, "capabilitygrant: ListComponentGrants: ListObjects failed",
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
// ListAuditLog
// ---------------------------------------------------------------------------

// ListAuditLog returns a paginated list of audit log entries from Postgres.
func (s *CapabilityGrantService) ListAuditLog(
	ctx context.Context,
	tenantID, actorID, action, targetType string,
	limit, offset int,
) ([]audit.PgEntry, int, error) {
	if tenantID == "" {
		return nil, 0, fmt.Errorf("capabilitygrant: ListAuditLog: tenant_id is required")
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

	var key struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(jwk, &key); err != nil {
		return "", fmt.Errorf("parse JWK: %w", err)
	}
	if key.Kty != "OKP" || key.Crv != "Ed25519" || key.X == "" {
		// Only Ed25519 host keys exist (parseJWKEd25519 enforces the same), and
		// silently thumbprinting something else would mint an id for a key the
		// verifier will later refuse.
		return "", fmt.Errorf("unsupported host key: kty=%q crv=%q (want OKP/Ed25519)", key.Kty, key.Crv)
	}

	// RFC 7638 §3: SHA-256 over the required members only, lexicographically
	// ordered, no whitespace — for OKP that is crv, kty, x — base64url, unpadded.
	//
	// This MUST match what the client computes, because the client signs its
	// host+jwt with `iss` set to it and the daemon looks the host up by that
	// value. The previous implementation hashed the RAW JWK BYTES and truncated
	// to 8, producing a "host_<hex>" id no client could ever derive: every
	// re-registration with a host key was an unknown-host 401, so the persisted
	// key never worked and only a fresh human-issued bootstrap token did —
	// defeating ADR-0045's unattended restart entirely (gibson#1207).
	//
	// Hashing the raw bytes also made the "content-addressed, so re-registration
	// is idempotent" claim false: the same key serialised with different field
	// order hashed differently.
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, key.Crv, key.Kty, key.X)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// parseCapabilityName parses a capability name in "{verb}:{kind}:{name}" format
// and returns the FGA component ref ("component:{kind}/{name}"), the kind, and the name.
// Returns ("", "", "", false) if the format is invalid.
func parseCapabilityName(capName string) (componentRef, kind, name string, ok bool) {
	parts := strings.SplitN(capName, ":", 3)
	if len(parts) != 3 || parts[2] == "" || !authz.IsComponentKind(parts[1]) {
		return "", "", "", false
	}
	// The capability name carries the kind ("{verb}:{kind}:{name}"), so the FGA
	// object is the canonical kind-prefixed ref (ADR-0015).
	return authz.ComponentObject(parts[1], parts[2]), parts[1], parts[2], true
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
