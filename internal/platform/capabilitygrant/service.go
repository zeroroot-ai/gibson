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
			Attested:     bootstrapType == BootstrapTypeSPIFFESVID,
			// A re-registration keeps what the row has (touchHostTx).
			AgentName:         agentName,
			CapabilityCeiling: capabilityCeiling,
		},
		KeepHostAttestation: reRegistration,
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

	// The audit record is durable before the identity exists (ADR-0113,
	// gibson#676). A failed write fails the registration.
	meta, _ := json.Marshal(map[string]any{
		"agent_name":       agentName,
		"agent_mode":       mode,
		"bootstrap_type":   bootstrapType,
		"capability_count": len(caps),
	})
	registered := audit.Event{
		TenantID:   tenantID,
		ActorID:    ownerUserID,
		ActorType:  "user",
		Action:     "agent_registered",
		TargetType: "agent",
		TargetID:   agentID,
		Metadata:   json.RawMessage(meta),
	}
	if err := s.auditWriter.WriteSync(ctx, registered); err != nil {
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: audit: %w", err)
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
		s.recordFailure(ctx, registered, err)
		return nil, fmt.Errorf("capabilitygrant: RegisterCapabilityGrant: enroll: %w", err)
	}

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

// LookupEnrolledAgent returns the registered name of the active agent enrolled
// under principalRef in tenantID, and the subject of the person who enrolled
// it. Both are empty when the registry has no active agent for the principal.
//
// This is the attribution read for a finding an enrolled agent submits
// (gibson#208): the principal is what ext-authz verified, and this call turns
// it into the name the agent registered under and the person behind it. An
// empty principalRef or tenantID answers empty rather than querying.
//
// Implements component.EnrolledAgentLookup (structurally; component cannot
// import this package, see internal/platform/capname's doc comment for why).
func (s *CapabilityGrantService) LookupEnrolledAgent(ctx context.Context, tenantID, principalRef string) (agentName, enrolledBy string, err error) {
	if tenantID == "" || principalRef == "" {
		return "", "", nil
	}
	ag, err := s.store.AgentByPrincipal(ctx, tenantID, principalRef)
	if err != nil {
		return "", "", fmt.Errorf("capabilitygrant: LookupEnrolledAgent: %w", err)
	}
	if ag == nil {
		return "", "", nil
	}
	return ag.Name, ag.UserID, nil
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

// recordFailure writes the second audit record of a state change whose
// action failed. The action already failed, so a write error is logged and
// the caller still gets the error of the action.
func (s *CapabilityGrantService) recordFailure(ctx context.Context, ev audit.Event, cause error) {
	if err := s.auditWriter.WriteSync(ctx, failedAction(ev, cause)); err != nil {
		s.logger.ErrorContext(ctx, "capabilitygrant: the failure record of an action was not written",
			slog.String("action", ev.Action),
			slog.String("target_id", ev.TargetID),
			slog.String("error", err.Error()),
		)
	}
}

// failedAction is the second audit record of a state change whose action
// failed after its first record was durable (gibson#676). It names the
// same action and target, with the decision "deny" and the cause.
func failedAction(ev audit.Event, cause error) audit.Event {
	meta, _ := json.Marshal(map[string]any{"result": "failure", "error": cause.Error()})
	ev.Decision = "deny"
	ev.Metadata = json.RawMessage(meta)
	return ev
}

// HostKeyID returns the host id of a host public key: the id that a host
// stores and signs a host+jwt under. The register endpoint compares it with
// the id of the host that signed the credential.
func HostKeyID(jwk json.RawMessage) (string, error) {
	return jwkThumbprint(jwk)
}
