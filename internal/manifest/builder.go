package manifest

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/capabilitygrant"
	"github.com/zero-day-ai/gibson/internal/component"

	identitypb "github.com/zero-day-ai/sdk/api/gen/gibson/identity/v1"
	manifestpb "github.com/zero-day-ai/sdk/api/gen/gibson/manifest/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BuilderDeps bundles the collaborators a Builder requires. Every field
// is exported so daemon wiring can populate them one-by-one; Builder
// validates presence at construction time.
type BuilderDeps struct {
	FGA      FGAResolver
	Registry RegistrySource
	Signer   Signer
	Versions VersionStore

	// Optional: nil-safe. Builder substitutes empty defaults when absent.
	Tiers  TierLimitsSource
	Memory MemoryPolicySource
	LLM    LLMSlotSource
	Audit  AuditWriter

	// Logger is optional; defaults to slog.Default().
	Logger *slog.Logger

	// Clock is optional; defaults to time.Now. Tests inject a fake.
	Clock func() time.Time
}

// manifestBuilder implements Builder.
type manifestBuilder struct {
	deps BuilderDeps
	cfg  BuilderConfig
}

// NewBuilder constructs a Builder from its dependencies and config.
// Fails fast on missing required collaborators so misconfiguration is a
// startup error rather than a runtime surprise.
func NewBuilder(deps BuilderDeps, cfg BuilderConfig) (Builder, error) {
	if deps.FGA == nil {
		return nil, fmt.Errorf("manifest: NewBuilder: FGA resolver is required")
	}
	if deps.Registry == nil {
		return nil, fmt.Errorf("manifest: NewBuilder: Registry source is required")
	}
	if deps.Signer == nil {
		return nil, fmt.Errorf("manifest: NewBuilder: Signer is required")
	}
	if deps.Versions == nil {
		return nil, fmt.Errorf("manifest: NewBuilder: VersionStore is required")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	return &manifestBuilder{deps: deps, cfg: cfg.defaults()}, nil
}

// Build composes the manifest per design.md:
//
//  1. tenant resolution (from subject.TenantID)
//  2. FGA capability resolution (+agent_principal intersection if needed)
//  3. registry enrichment via DiscoverAll — drops components the subject
//     has no FGA relation on
//  4. cross-component rule resolution
//  5. tier limits / LLM slots / memory policy projection
//  6. version stamp from VersionStore.Current (cached 1s)
//  7. sign
//
// Fail-closed: any FGA error propagates; no partial manifests.
func (b *manifestBuilder) Build(ctx context.Context, subject ManifestSubject) (*manifestpb.CapabilityManifest, error) {
	start := b.deps.Clock()

	if err := validateSubject(subject); err != nil {
		return nil, err
	}
	tenantID := subject.TenantID
	if tenantID == "" {
		return nil, fmt.Errorf("manifest: Build: subject has no tenant — caller must resolve tenant before invoking Build")
	}

	// --- (2) + agent_principal intersection -------------------------------
	var (
		caps      []capabilitygrant.Capability
		ownerCaps []capabilitygrant.Capability
	)
	switch subject.Type {
	case SubjectTypeUser:
		c, err := b.deps.FGA.ResolveCapabilities(ctx, subject.ID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("manifest: Build: ResolveCapabilities(user): %w", err)
		}
		caps = c
	case SubjectTypeAgentPrincipal:
		if subject.OwnerUserID == "" {
			return nil, fmt.Errorf("manifest: Build: agent_principal subject requires OwnerUserID")
		}
		// Agent's own grants, looked up through the agent_principal FGA ref.
		agentSubject := "agent_principal:" + subject.ID
		owner, err := b.deps.FGA.ResolveCapabilities(ctx, subject.OwnerUserID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("manifest: Build: ResolveCapabilities(owner): %w", err)
		}
		ownerCaps = owner
		intersection, err := b.deps.FGA.ResolveAgentPrincipalIntersection(ctx, subject.ID, subject.OwnerUserID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("manifest: Build: ResolveAgentPrincipalIntersection: %w", err)
		}
		// Build per-component permission list by consulting owner caps as
		// the reachable set; the agent_principal's subset is the
		// intersection already.
		caps = projectAgentCapabilities(agentSubject, intersection, owner)
		_ = agentSubject
	default:
		return nil, fmt.Errorf("manifest: Build: unknown subject type %q", subject.Type)
	}

	// --- (3) registry enrichment ----------------------------------------
	componentInfos, err := b.deps.Registry.DiscoverAll(ctx, tenantID, "")
	if err != nil {
		return nil, fmt.Errorf("manifest: Build: DiscoverAll: %w", err)
	}
	permittedByName := indexPermissions(caps)
	agents, tools, plugins, scope := projectComponents(componentInfos, permittedByName)

	// --- (4) cross-component rule resolution ----------------------------
	subjectFGA := subjectFGARef(subject)
	rules, err := b.deps.FGA.ResolveCrossComponentRules(ctx, subjectFGA, scope)
	if err != nil {
		return nil, fmt.Errorf("manifest: Build: ResolveCrossComponentRules: %w", err)
	}
	truncated := false
	if len(rules) > b.cfg.CrossComponentRuleHardCap {
		b.deps.Logger.Warn("manifest: cross-component rule hard cap exceeded — truncating",
			"count", len(rules), "cap", b.cfg.CrossComponentRuleHardCap, "tenant", tenantID)
		rules = rules[:b.cfg.CrossComponentRuleHardCap]
		truncated = true
	}
	pbRules := convertRules(rules)

	// --- (5) optional projections ---------------------------------------
	limits, memory, slots := b.projectAuxiliary(ctx, tenantID, subject)

	// --- (6) stamping ---------------------------------------------------
	version, err := b.deps.Versions.Current(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("manifest: Build: VersionStore.Current: %w", err)
	}
	issuedAt := b.deps.Clock()
	expiresAt := issuedAt.Add(b.cfg.TTL)

	m := &manifestpb.CapabilityManifest{
		ManifestId:                   newManifestID(issuedAt),
		ManifestVersion:              version,
		TenantId:                     tenantID,
		Subject:                      subjectFGA,
		IssuedAt:                     timestamppb.New(issuedAt),
		ExpiresAt:                    timestamppb.New(expiresAt),
		TtlSeconds:                   uint32(b.cfg.TTL.Seconds()),
		TenantContext:                &manifestpb.TenantContext{TenantId: tenantID},
		Agents:                       agents,
		Tools:                        tools,
		Plugins:                      plugins,
		CrossComponentRules:          pbRules,
		CrossComponentRulesTruncated: truncated,
		Limits:                       limits,
		AvailableLlmSlots:            slots,
		Memory:                       memory,
	}

	// --- (7) sign -------------------------------------------------------
	if err := b.deps.Signer.Sign(m); err != nil {
		return nil, fmt.Errorf("manifest: Build: Sign: %w", err)
	}

	// Best-effort audit write — failure never fails the Build.
	if b.deps.Audit != nil {
		if err := b.deps.Audit.RecordIssuance(ctx, m, nil); err != nil {
			b.deps.Logger.Warn("manifest: audit write failed (non-fatal)",
				"manifest_id", m.ManifestId, "error", err)
		}
	}

	b.deps.Logger.Info("manifest: issued",
		"manifest_id", m.ManifestId,
		"tenant_id", tenantID,
		"subject", subjectFGA,
		"version", version,
		"components", len(agents)+len(tools)+len(plugins),
		"cross_rules", len(pbRules),
		"duration_ms", time.Since(start).Milliseconds(),
	)
	_ = ownerCaps
	return m, nil
}

func (b *manifestBuilder) projectAuxiliary(ctx context.Context, tenantID string, subject ManifestSubject) (*manifestpb.LimitsAndQuotas, *manifestpb.MemoryPermissions, []string) {
	var (
		limits *manifestpb.LimitsAndQuotas
		memory *manifestpb.MemoryPermissions
		slots  []string
	)
	if b.deps.Tiers != nil {
		if l, err := b.deps.Tiers.LimitsFor(ctx, tenantID); err != nil {
			b.deps.Logger.Warn("manifest: tier limits lookup failed", "tenant", tenantID, "error", err)
		} else {
			limits = l
		}
	}
	if b.deps.Memory != nil {
		if mp, err := b.deps.Memory.MemoryPolicy(ctx, tenantID, subject); err != nil {
			b.deps.Logger.Warn("manifest: memory policy lookup failed", "tenant", tenantID, "error", err)
		} else {
			memory = mp
		}
	}
	if b.deps.LLM != nil {
		if s, err := b.deps.LLM.AvailableSlots(ctx, tenantID, subject); err != nil {
			b.deps.Logger.Warn("manifest: llm slot lookup failed", "tenant", tenantID, "error", err)
		} else {
			slots = s
		}
	}
	return limits, memory, slots
}

func validateSubject(s ManifestSubject) error {
	if s.ID == "" || s.Type == "" {
		return fmt.Errorf("manifest: subject missing type or id")
	}
	if s.Type != SubjectTypeUser && s.Type != SubjectTypeAgentPrincipal {
		return fmt.Errorf("manifest: invalid subject type %q", s.Type)
	}
	return nil
}

func subjectFGARef(s ManifestSubject) string { return s.FGARef() }

// projectAgentCapabilities narrows the owner's cap list to the intersection
// produced by FGABridge.ResolveAgentPrincipalIntersection, rekeying the
// subject field to the agent_principal so ComponentCapability.permissions
// reflect the agent's reachable surface.
func projectAgentCapabilities(agentSubject string, intersection []capabilitygrant.ComponentRef, owner []capabilitygrant.Capability) []capabilitygrant.Capability {
	if len(intersection) == 0 || len(owner) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(intersection))
	for _, r := range intersection {
		allowed[r.FGARef()] = struct{}{}
	}
	var out []capabilitygrant.Capability
	for _, c := range owner {
		if _, ok := allowed[c.ComponentRef]; !ok {
			continue
		}
		out = append(out, c)
	}
	_ = agentSubject
	return out
}

// indexPermissions returns name → sorted permission list for the
// "{relation}" prefixes FGABridge emits in Capability.Name.
func indexPermissions(caps []capabilitygrant.Capability) map[string][]string {
	idx := make(map[string][]string)
	for _, c := range caps {
		// c.Name format: "verb:kind:name"
		parts := strings.SplitN(c.Name, ":", 3)
		if len(parts) != 3 {
			continue
		}
		verb, name := parts[0], parts[2]
		// Convert verb back to FGA relation (execute→can_execute etc).
		var relation string
		switch verb {
		case "execute":
			relation = "can_execute"
		case "read":
			relation = "can_read"
		case "configure":
			relation = "can_configure"
		default:
			relation = verb
		}
		idx[name] = appendUnique(idx[name], relation)
	}
	return idx
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

// projectComponents takes live registry entries and a permission index,
// and emits three kind-sorted slices of ComponentCapability plus the
// flat scope list used by cross-component rule resolution.
// Components with no permissions in the index are dropped.
func projectComponents(infos []component.ComponentInfo, perms map[string][]string) (agents, tools, plugins []*manifestpb.ComponentCapability, scope []capabilitygrant.ComponentRef) {
	// Dedupe by (kind, name) — the registry may return multiple instances
	// of the same component.
	type key struct{ kind, name string }
	seen := make(map[key]struct{}, len(infos))
	for _, info := range infos {
		k := key{info.Kind, info.Name}
		if _, dup := seen[k]; dup {
			continue
		}
		permissions := perms[info.Name]
		if len(permissions) == 0 {
			continue
		}
		seen[k] = struct{}{}
		cc := &manifestpb.ComponentCapability{
			Name:          info.Name,
			Kind:          info.Kind,
			PrincipalKind: principalKindFromString(info.Kind),
			ComponentRef:  "component:" + info.Name,
			Version:       info.Version,
			Description:   info.Description,
			IsSystem:      info.TenantID == "_system",
			OwnerTenant:   info.TenantID,
			Permissions:   permissions,
			Liveness: &manifestpb.ComponentLiveness{
				Status:        "running",
				LastHeartbeat: timestamppb.New(info.LastHeartbeat),
				InstanceCount: 1,
			},
		}
		scope = append(scope, capabilitygrant.ComponentRef{Name: info.Name, Kind: info.Kind})
		switch info.Kind {
		case "agent":
			agents = append(agents, cc)
		case "tool":
			tools = append(tools, cc)
		case "plugin":
			plugins = append(plugins, cc)
		}
	}
	return agents, tools, plugins, scope
}

// principalKindFromString maps the legacy string kind on
// ComponentCapability to the typed PrincipalKind. Returns
// PRINCIPAL_KIND_UNSPECIFIED for unknown values, which the manifest
// consumers (CLI validate, daemon RegisterPlugin) flag as a
// deprecation warning rather than an error during the backward-compat
// window.
//
// Spec: component-bootstrap-e2e Requirement 12.
func principalKindFromString(kind string) identitypb.PrincipalKind {
	switch kind {
	case "agent":
		return identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT
	case "tool":
		return identitypb.PrincipalKind_PRINCIPAL_KIND_TOOL
	case "plugin":
		return identitypb.PrincipalKind_PRINCIPAL_KIND_PLUGIN
	default:
		return identitypb.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED
	}
}

func convertRules(rules []capabilitygrant.CrossRule) []*manifestpb.CrossComponentRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]*manifestpb.CrossComponentRule, 0, len(rules))
	for _, r := range rules {
		var effect manifestpb.CrossComponentRule_Effect
		switch r.Effect {
		case capabilitygrant.EffectAllow:
			effect = manifestpb.CrossComponentRule_EFFECT_ALLOW
		case capabilitygrant.EffectDeny:
			effect = manifestpb.CrossComponentRule_EFFECT_DENY
		default:
			effect = manifestpb.CrossComponentRule_EFFECT_UNSPECIFIED
		}
		out = append(out, &manifestpb.CrossComponentRule{
			SourceComponentRef: r.Source,
			TargetComponentRef: r.Target,
			Effect:             effect,
			Reason:             r.Reason,
		})
	}
	return out
}

// newManifestID returns a ULID-ish identifier stable enough for audit
// keying. Format: 01<48 bits of ms timestamp>-<80 bits randomness>
// expressed in Crockford base32 without padding. Not strictly ULID RFC
// but preserves the time-ordered property without pulling another dep.
func newManifestID(now time.Time) string {
	var buf [16]byte
	ms := uint64(now.UnixMilli())
	for i := 0; i < 6; i++ {
		buf[i] = byte(ms >> (40 - 8*i))
	}
	if _, err := rand.Read(buf[6:]); err != nil {
		// best-effort — fall back to all-zero randomness so audit keys
		// can still be written if rand fails.
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf[:])
	return "M" + enc
}
