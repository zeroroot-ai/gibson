package capabilitygrant

import (
	"context"
	"fmt"
	"strings"
)

// CrossComponentRuleEffect distinguishes explicit ALLOW/DENY overrides
// surfaced in the manifest. The values mirror the proto enum but live
// here so FGABridge does not need to import the manifest proto package.
type CrossComponentRuleEffect int

const (
	// EffectUnspecified is the zero value; never emitted.
	EffectUnspecified CrossComponentRuleEffect = iota
	// EffectAllow indicates an explicit can_be_invoked_by grant that
	// overrides the default can_execute evaluation.
	EffectAllow
	// EffectDeny indicates an explicit cannot_invoke tuple that denies
	// invocation regardless of any positive grants the subject holds.
	EffectDeny
)

// CrossRule is the daemon-local representation of a cross-component
// invocation override. Builder (Task 9) converts these into
// manifestpb.CrossComponentRule.
type CrossRule struct {
	Source string // FGA ref, e.g. "agent_principal:X" or "component:nmap-agent"
	Target string // FGA ref, e.g. "component:gitlab"
	Effect CrossComponentRuleEffect
	Reason string // "fga_deny", "fga_grant"
}

// ComponentRef is an opaque FGA-addressable component reference used by
// the bridge's manifest-oriented methods. It mirrors manifest.ComponentRef
// but lives in capabilitygrant so that package does not import manifest.
type ComponentRef struct {
	Name string // e.g. "nmap"
	Kind string // "agent" | "tool" | "plugin"
}

// FGARef returns "component:<name>" for this reference.
func (c ComponentRef) FGARef() string {
	if c.Name == "" {
		return ""
	}
	return "component:" + c.Name
}

// ResolveCrossComponentRules evaluates cross-component invocation
// overrides for the given subject against every component in scope.
// Only rules that actually override the default can_execute evaluation
// are returned — rules absent from FGA are not emitted.
//
// The subjectFGA must be a valid FGA reference ("agent_principal:<id>"
// or "component:<name>"). components is the scope returned by prior
// capability resolution — only these targets are considered.
//
// Implementation uses ListObjects to harvest all cannot_invoke /
// can_be_invoked_by tuples the subject has, which is O(1) FGA calls
// rather than O(N) Check calls per target. For agent_principal subjects
// both relations are consulted; for component subjects only
// can_be_invoked_by applies (cannot_invoke is agent_principal-only).
func (b *FGABridge) ResolveCrossComponentRules(ctx context.Context, subjectFGA string, components []ComponentRef) ([]CrossRule, error) {
	if subjectFGA == "" {
		return nil, fmt.Errorf("capabilitygrant: ResolveCrossComponentRules: empty subject")
	}
	if len(components) == 0 {
		return nil, nil
	}

	// Build the target set for O(1) intersection.
	targetSet := make(map[string]struct{}, len(components))
	for _, c := range components {
		if ref := c.FGARef(); ref != "" {
			targetSet[ref] = struct{}{}
		}
	}

	// Harvest explicit DENY targets (only meaningful for agent_principal
	// subjects — the FGA schema places cannot_invoke on agent_principal).
	var denyObjects []string
	if strings.HasPrefix(subjectFGA, "agent_principal:") {
		objs, err := b.authorizer.ListObjects(ctx, subjectFGA, "cannot_invoke", "component")
		if err != nil {
			return nil, fmt.Errorf("capabilitygrant: ListObjects(cannot_invoke): %w", err)
		}
		denyObjects = objs
	}

	// Harvest explicit ALLOW targets via can_be_invoked_by. FGA's schema
	// permits both agent_principal and component as user types, so this
	// lookup works for either subject kind.
	allowObjects, err := b.authorizer.ListObjects(ctx, subjectFGA, "can_be_invoked_by", "component")
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: ListObjects(can_be_invoked_by): %w", err)
	}

	rules := make([]CrossRule, 0, len(denyObjects)+len(allowObjects))
	denySeen := make(map[string]struct{}, len(denyObjects))

	// DENY wins — emit first so downstream consumers observe them first.
	for _, obj := range denyObjects {
		if _, inScope := targetSet[obj]; !inScope {
			continue
		}
		denySeen[obj] = struct{}{}
		rules = append(rules, CrossRule{
			Source: subjectFGA,
			Target: obj,
			Effect: EffectDeny,
			Reason: "fga_deny",
		})
	}
	for _, obj := range allowObjects {
		if _, inScope := targetSet[obj]; !inScope {
			continue
		}
		// A target that is both denied AND allowed surfaces only as the
		// DENY rule — a DENY always overrides a positive grant.
		if _, denied := denySeen[obj]; denied {
			continue
		}
		rules = append(rules, CrossRule{
			Source: subjectFGA,
			Target: obj,
			Effect: EffectAllow,
			Reason: "fga_grant",
		})
	}
	return rules, nil
}

// ResolveAgentPrincipalIntersection returns the components reachable by
// BOTH an agent_principal AND its owner user. The manifest must never
// surface components the owner cannot reach, even if a misconfigured
// tuple gives the agent a broader grant than its owner has.
//
// The intersection is the set of component_refs that appear in both
// capability result sets (any relation). Result kind is populated from
// the agent_principal's resolved capabilities since those are
// registry-enriched by ResolveCapabilities.
func (b *FGABridge) ResolveAgentPrincipalIntersection(ctx context.Context, agentPrincipalID, ownerUserID, tenantID string) ([]ComponentRef, error) {
	if agentPrincipalID == "" {
		return nil, fmt.Errorf("capabilitygrant: ResolveAgentPrincipalIntersection: empty agentPrincipalID")
	}
	if ownerUserID == "" {
		return nil, fmt.Errorf("capabilitygrant: ResolveAgentPrincipalIntersection: empty ownerUserID")
	}

	ownerCaps, err := b.ResolveCapabilities(ctx, ownerUserID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: owner capabilities: %w", err)
	}
	ownerRefs := make(map[string]struct{}, len(ownerCaps))
	for _, c := range ownerCaps {
		ownerRefs[c.ComponentRef] = struct{}{}
	}

	// For the agent_principal we query FGA directly under the
	// "agent_principal:<id>" subject across the three relations.
	agentSubject := "agent_principal:" + agentPrincipalID
	type keyedCap struct {
		ref  string
		kind string
	}
	seen := make(map[string]keyedCap)
	for _, rel := range relations {
		objs, err := b.authorizer.ListObjects(ctx, agentSubject, rel.fgaRelation, "component")
		if err != nil {
			return nil, fmt.Errorf("capabilitygrant: agent ListObjects(%s): %w", rel.fgaRelation, err)
		}
		for _, obj := range objs {
			if _, dup := seen[obj]; dup {
				continue
			}
			name, ok := parseComponentRef(obj)
			if !ok {
				continue
			}
			seen[obj] = keyedCap{ref: obj, kind: resolveKind(ownerCaps, name)}
		}
	}

	out := make([]ComponentRef, 0, len(seen))
	for ref, kc := range seen {
		if _, ok := ownerRefs[ref]; !ok {
			continue
		}
		name, ok := parseComponentRef(ref)
		if !ok {
			continue
		}
		out = append(out, ComponentRef{Name: name, Kind: kc.kind})
	}
	return out, nil
}

// resolveKind picks the kind for name from a []Capability, returning
// "unknown" when the name isn't present. Used during intersection so
// result entries carry a stable kind without a second registry pass.
func resolveKind(caps []Capability, name string) string {
	for _, c := range caps {
		if strings.TrimPrefix(c.ComponentRef, "component:") == name {
			return c.Kind
		}
	}
	return "unknown"
}
