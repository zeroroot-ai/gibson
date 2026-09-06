// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package capabilitygrant provides the FGA bridge for resolving agent capabilities
// from OpenFGA relationship tuples and the component registry.
//
// The FGABridge translates between FGA relationships and Agent Auth capability
// objects. When an agent registers, the daemon uses the bridge to determine
// what capabilities to grant based on the agent owner's FGA permissions.
package capabilitygrant

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// Capability represents a resolved permission for an agent to interact with
// a specific component. The Name field encodes the relation and component
// identity using colon-delimited notation:
//
//	"execute:tool:nmap"   — can_execute granted on component nmap (kind: tool)
//	"read:agent:recon"    — can_read granted on component recon (kind: agent)
//	"configure:plugin:gitlab" — can_configure granted on component gitlab (kind: plugin)
type Capability struct {
	// Name is the canonical string representation of the capability.
	// Format: "{relation}:{kind}:{component-name}"
	Name string

	// ComponentRef is the FGA object reference for the component.
	// Format: "component:{name}"
	ComponentRef string

	// Kind is the component kind: "tool", "agent", or "plugin".
	Kind string

	// Description is the human-readable description from the component registry.
	// May be empty if the component has no description metadata.
	Description string
}

// FGABridge translates FGA relationship tuples into Agent Auth capabilities.
//
// It queries the Authorizer for the set of objects a user has a given relation
// on, then cross-references those objects against the ComponentRegistry to
// enrich the capabilities with kind and description metadata.
//
// FGABridge does not cache results — callers are expected to cache at the
// appropriate layer (e.g., the agent registration handler).
//
// FGABridge is safe for concurrent use provided the injected Authorizer and
// ComponentRegistry implementations are also safe for concurrent use.
type FGABridge struct {
	authorizer authz.Authorizer
	registry   component.ComponentRegistry
	logger     *slog.Logger
}

// NewFGABridge creates an FGABridge wired to the given Authorizer and
// ComponentRegistry. Both dependencies are required and must be non-nil.
// If logger is nil, slog.Default() is used.
func NewFGABridge(authorizer authz.Authorizer, registry component.ComponentRegistry, logger *slog.Logger) *FGABridge {
	if logger == nil {
		logger = slog.Default()
	}
	return &FGABridge{
		authorizer: authorizer,
		registry:   registry,
		logger:     logger,
	}
}

// relations enumerates the FGA relations that map to agent capabilities.
// Each entry maps an FGA relation name to the capability prefix used in the
// Capability.Name field.
var relations = []struct {
	fgaRelation    string // e.g. "can_execute"
	capabilityVerb string // e.g. "execute"
}{
	{"can_execute", "execute"},
	{"can_read", "read"},
	{"can_configure", "configure"},
}

// ResolveCapabilities returns all capabilities granted to the given user
// within the given tenant. It queries FGA for the set of components the user
// can execute, read, and configure, then enriches each grant with component
// metadata from the registry.
//
// The registry is queried with DiscoverAll using an empty kind filter so that
// all component kinds (tool, agent, plugin) are returned. Both tenant-scoped
// and system-scoped components are included because DiscoverAll merges both
// namespaces.
//
// Results are deduplicated by (relation, component-name) so that a user with
// the same capability granted via multiple FGA paths receives only one entry.
//
// An empty slice (not nil) is returned when the user has no FGA grants.
func (b *FGABridge) ResolveCapabilities(ctx context.Context, userID, tenantID string) ([]Capability, error) {
	fgaUser := "user:" + userID

	// Collect component metadata from the registry once so we can look up kind
	// and description without a per-component round-trip.
	allComponents, err := b.registry.DiscoverAll(ctx, tenantID, "")
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: failed to discover components for tenant %q: %w", tenantID, err)
	}

	// Build a name→info index for O(1) look-up. When multiple instances of
	// the same component (name+kind) are alive, we only need the first one
	// since all instances share the same kind and description metadata.
	type componentMeta struct {
		kind        string
		description string
	}
	index := make(map[string]componentMeta, len(allComponents))
	for _, info := range allComponents {
		if _, exists := index[info.Name]; !exists {
			desc := info.Metadata["description"]
			index[info.Name] = componentMeta{kind: info.Kind, description: desc}
		}
	}

	// seen tracks (capabilityVerb+":"+kind+":"+name) to deduplicate.
	seen := make(map[string]struct{})
	var caps []Capability

	for _, rel := range relations {
		objects, err := b.authorizer.ListObjects(ctx, fgaUser, rel.fgaRelation, "component")
		if err != nil {
			return nil, fmt.Errorf("capabilitygrant: ListObjects(%q, %q, %q) failed: %w",
				fgaUser, rel.fgaRelation, "component", err)
		}

		b.logger.Debug("capabilitygrant: resolved FGA objects",
			"user", fgaUser,
			"relation", rel.fgaRelation,
			"count", len(objects),
		)

		for _, obj := range objects {
			// FGA returns object references in "type:id" notation, e.g. "component:nmap".
			// Extract the component name from the object reference.
			componentKind, componentName, ok := parseComponentRef(obj)
			if !ok {
				b.logger.Warn("capabilitygrant: skipping malformed component object reference",
					"object", obj,
					"user", fgaUser,
					"relation", rel.fgaRelation,
				)
				continue
			}

			// The kind is carried by the object identity itself
			// ("component:<kind>/<name>", ADR-0015), so it resolves even for a
			// grant on a component not currently live in the registry. The
			// registry lookup by name supplies the description when available.
			meta := index[componentName]

			capName := rel.capabilityVerb + ":" + componentKind + ":" + componentName
			if _, dup := seen[capName]; dup {
				continue
			}
			seen[capName] = struct{}{}

			caps = append(caps, Capability{
				Name:         capName,
				ComponentRef: authz.ComponentObject(componentKind, componentName),
				Kind:         componentKind,
				Description:  meta.description,
			})
		}
	}

	if caps == nil {
		caps = []Capability{}
	}

	return caps, nil
}

// componentPrincipalTypes are the FGA subject types minted per component
// installation. A subject of one of these types is a component acting for
// itself, and is evaluated against the narrowed can_*_as_component relations
// (ADR-0046) rather than the owner-side can_* ones.
var componentPrincipalTypes = []string{"agent_principal:", "tool_principal:", "plugin_principal:"}

// isComponentPrincipal reports whether subject is a per-installation component
// principal rather than a human user.
func isComponentPrincipal(subject string) bool {
	for _, prefix := range componentPrincipalTypes {
		if strings.HasPrefix(subject, prefix) {
			return true
		}
	}
	return false
}

// componentScopeRelations maps an owner-side relation to the component-scoped
// relation that narrows it. can_*_as_component requires BOTH the owner-side
// grant and a per-component enablement written for this principal, so a
// component reaches only what was granted to IT.
var componentScopeRelations = map[string]string{
	"can_execute":   "can_execute_as_component",
	"can_read":      "can_read_as_component",
	"can_configure": "can_write_as_component",
}

// componentScopeGrantRelations maps an owner-side relation to the direct
// per-component enablement tuple written for a component principal. These are
// the relations ListObjects can enumerate for a principal subject.
var componentScopeGrantRelations = map[string]string{
	"can_execute":   "component_execute_enabled",
	"can_read":      "component_read_enabled",
	"can_configure": "component_write_enabled",
}

// CheckExecution reports whether subjectFGA may execute componentRef.
//
// subjectFGA is a FULLY-QUALIFIED FGA subject — "user:<id>" for a human,
// "agent_principal:<id>" (or the tool/plugin equivalents) for a component
// acting for itself. Passing a bare id is a caller bug and is rejected, because
// silently prefixing "user:" is how an executing component came to be checked
// as though it were its enroller.
//
// A component principal is evaluated against can_execute_as_component, so it
// needs both the owner-side grant and the per-component enablement written for
// it; a human is evaluated against can_execute. componentRef must be in
// "component:{name}" format.
//
// It delegates directly to the Authorizer.Check method without any local
// caching — callers that need repeated checks should cache the result.
func (b *FGABridge) CheckExecution(ctx context.Context, subjectFGA, componentRef string) (bool, error) {
	if _, _, ok := parseComponentRef(componentRef); !ok {
		return false, fmt.Errorf("capabilitygrant: malformed componentRef %q: expected \"component:{name}\"", componentRef)
	}
	if !strings.Contains(subjectFGA, ":") {
		return false, fmt.Errorf("capabilitygrant: malformed subject %q: expected a typed FGA subject such as \"user:{id}\" or \"agent_principal:{id}\"", subjectFGA)
	}

	relation := "can_execute"
	if isComponentPrincipal(subjectFGA) {
		relation = componentScopeRelations["can_execute"]
	}

	allowed, err := b.authorizer.Check(ctx, subjectFGA, relation, componentRef)
	if err != nil {
		return false, fmt.Errorf("capabilitygrant: Check(%q, %q, %q) failed: %w",
			subjectFGA, relation, componentRef, err)
	}

	return allowed, nil
}

// ResolveComponentCapabilities returns the capabilities a registered component
// principal actually holds: its own per-component grants, intersected with what
// the enrolling owner can reach.
//
// Registration used to record the OWNER's whole capability set against the new
// component, which made the stored grants — and the list the dashboard shows —
// a description of the enroller rather than of the component, and meant a
// capability later granted to that human silently widened every component they
// had ever enrolled. Resolving the principal's own tuples makes the recorded
// grants the same set the execution check enforces.
//
// The owner intersection is retained from ResolveAgentPrincipalIntersection's
// reasoning: a misconfigured tuple must never let a component reach further
// than the person who enrolled it.
//
// principalRef is a fully-qualified FGA subject. An empty one yields no
// capabilities: a component with no principal has no grants of its own to
// resolve, and inheriting the owner's is exactly what this replaces.
func (b *FGABridge) ResolveComponentCapabilities(ctx context.Context, principalRef, ownerUserID, tenantID string) ([]Capability, error) {
	ownerCaps, err := b.ResolveCapabilities(ctx, ownerUserID, tenantID)
	if err != nil {
		return nil, err
	}
	if principalRef == "" || !isComponentPrincipal(principalRef) {
		b.logger.Warn("capabilitygrant: registration has no component principal; recording no grants",
			"principal", principalRef,
			"tenant", tenantID,
		)
		return []Capability{}, nil
	}

	// Index the owner's reach by (verb, component) so the intersection keeps the
	// registry-enriched kind and description already resolved for it.
	type verbComponent struct{ verb, component string }
	ownerReach := make(map[verbComponent]Capability, len(ownerCaps))
	for _, c := range ownerCaps {
		verb, _, found := strings.Cut(c.Name, ":")
		if !found {
			continue
		}
		ownerReach[verbComponent{verb: verb, component: c.ComponentRef}] = c
	}

	caps := make([]Capability, 0, len(ownerCaps))
	seen := make(map[string]struct{}, len(ownerCaps))
	for _, rel := range relations {
		grantRelation, ok := componentScopeGrantRelations[rel.fgaRelation]
		if !ok {
			continue
		}
		objects, err := b.authorizer.ListObjects(ctx, principalRef, grantRelation, "component")
		if err != nil {
			return nil, fmt.Errorf("capabilitygrant: ListObjects(%q, %q, %q) failed: %w",
				principalRef, grantRelation, "component", err)
		}
		for _, obj := range objects {
			if _, _, ok := parseComponentRef(obj); !ok {
				b.logger.Warn("capabilitygrant: skipping malformed component object reference",
					"object", obj,
					"principal", principalRef,
					"relation", grantRelation,
				)
				continue
			}
			// The principal may hold a tuple its enroller cannot reach; the
			// component does not get it.
			owned, reachable := ownerReach[verbComponent{verb: rel.capabilityVerb, component: obj}]
			if !reachable {
				continue
			}
			if _, dup := seen[owned.Name]; dup {
				continue
			}
			seen[owned.Name] = struct{}{}
			caps = append(caps, owned)
		}
	}
	return caps, nil
}

// parseComponentRef parses the canonical FGA component object
// "component:<kind>/<name>" into its kind and name (ADR-0015). A bare,
// kind-less "component:<name>" is rejected (ok=false): the kind is part of the
// object identity, so a kind-less reference is not a valid component object.
func parseComponentRef(ref string) (kind, name string, ok bool) {
	const prefix = "component:"
	rest, hasPrefix := strings.CutPrefix(ref, prefix)
	if !hasPrefix {
		return "", "", false
	}
	kind, name, hasSlash := strings.Cut(rest, "/")
	if !hasSlash || name == "" || !authz.IsComponentKind(kind) {
		// Fail closed on a kind-less ("component:nmap") or unknown-kind
		// ("component:unknown/nmap") object — never authorize against an
		// object whose kind is not one of the four canonical kinds (ADR-0015).
		return "", "", false
	}
	return kind, name, true
}
