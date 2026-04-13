// Package agentauth provides the FGA bridge for resolving agent capabilities
// from OpenFGA relationship tuples and the component registry.
//
// The FGABridge translates between FGA relationships and Agent Auth capability
// objects. When an agent registers, the daemon uses the bridge to determine
// what capabilities to grant based on the agent owner's FGA permissions.
package agentauth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/component"
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
		return nil, fmt.Errorf("agentauth: failed to discover components for tenant %q: %w", tenantID, err)
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
			return nil, fmt.Errorf("agentauth: ListObjects(%q, %q, %q) failed: %w",
				fgaUser, rel.fgaRelation, "component", err)
		}

		b.logger.Debug("agentauth: resolved FGA objects",
			"user", fgaUser,
			"relation", rel.fgaRelation,
			"count", len(objects),
		)

		for _, obj := range objects {
			// FGA returns object references in "type:id" notation, e.g. "component:nmap".
			// Extract the component name from the object reference.
			componentName, ok := parseComponentRef(obj)
			if !ok {
				b.logger.Warn("agentauth: skipping malformed component object reference",
					"object", obj,
					"user", fgaUser,
					"relation", rel.fgaRelation,
				)
				continue
			}

			meta, known := index[componentName]
			if !known {
				// The user has an FGA grant for a component that is not currently
				// live in the registry (component may be stopped or yet to start).
				// We still emit the capability — the daemon enforces liveness
				// separately at execution time.
				b.logger.Debug("agentauth: component not found in registry, emitting capability without metadata",
					"component", componentName,
					"user", fgaUser,
				)
				meta = componentMeta{kind: "unknown"}
			}

			capName := rel.capabilityVerb + ":" + meta.kind + ":" + componentName
			if _, dup := seen[capName]; dup {
				continue
			}
			seen[capName] = struct{}{}

			caps = append(caps, Capability{
				Name:         capName,
				ComponentRef: "component:" + componentName,
				Kind:         meta.kind,
				Description:  meta.description,
			})
		}
	}

	if caps == nil {
		caps = []Capability{}
	}

	return caps, nil
}

// CheckExecution reports whether the given user has the can_execute relation
// on the given componentRef. componentRef must be in "component:{name}" format.
//
// It delegates directly to the Authorizer.Check method without any local
// caching — callers that need repeated checks should cache the result.
func (b *FGABridge) CheckExecution(ctx context.Context, userID, componentRef string) (bool, error) {
	fgaUser := "user:" + userID

	if _, ok := parseComponentRef(componentRef); !ok {
		return false, fmt.Errorf("agentauth: malformed componentRef %q: expected \"component:{name}\"", componentRef)
	}

	allowed, err := b.authorizer.Check(ctx, fgaUser, "can_execute", componentRef)
	if err != nil {
		return false, fmt.Errorf("agentauth: Check(%q, %q, %q) failed: %w",
			fgaUser, "can_execute", componentRef, err)
	}

	return allowed, nil
}

// parseComponentRef extracts the component name from an FGA object reference
// in "component:{name}" format. Returns ("", false) if the input is malformed.
func parseComponentRef(ref string) (string, bool) {
	const prefix = "component:"
	if !strings.HasPrefix(ref, prefix) {
		return "", false
	}
	name := strings.TrimPrefix(ref, prefix)
	if name == "" {
		return "", false
	}
	return name, true
}
