package authz

import "strings"

// Canonical FGA object derivation (gibson#694).
//
// This file is the single source of truth for how gibson code derives the FGA
// object reference for components and plugins. Before it existed, four call
// sites used four different forms (bare, kind-qualified-colon, kind-qualified-
// dash, tenant-qualified) and a can_execute check could silently never match
// the seeded tuple. The canonical forms are:
//
//	component:<name>          — a component (agent | tool | plugin) in the
//	                            registry. Tenant-LESS: tenant isolation comes
//	                            from the model's in_tenant_catalog gate
//	                            (tenant_enabled tuples) plus the tenant-scoped
//	                            membership of the checking subject, and from
//	                            the data plane keying every registry lookup and
//	                            dispatch by (tenant, name).
//	plugin:<tenant>:<name>    — the plugin-invocation object checked by the
//	                            PluginInvoke can_invoke annotation
//	                            (object_deriver: tenant_and_field('PluginName'))
//	                            and seeded by the tenant-operator
//	                            PluginCanInvokeTuple. Tenant-qualified.
//
// NOT an FGA reference: the capability-grant JWT subject
// "component:<kind>:<name>" (minted in internal/harness mintCGForWork). That
// string is an identity-namespace value carried in the token's sub claim; the
// FGA reference derived from a capability name is always the bare
// ComponentObject form (see capabilitygrant.parseCapabilityName).
//
// The (tool source → object, relation) mapping for the SearchTools catalog
// filter lives in internal/catalog.FGAAuthorizer and is built on these
// helpers:
//
//	mcp:<connector>:<tool> → Check(subject, can_invoke,  PluginObject(tenant, connector))
//	native:<tool>          → Check(subject, can_execute, ComponentObject(tool))

// ComponentObject returns the canonical FGA object reference for a component:
// "component:<name>". The name is the bare component name — never
// kind-qualified, never tenant-qualified.
func ComponentObject(name string) string {
	return "component:" + name
}

// PluginObject returns the canonical FGA object reference for plugin
// invocation: "plugin:<tenant>:<name>". The tenant-qualified id must match
// what the PluginInvoke RPC's tenant_and_field('PluginName') deriver produces
// at check time and what the tenant-operator seeds at enrollment.
func PluginObject(tenant, name string) string {
	return "plugin:" + tenant + ":" + name
}

// componentKinds are the component-kind qualifiers that callers historically
// prefixed onto component resource strings ("tool:nmap", "plugin:gitlab").
// CanonicalComponentResource strips them: the FGA object is kind-less.
var componentKinds = map[string]bool{
	"agent":  true,
	"tool":   true,
	"plugin": true,
}

// CanonicalComponentResource maps a caller-provided component resource string
// to the canonical FGA object reference. Accepted inputs and their mappings:
//
//	"nmap"                → "component:nmap"   (bare name)
//	"tool:nmap"           → "component:nmap"   (kind-qualified; kind stripped)
//	"component:nmap"      → "component:nmap"   (already canonical)
//	"component:tool:nmap" → "component:nmap"   (legacy kind-qualified object)
//	"plugin:acme:gitlab"  → unchanged          (already a typed plugin object)
//	"mission:abc"         → unchanged          (non-component typed reference)
//
// Any other typed reference passes through unchanged: callers that provide a
// fully-typed FGA object are trusted to have used the canonical helpers, and
// an unknown type fails the FGA check loudly (fail-closed) rather than being
// rewritten here.
func CanonicalComponentResource(resource string) string {
	parts := strings.SplitN(resource, ":", 3)
	switch len(parts) {
	case 1:
		// Bare component name.
		return ComponentObject(resource)
	case 2:
		if parts[0] == "component" || componentKinds[parts[0]] {
			// "component:<name>" (canonical) or "<kind>:<name>".
			return ComponentObject(parts[1])
		}
		return resource
	default:
		if parts[0] == "component" && componentKinds[parts[1]] {
			// Legacy "component:<kind>:<name>".
			return ComponentObject(parts[2])
		}
		// Includes "plugin:<tenant>:<name>" — a valid typed plugin object,
		// never rewritten ("plugin" only acts as a kind qualifier in the
		// two-segment form).
		return resource
	}
}
