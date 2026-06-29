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

// TenantQualifiedSep joins the tenant and field segments of a tenant-qualified
// FGA object id (e.g. plugin:<tenant><sep><name>). It MUST NOT be a colon:
// OpenFGA v1.8.4 rejects a THIRD colon at the structural type-id boundary —
// i.e. "type:tenant:name" is parsed as a 3-part string and fails with "invalid
// 'object' field format" on both Write and Check. The id portion may contain
// colons in the body (e.g. a ref like "cred:openai-prod"), but the separator
// between the tenant slug and the rest of the id must not be ":". We use "/"
// instead, which OpenFGA accepts and which cannot appear in a tenant slug or
// component name ([a-z0-9-]). See gibson#1024. Every producer of a tenant-
// qualified object — the daemon (PluginObject + the secret writers), ext-authz's
// tenant_and_field deriver, and the tenant-operator FGA clients — MUST use this
// same separator or Check will never match Write.
const TenantQualifiedSep = "/"

// PluginObject returns the canonical FGA object reference for plugin
// invocation: "plugin:<tenant>/<name>". The tenant-qualified id must match
// what the PluginInvoke RPC's tenant_and_field('PluginName') deriver produces
// at check time and what the tenant-operator seeds at enrollment.
func PluginObject(tenant, name string) string {
	return "plugin:" + tenant + TenantQualifiedSep + name
}

// SecretObject returns the canonical FGA object reference for a tenant-scoped
// secret: "secret:tenant-<tenant>/<ref>". The "tenant-" prefix is a fixed part
// of the secret object id convention (not a type qualifier) — it distinguishes
// the tenant-namespace segment from the ref and is consistent with the
// tenant-operator's SecretCanResolveTuple and the daemon's plugin_admin writers.
//
// The tenant-slug and ref are joined with "/" (TenantQualifiedSep, not ":").
// OpenFGA v1.8.4 rejects an object id where the segment immediately after the
// type colon is itself colon-split (a third colon at the structural level) —
// e.g. "secret:tenant-acme:ref" is invalid. The ref portion may contain colons
// (e.g. "cred:openai-prod") since those appear in the body of the id, not at
// the structural type-id boundary. See TenantQualifiedSep and gibson#1024.
//
// Usage:
//
//	tupleObj = authz.SecretObject(tenant.String(), ref)   // for FGA writes
//	// ext-authz tenant_and_field deriver uses SecretObjectFromDeriver
//
// SecretObject is the canonical form: all secret FGA tuple writers, the authz
// deriver, and uriToRef must agree on this exact format (gibson#1035).
func SecretObject(tenant, ref string) string {
	return "secret:tenant-" + tenant + TenantQualifiedSep + ref
}

// SecretObjectFromDeriver returns the FGA object a tenant_and_field('Name')
// deriver should produce for a secret can_resolve check. It takes the tenant
// slug as carried in identity.Tenant (the raw JWT claim, e.g. "acme") and the
// ref field from the request metadata. This is the ext-authz-side mirror of
// SecretObject — they must produce identical strings for the same (tenant, ref).
func SecretObjectFromDeriver(tenant, ref string) string {
	return SecretObject(tenant, ref)
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
		if parts[0] == "plugin" && strings.Contains(parts[1], TenantQualifiedSep) {
			// "plugin:<tenant>/<name>" — a typed, tenant-qualified plugin object
			// (the colon-free form, gibson#1024). The "/" distinguishes it from
			// the kind-qualified "plugin:<name>" below; never rewritten.
			return resource
		}
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
		// A 3-segment typed object (e.g. the legacy colon "plugin:<tenant>:<name>"
		// form) is returned unchanged; current producers emit the colon-free
		// "plugin:<tenant>/<name>" handled in the two-segment case above.
		return resource
	}
}
