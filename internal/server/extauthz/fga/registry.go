// Package fga implements OpenFGA authorization for the ext-authz service.
//
// The registry is the SOURCE OF TRUTH for per-RPC authorization. It is
// generated from proto annotations in zeroroot-ai/sdk by the
// authz-registry-gen tool and shipped as auth/registry/registry.yaml.
// ext-authz loads the YAML at startup and refuses to start on parse
// failure — the YAML drives default-deny semantics: a request whose
// method has no entry is rejected before reaching FGA.
//
// Spec: unified-identity-and-authorization Requirements 4, 7.
package fga

import (
	"errors"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// IdentityClass mirrors gibson.auth.v1.IdentityClass and the SDK's
// auth/registry IdentityClass. Comparison is bitfield-based.
type IdentityClass uint8

const (
	IdentityUser             IdentityClass = 1
	IdentityService          IdentityClass = 2
	IdentityComponent        IdentityClass = 4
	IdentityPlatformOperator IdentityClass = 8
)

func (c IdentityClass) Has(want IdentityClass) bool { return c&want == want }

// String renders the bitfield as a slash-separated list ("USER/SERVICE")
// for log/metric tags. Stable ordering for deterministic output.
func (c IdentityClass) String() string {
	parts := []string{}
	if c.Has(IdentityUser) {
		parts = append(parts, "USER")
	}
	if c.Has(IdentityService) {
		parts = append(parts, "SERVICE")
	}
	if c.Has(IdentityComponent) {
		parts = append(parts, "COMPONENT")
	}
	if c.Has(IdentityPlatformOperator) {
		parts = append(parts, "PLATFORM_OPERATOR")
	}
	if len(parts) == 0 {
		return "NONE"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "/" + p
	}
	return out
}

// Entry is a validated, normalized registry entry. It is the runtime
// representation consumed by Checker.Check.
type Entry struct {
	// Method is the gRPC FullMethod string, e.g. "/pkg.Service/Method".
	Method string

	// Service is the gRPC service FQN ("<package>.<Service>"). Used for
	// service-level metric labels.
	Service string

	// Relation is the FGA relation to check, e.g. "member", "admin".
	// Empty when Unauthenticated is true.
	Relation string

	// ObjectType is the FGA object type, e.g. "tenant", "system_tenant",
	// "component", "mission". Combined with the resolver to form the
	// concrete object string.
	ObjectType string

	// ObjectDeriver names the strategy for deriving the object's
	// identifier from the request. Supported derivers (handled in
	// check.go's resolveObject):
	//   - "tenant_from_identity"
	//   - "system_tenant"
	//   - "from_field('<name>')"            — request body field
	//   - "tenant_and_field('<name>')"      — tenant prefix + field
	ObjectDeriver string

	// AllowedIdentities is the bitfield of caller classes permitted to
	// invoke this RPC. Callers of an excluded class are rejected
	// before FGA is consulted.
	AllowedIdentities IdentityClass

	// Unauthenticated, when true, means the RPC bypasses ALL identity
	// checks (Ping, health, etc.). Mutually exclusive with the other
	// fields.
	Unauthenticated bool

	// Self, when true, means the RPC is an authenticated self-read: the
	// caller's JWT is validated by Envoy jwt_authn, ext-authz applies the
	// AllowedIdentities bitfield, and the FGA Check is skipped entirely.
	// The daemon handler is responsible for scoping the response to the
	// verified caller subject. Mutually exclusive with Unauthenticated and
	// rule fields (Relation/ObjectType/ObjectDeriver).
	// Spec: self-mode-authz.
	Self bool
}

// Registry holds the validated set of RPC→FGA mappings loaded from the
// SDK's generated YAML.
type Registry struct {
	entries map[string]Entry
}

// LoadRegistry parses and validates a registry YAML, returning an
// immutable Registry. The expected schema is what the SDK's
// authz-registry-gen tool emits to auth/registry/registry.yaml.
//
// Spec: unified-identity-and-authorization Requirement 4.7.
func LoadRegistry(yamlBytes []byte) (*Registry, error) {
	if len(yamlBytes) == 0 {
		return nil, errors.New("fga: registry YAML is empty")
	}

	type sdkFile struct {
		Entries map[string]normalizeEntry `yaml:"entries"`
	}

	var file sdkFile
	if err := yaml.Unmarshal(yamlBytes, &file); err != nil {
		return nil, fmt.Errorf("fga: registry YAML parse failed: %w", err)
	}
	if len(file.Entries) == 0 {
		return nil, errors.New("fga: registry contains no entries")
	}

	reg := &Registry{entries: make(map[string]Entry, len(file.Entries))}
	for method, raw := range file.Entries {
		e, err := normalize(method, raw)
		if err != nil {
			return nil, err
		}
		reg.entries[method] = e
	}
	return reg, nil
}

// normalizeEntry is the named struct used both inside LoadRegistry's sdkEntry
// and by normalize, so the function signature can reference a concrete type.
type normalizeEntry struct {
	Relation          string   `yaml:"relation"`
	ObjectType        string   `yaml:"object_type"`
	ObjectDeriver     string   `yaml:"object_deriver"`
	AllowedIdentities []string `yaml:"allowed_identities"`
	Unauthenticated   bool     `yaml:"unauthenticated"`
	Self              bool     `yaml:"self"`
}

func normalize(method string, raw normalizeEntry) (Entry, error) {
	if method == "" {
		return Entry{}, errors.New("fga: registry contains an entry with empty method")
	}

	// self mode: authenticated user reading their own data; no FGA tuple needed.
	// Spec: self-mode-authz.
	if raw.Self {
		if raw.Unauthenticated {
			return Entry{}, fmt.Errorf("fga: %q: self and unauthenticated are mutually exclusive (self-mode-authz)", method)
		}
		if raw.Relation != "" || raw.ObjectType != "" || raw.ObjectDeriver != "" {
			return Entry{}, fmt.Errorf("fga: %q: self mode is incompatible with relation/object_type/object_deriver (self-mode-authz)", method)
		}
		if len(raw.AllowedIdentities) == 0 {
			return Entry{}, fmt.Errorf("fga: %q: allowed_identities is required for self mode (self-mode-authz)", method)
		}
		ic, err := parseIdentityClasses(method, raw.AllowedIdentities)
		if err != nil {
			return Entry{}, err
		}
		return Entry{Method: method, Service: serviceFromMethod(method), AllowedIdentities: ic, Self: true}, nil
	}

	if raw.Unauthenticated {
		if raw.Relation != "" || raw.ObjectType != "" || raw.ObjectDeriver != "" || len(raw.AllowedIdentities) != 0 {
			return Entry{}, fmt.Errorf("fga: %q: unauthenticated:true is mutually exclusive with relation/object_type/object_deriver/allowed_identities", method)
		}
		return Entry{Method: method, Service: serviceFromMethod(method), Unauthenticated: true}, nil
	}

	// rule mode: all fields required.
	if raw.Relation == "" || raw.ObjectType == "" || raw.ObjectDeriver == "" || len(raw.AllowedIdentities) == 0 {
		return Entry{}, fmt.Errorf("fga: %q: relation/object_type/object_deriver/allowed_identities all required when not unauthenticated", method)
	}

	ic, err := parseIdentityClasses(method, raw.AllowedIdentities)
	if err != nil {
		return Entry{}, err
	}

	return Entry{
		Method:            method,
		Service:           serviceFromMethod(method),
		Relation:          raw.Relation,
		ObjectType:        raw.ObjectType,
		ObjectDeriver:     raw.ObjectDeriver,
		AllowedIdentities: ic,
	}, nil
}

// parseIdentityClasses converts a slice of identity-class name strings into
// an IdentityClass bitfield. Returns an error naming the offending entry.
func parseIdentityClasses(method string, names []string) (IdentityClass, error) {
	var ic IdentityClass
	for _, name := range names {
		switch name {
		case "USER":
			ic |= IdentityUser
		case "SERVICE":
			ic |= IdentityService
		case "COMPONENT":
			ic |= IdentityComponent
		case "PLATFORM_OPERATOR":
			ic |= IdentityPlatformOperator
		default:
			return 0, fmt.Errorf("fga: %q: unknown allowed_identities entry %q", method, name)
		}
	}
	return ic, nil
}

func serviceFromMethod(method string) string {
	// "/pkg.Service/Method" -> "pkg.Service"
	if len(method) < 2 || method[0] != '/' {
		return ""
	}
	rest := method[1:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i]
		}
	}
	return ""
}

// Lookup returns the Entry for a fully-qualified gRPC method path and
// whether it was found. A miss signals default-deny — the caller MUST
// reject the request without calling FGA.
func (r *Registry) Lookup(method string) (Entry, bool) {
	e, ok := r.entries[method]
	return e, ok
}

// Methods returns a sorted slice of every registered method path.
// Used by coverage tests and admin diagnostics.
func (r *Registry) Methods() []string {
	out := make([]string, 0, len(r.entries))
	for m := range r.entries {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// Len returns the number of entries in the registry.
func (r *Registry) Len() int {
	return len(r.entries)
}
