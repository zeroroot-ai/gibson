package auth

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// LoadRegistry constructs an *FgaRpcRegistry from the embedded YAML, optionally
// overridden by a file at overridePath.
//
// Behavior:
//   - overridePath == "":   parse embedded bytes (default).
//   - overridePath != "":   read and parse that file. If the file is missing,
//     unreadable, or invalid, LoadRegistry returns an error — there is NO
//     silent fallback to the embedded default. This is deliberate: an
//     operator misconfiguring the override path must fail boot loudly so
//     they discover the problem before authz starts behaving unexpectedly.
//
// The returned registry is the same *FgaRpcRegistry type used by today's
// constructor; Lookup, Methods, Validate, ValidateCoverage, and
// ValidateNoStaleEntries continue to work unchanged.
func LoadRegistry(embedded []byte, overridePath string) (*FgaRpcRegistry, error) {
	src, source, err := chooseRegistrySource(embedded, overridePath)
	if err != nil {
		return nil, err
	}

	file, err := parseRegistryFile(src)
	if err != nil {
		return nil, fmt.Errorf("rpc registry (%s): %w", source, err)
	}

	return buildRegistryFromFile(file, source)
}

// supportedRegistryVersion is the only YAML schema version this loader
// accepts. Bumping it is a breaking change — old binaries reject newer YAML.
const supportedRegistryVersion = 1

// RegistryEntryView is the display projection of a single registry entry,
// preserving the YAML-level distinction between `object_from` (named
// resolver) and `object` (literal). Used by `gibson authz inspect-rpc` /
// `list-rpcs` so operators see the exact source declaration rather than an
// opaque function pointer. Not used at request time — the runtime only ever
// needs the resolved FgaCheckSpec.
type RegistryEntryView struct {
	Method          string
	Relation        string
	ObjectFrom      string // resolver name, empty if Object set or both empty
	Object          string // literal, empty if ObjectFrom set or both empty
	Unauthenticated bool
	Description     string
}

// LoadRegistryView returns the parsed YAML entries plus the source label
// (matching LoadRegistry's source: "embedded" or "override:<path>"), in the
// order they appear in the file. Validation rules from LoadRegistry are NOT
// applied here — the view is intentionally raw so a debugging operator can
// inspect a partially-broken file. For startup-time validation, use
// LoadRegistry.
func LoadRegistryView(embedded []byte, overridePath string) ([]RegistryEntryView, string, error) {
	src, source, err := chooseRegistrySource(embedded, overridePath)
	if err != nil {
		return nil, "", err
	}
	file, err := parseRegistryFile(src)
	if err != nil {
		return nil, source, fmt.Errorf("rpc registry (%s): %w", source, err)
	}
	out := make([]RegistryEntryView, len(file.Entries))
	for i, e := range file.Entries {
		out[i] = RegistryEntryView{
			Method:          e.Method,
			Relation:        e.Relation,
			ObjectFrom:      e.ObjectFrom,
			Object:          e.Object,
			Unauthenticated: e.Unauthenticated,
			Description:     e.Description,
		}
	}
	return out, source, nil
}

// rpcRegistryFile is the on-disk YAML schema. Distinct from FgaCheckSpec so
// the wire format can evolve (versioning) without leaking into the runtime
// type.
type rpcRegistryFile struct {
	Version int            `yaml:"version"`
	Entries []rpcEntryYAML `yaml:"entries"`
}

// rpcEntryYAML is one row of the registry YAML.
type rpcEntryYAML struct {
	Method          string `yaml:"method"`
	Relation        string `yaml:"relation,omitempty"`
	ObjectFrom      string `yaml:"object_from,omitempty"`
	Object          string `yaml:"object,omitempty"`
	Unauthenticated bool   `yaml:"unauthenticated,omitempty"`
	Description     string `yaml:"description,omitempty"`
}

// objectLiteralRe matches "type:id" strings used in literal `object` entries.
// The type segment is a Go-style identifier; the id segment forbids whitespace
// and ':' but otherwise permits arbitrary visible characters (so tenant slugs
// like "acme-corp" or system constants like "_system" both qualify).
var objectLiteralRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*:[^\s:]+$`)

// chooseRegistrySource returns the YAML bytes plus a human-readable source
// label used in error messages and tooling output.
func chooseRegistrySource(embedded []byte, overridePath string) ([]byte, string, error) {
	if overridePath == "" {
		return embedded, "embedded", nil
	}
	data, err := os.ReadFile(overridePath)
	if err != nil {
		return nil, "", fmt.Errorf("rpc registry override %s: %w", overridePath, err)
	}
	return data, "override:" + overridePath, nil
}

// parseRegistryFile strict-decodes the YAML. Unknown fields are rejected to
// surface schema typos at boot rather than silently dropping them.
func parseRegistryFile(src []byte) (*rpcRegistryFile, error) {
	var file rpcRegistryFile
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}
	if file.Version != supportedRegistryVersion {
		return nil, fmt.Errorf("unsupported version %d (this binary supports %d)",
			file.Version, supportedRegistryVersion)
	}
	return &file, nil
}

// buildRegistryFromFile validates each entry, aggregates errors, and returns
// the populated *FgaRpcRegistry. On any error, no partial registry is
// returned — the daemon must fail-closed.
func buildRegistryFromFile(file *rpcRegistryFile, source string) (*FgaRpcRegistry, error) {
	r := &FgaRpcRegistry{entries: make(map[string]FgaCheckSpec, len(file.Entries))}
	seen := make(map[string]struct{}, len(file.Entries))
	var errs []error

	for i, e := range file.Entries {
		if e.Method == "" {
			errs = append(errs, fmt.Errorf("entry[%d]: missing method", i))
			continue
		}
		if _, dup := seen[e.Method]; dup {
			errs = append(errs, fmt.Errorf("duplicate method: %s", e.Method))
			continue
		}
		seen[e.Method] = struct{}{}

		spec, err := entryToSpec(e)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Method, err))
			continue
		}
		r.entries[e.Method] = spec
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("rpc registry (%s) has %d error(s): %w",
			source, len(errs), errors.Join(errs...))
	}
	return r, nil
}

// entryToSpec converts a single YAML row into an FgaCheckSpec, enforcing all
// per-entry invariants (mutual exclusion, resolver existence, literal format).
func entryToSpec(e rpcEntryYAML) (FgaCheckSpec, error) {
	spec := FgaCheckSpec{Description: e.Description}

	if e.Unauthenticated {
		if e.Relation != "" || e.Object != "" || e.ObjectFrom != "" {
			return spec, errors.New(
				"unauthenticated entries must not set relation, object, or object_from")
		}
		spec.Unauthenticated = true
		return spec, nil
	}

	if e.Relation == "" {
		return spec, errors.New("relation is required for authenticated entries")
	}
	spec.Relation = e.Relation

	if e.Object != "" && e.ObjectFrom != "" {
		return spec, errors.New("object and object_from are mutually exclusive")
	}

	switch {
	case e.Object != "":
		if !objectLiteralRe.MatchString(e.Object) {
			return spec, fmt.Errorf("invalid object literal %q (want type:id)", e.Object)
		}
		spec.ObjectFrom = constObject(e.Object)
	case e.ObjectFrom != "":
		deriver, ok := lookupObjectResolver(e.ObjectFrom)
		if !ok {
			return spec, fmt.Errorf("unknown object_from resolver %q", e.ObjectFrom)
		}
		spec.ObjectFrom = deriver
	default:
		// Neither set — interceptor falls back to "tenant:" + tenant in ctx,
		// matching the existing default for tenant-scoped RPCs.
	}

	return spec, nil
}
