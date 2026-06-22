package harness

import "context"

// Metadata precedence levels for compliance signal tag merging. Higher values
// win over lower values during collision resolution. The full precedence
// ladder lives in the audit-compliance-emitter design doc and in
// docs/AUDIT-FEATURE.md Q7.
//
// Source 1 (target node) is the highest precedence because customer-applied
// tags on the resource being touched are always the most specific. Source 5
// (daemon defaults) is the lowest because it's the fallback everyone gets
// without opting in.
const (
	// PrecedenceTargetNode = 1 — tags copied from the target graph node's
	// properties (e.g., env=prod set on the host being scanned). Highest
	// precedence because the customer directly labeled the target.
	PrecedenceTargetNode = 1

	// PrecedenceMissionYAML = 2 — top-level tags: map in the mission YAML.
	PrecedenceMissionYAML = 2

	// PrecedenceAgent = 3 — agent-supplied tags via harness.WithMetadata().
	// NOT wired in audit-compliance-emitter; the audit-metadata-riders spec
	// registers a MetadataProvider at this precedence.
	PrecedenceAgent = 3

	// PrecedenceToolPlugin = 4 — tags declared by the tool or plugin on its
	// proto response or component.yaml. NOT wired in audit-compliance-emitter;
	// the audit-metadata-riders spec registers a MetadataProvider here.
	PrecedenceToolPlugin = 4

	// PrecedenceDaemonDefaults = 5 — fallback tags stamped by the daemon at
	// signal construction time (gibson_version, cluster_id, region). Lowest
	// precedence because these are the background everybody gets for free.
	PrecedenceDaemonDefaults = 5
)

// TagSet is the payload returned by a MetadataProvider. It distinguishes
// "resource tags" (describing WHAT was touched) from "custom tags" (describing
// the ACTION ITSELF), matching the two bag fields on the compliance_signal
// proto type. Providers may populate either or both.
//
// Keys are plain strings; values are plain strings. Nested or typed values
// are explicitly unsupported — queries target these as flat key/value maps
// in Cypher.
type TagSet struct {
	ResourceTags map[string]string
	Custom       map[string]string
}

// NewTagSet returns an empty, non-nil TagSet ready for population.
func NewTagSet() TagSet {
	return TagSet{
		ResourceTags: map[string]string{},
		Custom:       map[string]string{},
	}
}

// IsEmpty reports whether the tag set contains no entries.
func (t TagSet) IsEmpty() bool {
	return len(t.ResourceTags) == 0 && len(t.Custom) == 0
}

// MetadataProvider is the plug-in interface used by ComplianceMiddleware to
// collect tag contributions for each harness call. Implementations are
// registered at daemon startup in precedence order.
//
// The audit-compliance-emitter spec ships the interface and the merger
// scaffolding. The audit-metadata-riders spec ships the first two real
// implementations (agent riders at precedence 3, tool/plugin riders at
// precedence 4). In-tree defaults (target node and mission YAML) do NOT go
// through this interface; they are merged directly by the ComplianceMiddleware
// because the middleware already has access to those sources.
type MetadataProvider interface {
	// Precedence returns the precedence constant this provider contributes
	// to. Used by the merger to order providers.
	Precedence() int

	// Provide returns the tags this provider wants to contribute for the
	// given harness method and request. The merger calls this on every
	// signal emission, so implementations must be cheap and must not block.
	//
	// Providers that cannot classify the call should return an empty
	// TagSet — returning nil maps is also allowed.
	Provide(ctx context.Context, method HarnessMethod, request any) TagSet
}
