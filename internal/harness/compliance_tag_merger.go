package harness

import (
	"context"
	"log/slog"
	"sort"
)

// ReservedTagKey is the set of tag keys whose values are constrained to a
// closed vocabulary. These are the 4 reserved keys declared in the taxonomy
// foundation spec (Requirement 12) — when their values fail vocabulary
// validation, the merger drops them (Requirement 5.5) and counts a violation
// against the compliance metrics.
//
// The vocabularies themselves are enforced by the SDK CEL validators; the
// merger only knows WHICH keys are reserved so it can log collisions at WARN
// instead of debug (Requirement 5.4).
var ReservedTagKeys = map[string]bool{
	"env":        true,
	"data_class": true,
	"residency":  true,
	"legal_hold": true,
}

// TagMerger collapses tags from multiple precedence sources into the two
// destination bags carried on a ComplianceSignal: resource_tags (what was
// touched) and custom (the action itself). Higher-precedence sources win
// collisions; lower-precedence values are shadowed.
//
// Full 5-source precedence (audit-metadata-riders task 5):
//   - Precedence 1 (target node) — highest
//   - Precedence 2 (mission YAML)
//   - Precedence 3 (agent) — via AgentMetadataProvider
//   - Precedence 4 (tool/plugin) — via ToolMetadataProvider
//   - Precedence 5 (daemon defaults) — lowest
//
// After merging, the merger runs:
//   - ReservedKeyValidator — drops keys with values outside the closed
//     vocabulary, logs WARN.
//   - SizeEnforcer — truncates long values, evicts low-precedence entries
//     until the bag fits within size limits, stamps the gibson.truncated_keys
//     and gibson.size_dropped_keys marker keys.
type TagMerger struct {
	providers []MetadataProvider
	defaults  TagSet
	logger    *slog.Logger
	metrics   *ComplianceMetrics
	reserved  *ReservedKeyValidator
	enforcer  *SizeEnforcer
}

// NewTagMerger constructs a TagMerger with the given slog.Logger and metrics.
// Pass nil for metrics in tests that don't care about violation counts.
func NewTagMerger(logger *slog.Logger, metrics *ComplianceMetrics) *TagMerger {
	if logger == nil {
		logger = slog.Default()
	}
	return &TagMerger{
		logger:   logger.With("component", "compliance_tag_merger"),
		metrics:  metrics,
		defaults: NewTagSet(),
		reserved: NewReservedKeyValidator(),
		enforcer: NewSizeEnforcer(metrics),
	}
}

// SetDaemonDefaults installs the precedence-5 tag set. Daemon startup calls
// this once with (gibson_version, cluster_id, region) etc. — see
// docs/operations/compliance-emitter.md for the canonical list.
func (m *TagMerger) SetDaemonDefaults(defaults TagSet) {
	m.defaults = defaults
}

// RegisterProvider adds a MetadataProvider to the merger. Providers can be
// registered in any order; the merger sorts them by precedence at merge
// time so registration order is irrelevant.
//
// audit-metadata-riders calls this during daemon startup to install agent
// (precedence 3) and tool/plugin (precedence 4) providers.
func (m *TagMerger) RegisterProvider(p MetadataProvider) {
	m.providers = append(m.providers, p)
}

// Merge collapses tags from all 5 precedence sources into a pair of flat
// maps (resource tags, custom tags) that the middleware stamps onto the
// ComplianceSignal. Runs reserved-key validation and size enforcement at
// the end.
//
// Precedence order (highest → lowest):
//  1. target — source 1, highest; wins collisions
//  2. mission — source 2
//  3. agent providers (source 3) — plug-in hook
//  4. tool/plugin providers (source 4) — plug-in hook
//  5. daemon defaults — source 5, lowest
//
// Collisions on non-reserved keys log at debug. Collisions on reserved keys
// log at WARN per Requirement 5.4.
func (m *TagMerger) Merge(
	ctx context.Context,
	method HarnessMethod,
	request any,
	target TagSet,
	mission TagSet,
) (resourceTags, custom map[string]string) {
	// keySources tracks per-key source precedence for the size enforcer.
	// Keyed separately for resource and custom bags.
	resourceTags = map[string]string{}
	custom = map[string]string{}
	resourceSources := map[string]int{}
	customSources := map[string]int{}

	// Walk providers in ASCENDING precedence (lowest first) so the final
	// application of the higher-precedence sources overwrites.
	sorted := make([]MetadataProvider, len(m.providers))
	copy(sorted, m.providers)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Precedence() > sorted[j].Precedence()
	})

	// Precedence 5: daemon defaults.
	m.applySet(ctx, "daemon_defaults", PrecedenceDaemonDefaults, m.defaults,
		resourceTags, custom, resourceSources, customSources)

	// Precedences 4 and 3: plug-in providers, applied lowest-first.
	for i := len(sorted) - 1; i >= 0; i-- {
		p := sorted[i]
		set := p.Provide(ctx, method, request)
		m.applySet(ctx, sourceNameForPrecedence(p.Precedence()), p.Precedence(), set,
			resourceTags, custom, resourceSources, customSources)
	}

	// Precedence 2: mission YAML.
	m.applySet(ctx, "mission_yaml", PrecedenceMissionYAML, mission,
		resourceTags, custom, resourceSources, customSources)

	// Precedence 1: target node (highest, always wins).
	m.applySet(ctx, "target_node", PrecedenceTargetNode, target,
		resourceTags, custom, resourceSources, customSources)

	// Reserved-key validation: drop values outside the closed vocabulary.
	m.validateReserved(ctx, resourceTags, resourceSources, "resource_tags")
	m.validateReserved(ctx, custom, customSources, "custom")

	// Size enforcement: truncate values, evict entries, stamp markers.
	rtTrunc, rtDrop := m.enforcer.Enforce(resourceTags, resourceSources)
	cTrunc, cDrop := m.enforcer.Enforce(custom, customSources)

	if len(rtTrunc) > 0 || len(cTrunc) > 0 {
		marker := joinKeys(rtTrunc, cTrunc)
		resourceTags[MarkerTruncatedKeys] = marker
	}
	if len(rtDrop) > 0 || len(cDrop) > 0 {
		marker := joinKeys(rtDrop, cDrop)
		resourceTags[MarkerDroppedKeys] = marker
	}

	return resourceTags, custom
}

// applySet copies entries from src into dst maps, logging collisions with
// the given source name and tracking the source precedence for each key.
func (m *TagMerger) applySet(
	ctx context.Context,
	source string,
	precedence int,
	src TagSet,
	resourceDst, customDst map[string]string,
	resourceSources, customSources map[string]int,
) {
	for k, v := range src.ResourceTags {
		if prev, existed := resourceDst[k]; existed && prev != v {
			m.logCollision(ctx, source, k, prev, v)
		}
		resourceDst[k] = v
		resourceSources[k] = precedence
	}
	for k, v := range src.Custom {
		if prev, existed := customDst[k]; existed && prev != v {
			m.logCollision(ctx, source, k, prev, v)
		}
		customDst[k] = v
		customSources[k] = precedence
	}
}

// validateReserved drops reserved-key entries whose values fail the closed
// vocabulary check, logs a WARN, and increments the metric.
func (m *TagMerger) validateReserved(ctx context.Context, bag map[string]string, sources map[string]int, bagName string) {
	for k, v := range bag {
		if !m.reserved.IsReserved(k) {
			continue
		}
		if !m.reserved.IsValid(k, v) {
			src := sourceNameForPrecedence(sources[k])
			m.logger.WarnContext(ctx, "reserved tag key value failed closed-vocabulary validation",
				slog.String("key", k),
				slog.String("value", v),
				slog.String("source", src),
				slog.String("bag", bagName),
			)
			if m.metrics != nil {
				m.metrics.RecordReservedKeyViolation(k, src)
			}
			delete(bag, k)
			delete(sources, k)
		}
	}
}

// joinKeys merges two key slices into a comma-separated string for the
// marker entry values.
func joinKeys(a, b []string) string {
	seen := map[string]bool{}
	var out string
	for _, k := range a {
		if !seen[k] {
			if out != "" {
				out += ","
			}
			out += k
			seen[k] = true
		}
	}
	for _, k := range b {
		if !seen[k] {
			if out != "" {
				out += ","
			}
			out += k
			seen[k] = true
		}
	}
	return out
}

// logCollision logs a tag collision. Reserved keys log at WARN; everything
// else logs at debug to avoid spam.
func (m *TagMerger) logCollision(ctx context.Context, source, key, previous, winner string) {
	if ReservedTagKeys[key] {
		m.logger.WarnContext(ctx, "reserved tag key collision — higher precedence wins",
			slog.String("key", key),
			slog.String("winning_source", source),
			slog.String("winning_value", winner),
			slog.String("shadowed_value", previous),
		)
		return
	}
	m.logger.DebugContext(ctx, "tag key collision",
		slog.String("key", key),
		slog.String("winning_source", source),
		slog.String("winning_value", winner),
		slog.String("shadowed_value", previous),
	)
}

// sourceNameForPrecedence maps a precedence int to a stable source name
// used in log messages and metric labels.
func sourceNameForPrecedence(p int) string {
	switch p {
	case PrecedenceTargetNode:
		return "target_node"
	case PrecedenceMissionYAML:
		return "mission_yaml"
	case PrecedenceAgent:
		return "agent"
	case PrecedenceToolPlugin:
		return "tool_plugin"
	case PrecedenceDaemonDefaults:
		return "daemon_defaults"
	default:
		return "unknown"
	}
}
