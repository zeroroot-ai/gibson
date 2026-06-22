package harness

import (
	"log/slog"
	"strconv"
	"strings"

	taxonomypb "github.com/zeroroot-ai/sdk/api/gen/taxonomy/v1"
	"github.com/zeroroot-ai/sdk/taxonomy"
)

// ComplianceEvaluator runs a catalog's rules against a compliance_signal
// and returns the list of matched control IDs. It is a pure function —
// no I/O, no state — so it can be called inline on the emission hot path.
//
// Per Requirement 8.5 the evaluator must complete in ≤500µs per signal.
// The seed catalog has ~20 rules; each rule performs a small number of
// string comparisons so the budget is comfortable.
//
// Panic recovery around each rule ensures a malformed tenant rule cannot
// break emission for other tenants on the same daemon.
type ComplianceEvaluator struct {
	logger *slog.Logger
}

// NewComplianceEvaluator constructs an evaluator.
func NewComplianceEvaluator(logger *slog.Logger) *ComplianceEvaluator {
	if logger == nil {
		logger = slog.Default()
	}
	return &ComplianceEvaluator{logger: logger.With("component", "compliance_evaluator")}
}

// Evaluate walks the rules and returns the matched control IDs. Rules that
// panic during evaluation are skipped with a WARN log.
func (e *ComplianceEvaluator) Evaluate(sig *taxonomypb.ComplianceSignal, rules []taxonomy.Rule) []string {
	if sig == nil {
		return nil
	}
	var matched []string
	for _, rule := range rules {
		if e.evalRuleSafe(sig, rule) {
			matched = append(matched, rule.ControlID)
		}
	}
	return matched
}

// evalRuleSafe wraps the rule match in a defer/recover so a broken rule
// does not crash the emission path.
func (e *ComplianceEvaluator) evalRuleSafe(sig *taxonomypb.ComplianceSignal, rule taxonomy.Rule) (matched bool) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Warn("panic during compliance rule evaluation",
				slog.String("rule_id", rule.ID),
				slog.Any("panic", r),
			)
			matched = false
		}
	}()
	return evalMatcher(sig, rule.Matcher)
}

// evalMatcher recursively evaluates a matcher tree against a signal.
// Operator precedence:
//   - AllOf (and sibling Equals/In) — every child must match
//   - AnyOf — at least one child must match
//   - Not — nested child must NOT match
func evalMatcher(sig *taxonomypb.ComplianceSignal, m taxonomy.Matcher) bool {
	// Equals: every key/value must match.
	for k, v := range m.Equals {
		if readSignalField(sig, k) != v {
			return false
		}
	}
	// In: value must be in the list.
	for k, list := range m.In {
		got := readSignalField(sig, k)
		found := false
		for _, v := range list {
			if got == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Not: nested matcher must NOT match.
	if m.Not != nil {
		if evalMatcher(sig, *m.Not) {
			return false
		}
	}
	// AnyOf: at least one child must match.
	if len(m.AnyOf) > 0 {
		any := false
		for _, child := range m.AnyOf {
			if evalMatcher(sig, child) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	// AllOf: every child must match.
	for _, child := range m.AllOf {
		if !evalMatcher(sig, child) {
			return false
		}
	}
	return true
}

// readSignalField returns the string value at the given dotted path into a
// ComplianceSignal. Supports:
//
//   - flat fields: "action", "effect", "decision", "success", "error_code",
//     "actor_id", "actor_tenant_id", "caller_component", "resource_type",
//     "resource_uri"
//   - bag lookups: "resource_tags.<key>", "custom.<key>"
//
// Missing fields and missing bag keys return empty string — rules should
// use "not equals empty" to check presence.
func readSignalField(sig *taxonomypb.ComplianceSignal, path string) string {
	if sig == nil || path == "" {
		return ""
	}

	// Bag lookups are split on the first '.'.
	if idx := strings.Index(path, "."); idx > 0 {
		bag := path[:idx]
		key := path[idx+1:]
		switch bag {
		case "resource_tags":
			return readBagKey(sig.ResourceTags, key)
		case "custom":
			return readBagKey(sig.Custom, key)
		}
	}

	// Flat fields.
	switch path {
	case "action":
		return sig.Action
	case "effect":
		return sig.Effect
	case "decision":
		return sig.Decision
	case "success":
		return strconv.FormatBool(sig.Success)
	case "error_code":
		if sig.ErrorCode != nil {
			return *sig.ErrorCode
		}
		return ""
	case "actor_id":
		return sig.ActorId
	case "actor_tenant_id":
		return sig.ActorTenantId
	case "caller_component":
		return sig.CallerComponent
	case "resource_type":
		return sig.ResourceType
	case "resource_uri":
		if sig.ResourceUri != nil {
			return *sig.ResourceUri
		}
		return ""
	case "resource_node_id":
		if sig.ResourceNodeId != nil {
			return *sig.ResourceNodeId
		}
		return ""
	}
	return ""
}

// readBagKey parses the serialized resource_tags or custom JSON-ish map
// from the signal proto and returns the value at the given key.
//
// Both fields are stored as optional serialized strings on the proto (a
// limitation of the taxonomy codegen — map types aren't emitted directly
// on graph node messages). The stored format is "k1=v1,k2=v2,..." — a
// flat delimiter-based encoding that matches the merger's output.
//
// Future versions of the taxonomy may emit these as proper proto maps,
// at which point this helper should switch to map lookups.
func readBagKey(serialized *string, key string) string {
	if serialized == nil || *serialized == "" {
		return ""
	}
	return parseFlatBag(*serialized)[key]
}

// parseFlatBag decodes the "k1=v1,k2=v2" encoding into a map.
func parseFlatBag(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	for _, pair := range strings.Split(s, ",") {
		eq := strings.Index(pair, "=")
		if eq <= 0 {
			continue
		}
		out[strings.TrimSpace(pair[:eq])] = strings.TrimSpace(pair[eq+1:])
	}
	return out
}
