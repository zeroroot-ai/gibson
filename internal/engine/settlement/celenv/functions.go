// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/tidwall/gjson"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// Function names in the curated helper catalog (ADR-0131). A
// pack predicate names exactly these; anything else fails Compile with an
// "undeclared reference" error.
const (
	fnEvidenceText  = "evidenceText"
	fnRegexMatch    = "regexMatch"
	fnJSONPath      = "jsonPath"
	fnHTTPStatus    = "httpStatus"
	fnMarkerPresent = "markerPresent"
)

// helperFunctionOptions returns the curated helper-function catalog
// (ADR-0131): the small, fixed set of operations a settlement
// predicate may use to read one evidence item, alongside the plain
// type/title/content/timestamp field access [EvidenceMapType] already
// allows. Extending this catalog is the only thing that ever needs gibson
// code (ADR-0131) — a pack predicate can never add its own
// function.
//
//   - evidenceText(evidence_item) -> string: a plain-text rendering of one
//     evidence item's content, or "" if its type has none (a screenshot) or
//     its content does not decode as its declared type.
//   - regexMatch(text, pattern) -> bool: true iff pattern (RE2 syntax, the
//     Go regexp package — linear-time, no catastrophic backtracking) matches
//     somewhere in text.
//   - jsonPath(text, path) -> dyn: the value gjson's path syntax selects out
//     of text, or null if text is not valid JSON or path selects nothing.
//   - httpStatus(evidence_item) -> int: the status code of an http_response
//     evidence item, or of the daemon's record of a tool call (a log item
//     whose content is the tool result JSON with a top-level status_code).
//     It is -1 for any other item, or when the content will not decode.
//   - markerPresent(evidence, marker) -> bool: true iff at least one
//     evidence item's evidenceText contains marker as an exact,
//     case-sensitive substring (the deterministic check behind "proof of
//     control, not damage").
//
// Every helper here is a pure, terminating function of its arguments —
// never an LLM call, wall-clock read, or source of randomness — matching
// the same determinism contract internal/engine/settlement.Evaluator
// documents, and never a hard runtime error for an evidence item its
// operation does not apply to: each one degrades to its documented
// not-applicable sentinel instead, so a mixed-type evidence set never trips
// a CEL runtime error partway through an evidence.exists(...) scan.
func helperFunctionOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function(fnEvidenceText,
			cel.Overload("evidence_text_map",
				[]*cel.Type{EvidenceMapType}, cel.StringType,
				cel.UnaryBinding(evidenceTextImpl),
			),
		),
		cel.Function(fnRegexMatch,
			cel.Overload("regex_match_string_string",
				[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(regexMatchImpl),
			),
		),
		cel.Function(fnJSONPath,
			cel.Overload("json_path_string_string",
				[]*cel.Type{cel.StringType, cel.StringType}, cel.DynType,
				cel.BinaryBinding(jsonPathImpl),
			),
		),
		cel.Function(fnHTTPStatus,
			cel.Overload("http_status_map",
				[]*cel.Type{EvidenceMapType}, cel.IntType,
				cel.UnaryBinding(httpStatusImpl),
			),
		),
		cel.Function(fnMarkerPresent,
			cel.Overload("marker_present_list_string",
				[]*cel.Type{EvidenceListType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(markerPresentImpl),
			),
		),
	}
}

func evidenceTextImpl(v ref.Val) ref.Val {
	item, ok := evidenceItemFromVal(v)
	if !ok {
		return types.String("")
	}
	text, ok := evidenceItemText(item)
	if !ok {
		return types.String("")
	}
	return types.String(text)
}

func httpStatusImpl(v ref.Val) ref.Val {
	const notApplicable = types.Int(-1)

	item, ok := evidenceItemFromVal(v)
	if !ok {
		return notApplicable
	}
	typ, _ := item["type"].(string)
	// Two evidence types carry a status. Each other type is not applicable.
	evidence := finding.EvidenceType(typ)
	if evidence == finding.EvidenceHTTPResponse {
		content, ok := item["content"].(map[string]any)
		if !ok {
			return notApplicable
		}
		// JSON numbers decode to float64 through normalizeContent's round-trip.
		code, ok := content["status_code"].(float64)
		if !ok {
			return notApplicable
		}
		return types.Int(int64(code))
	}
	if evidence == finding.EvidenceLog {
		// The daemon's record of a tool call (gibson#810): content is the
		// JSON the tool returned, with proto field names. An HTTP tool
		// reports the response status in its top-level status_code field.
		code, ok := recordedStatusCode(item["content"])
		if !ok {
			return notApplicable
		}
		return types.Int(code)
	}
	return notApplicable
}

// recordedStatusCode reads the top-level status_code of a recorded tool
// result. The content is the JSON text that the flight recorder stored, or
// the object it decodes to. Anything that is not a JSON object with an
// integral status_code in the HTTP range is not applicable.
func recordedStatusCode(content any) (int64, bool) {
	var raw string
	switch c := content.(type) {
	case string:
		raw = c
	case map[string]any:
		data, err := json.Marshal(c)
		if err != nil {
			return 0, false
		}
		raw = string(data)
	default:
		return 0, false
	}
	if !gjson.Valid(raw) {
		return 0, false
	}
	root := gjson.Parse(raw)
	if !root.IsObject() {
		return 0, false
	}
	field := root.Get("status_code")
	if field.Type != gjson.Number {
		return 0, false
	}
	code := field.Float()
	if code != float64(int64(code)) || code < 100 || code > 599 {
		return 0, false
	}
	return int64(code), true
}

func regexMatchImpl(textVal, patternVal ref.Val) ref.Val {
	text, ok := textVal.Value().(string)
	if !ok {
		return types.NewErr("celenv: %s: text argument must be a string", fnRegexMatch)
	}
	pattern, ok := patternVal.Value().(string)
	if !ok {
		return types.NewErr("celenv: %s: pattern argument must be a string", fnRegexMatch)
	}
	matched, err := regexp.MatchString(pattern, text)
	if err != nil {
		return types.NewErr("celenv: %s: invalid pattern %q: %v", fnRegexMatch, pattern, err)
	}
	return types.Bool(matched)
}

func jsonPathImpl(textVal, pathVal ref.Val) ref.Val {
	text, ok := textVal.Value().(string)
	if !ok {
		return types.NewErr("celenv: %s: text argument must be a string", fnJSONPath)
	}
	path, ok := pathVal.Value().(string)
	if !ok {
		return types.NewErr("celenv: %s: path argument must be a string", fnJSONPath)
	}
	if !gjson.Valid(text) {
		return types.NullValue
	}
	result := gjson.Get(text, path)
	if !result.Exists() {
		return types.NullValue
	}
	return types.DefaultTypeAdapter.NativeToValue(result.Value())
}

func markerPresentImpl(listVal, markerVal ref.Val) ref.Val {
	marker, ok := markerVal.Value().(string)
	if !ok || marker == "" {
		return types.False
	}
	lister, ok := listVal.(traits.Lister)
	if !ok {
		return types.False
	}
	size, ok := lister.Size().Value().(int64)
	if !ok {
		return types.False
	}
	for i := range size {
		item, ok := evidenceItemFromVal(lister.Get(types.Int(i)))
		if !ok {
			continue
		}
		text, ok := evidenceItemText(item)
		if !ok {
			continue
		}
		if strings.Contains(text, marker) {
			return types.True
		}
	}
	return types.False
}

// evidenceItemText is evidenceText's implementation, working from the plain
// map[string]any an evidence item converts to (see evidenceItemFromVal)
// rather than a finding.EnhancedEvidence directly: one case for each
// evidence type, on the JSON-normalized shape [normalizeContent] guarantees.
func evidenceItemText(item map[string]any) (string, bool) {
	typ, _ := item["type"].(string)
	content := item["content"]

	switch finding.EvidenceType(typ) {
	case finding.EvidenceHTTPRequest, finding.EvidenceHTTPResponse:
		return stringField(content, "body")

	case finding.EvidenceConversation:
		cm, ok := content.(map[string]any)
		if !ok {
			return "", false
		}
		msgs, _ := cm["messages"].([]any)
		var b strings.Builder
		for _, mi := range msgs {
			msg, ok := mi.(map[string]any)
			if !ok {
				continue
			}
			if c, ok := msg["content"].(string); ok {
				b.WriteString(c)
				b.WriteByte('\n')
			}
		}
		return b.String(), true

	case finding.EvidenceLog, finding.EvidencePayload, finding.EvidenceCodeSnippet, finding.EvidenceNetworkTrace:
		if s, ok := content.(string); ok {
			return s, true
		}
		data, err := json.Marshal(content)
		if err != nil {
			return "", false
		}
		return string(data), true

	case finding.EvidenceScreenshot:
		// A screenshot has no text representation.
		return "", false

	default:
		// Any evidence type this catalog does not know about: no text
		// representation.
		return "", false
	}
}

func stringField(content any, key string) (string, bool) {
	m, ok := content.(map[string]any)
	if !ok {
		return "", false
	}
	s, ok := m[key].(string)
	return s, ok
}
