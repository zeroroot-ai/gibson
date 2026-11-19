// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"encoding/json"
	"reflect"

	"github.com/google/cel-go/common/types/ref"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// mapStringAnyType is the reflect.Type CompiledPredicate.Evaluate's activation
// maps use for "evidence" and the helper functions in functions.go convert an
// evidence-item ref.Val back to. Keeping it as a package-level value avoids
// reflect.TypeOf allocating a new value on every conversion.
var mapStringAnyType = reflect.TypeOf(map[string]any{})

// evidenceToCEL converts a recorded evidence set into the plain Go value
// CompiledPredicate.Evaluate hands cel-go's activation for [EvidenceVariable]
// — cel-go adapts native Go maps/slices/scalars to CEL values lazily as an
// expression touches them (the same pattern
// internal/engine/brain/condition.go's evalCondition uses for its "nodes"
// and "mission" bags), so no manual ref.Val construction is needed here.
func evidenceToCEL(evidence []*typespb.Evidence) []any {
	items := make([]any, len(evidence))
	for i, e := range evidence {
		items[i] = evidenceItemMap(e)
	}
	return items
}

// evidenceItemMap renders one piece of evidence as the map [EvidenceMapType]
// describes: "type" is the name of the evidence type, "title" is the title,
// and "content" is the content. The content of a request, a response and a
// conversation is JSON text, and the map holds the value that the text
// decodes to (see decodeContent). The content of each other type is the text
// as stored.
func evidenceItemMap(e *typespb.Evidence) map[string]any {
	var content any = e.GetContent()
	switch e.GetType() {
	case typespb.EvidenceType_EVIDENCE_TYPE_REQUEST,
		typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE,
		typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION:
		content = decodeContent(e.GetContent())
	case typespb.EvidenceType_EVIDENCE_TYPE_UNSPECIFIED,
		typespb.EvidenceType_EVIDENCE_TYPE_SCREENSHOT,
		typespb.EvidenceType_EVIDENCE_TYPE_CODE,
		typespb.EvidenceType_EVIDENCE_TYPE_LOG,
		typespb.EvidenceType_EVIDENCE_TYPE_OTHER,
		typespb.EvidenceType_EVIDENCE_TYPE_PAYLOAD,
		typespb.EvidenceType_EVIDENCE_TYPE_NETWORK_TRACE:
		// The content of these types is the text as stored.
	}
	return map[string]any{
		"type":    string(finding.EvidenceTypeName(e.GetType())),
		"title":   e.GetTitle(),
		"content": content,
	}
}

// decodeContent decodes JSON text into one of JSON's own value shapes:
// map[string]any, []any, string, float64, bool, or nil. Text that is not
// valid JSON decodes to nil rather than an error: one malformed piece of
// evidence degrades that item's content to "absent" for every helper
// function (evidenceText, httpStatus, … all treat a missing/wrong-shaped
// field as their documented not-applicable sentinel), it never aborts
// evaluation of the whole evidence set.
func decodeContent(text string) any {
	var out any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil
	}
	return out
}

// evidenceItemFromVal converts a helper function's evidence-item argument
// (a ref.Val of CEL type [EvidenceMapType]) back into a Go
// map[string]any. It returns (nil, false) for a value that will not convert
// — cel-go's per-overload runtime type-guard (see the UnaryBinding /
// BinaryBinding doc comments) means this should not happen for a compiled
// predicate, but a helper never panics on it regardless: it degrades to its
// documented not-applicable sentinel, the same fail-closed-to-false stance
// that internal/engine/brain takes for a mission condition.
func evidenceItemFromVal(v ref.Val) (map[string]any, bool) {
	native, err := v.ConvertToNative(mapStringAnyType)
	if err != nil {
		return nil, false
	}
	m, ok := native.(map[string]any)
	return m, ok
}
