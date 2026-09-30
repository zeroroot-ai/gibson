// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// nativeVal adapts a plain Go value (typically a map[string]any built by
// evidenceItemMap, or a []any of such maps) into the ref.Val a helper
// function receives at runtime — the same adaptation cel-go's own activation
// performs lazily for CompiledPredicate.Evaluate's "evidence" variable (see
// evidence.go).
func nativeVal(v any) ref.Val {
	return types.DefaultTypeAdapter.NativeToValue(v)
}

// These tests call the helper implementations directly (whitebox, same
// package) rather than only through a compiled predicate, specifically to
// reach the not-applicable/degrade branches a real compiled predicate's
// runtime type-guard would otherwise make unreachable — see
// evidenceItemFromVal's doc comment.

func TestEvidenceTextImpl(t *testing.T) {
	t.Run("a value that will not convert to an evidence-item map degrades to empty", func(t *testing.T) {
		got := evidenceTextImpl(types.Int(5))
		assert.Equal(t, types.String(""), got)
	})

	t.Run("an evidence item with no text representation degrades to empty", func(t *testing.T) {
		item := evidenceItemMap(finding.NewEnhancedEvidence(finding.EvidenceScreenshot, "shot", "binary"))
		got := evidenceTextImpl(nativeVal(item))
		assert.Equal(t, types.String(""), got)
	})

	t.Run("an evidence item with text returns it", func(t *testing.T) {
		item := evidenceItemMap(httpResponseEvidence(200, "hello"))
		got := evidenceTextImpl(nativeVal(item))
		assert.Equal(t, types.String("hello"), got)
	})
}

func TestHTTPStatusImpl(t *testing.T) {
	t.Run("a value that will not convert to an evidence-item map is not applicable", func(t *testing.T) {
		got := httpStatusImpl(types.String("nope"))
		assert.Equal(t, types.Int(-1), got)
	})

	t.Run("a non-http_response type is not applicable", func(t *testing.T) {
		item := evidenceItemMap(finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "text"))
		got := httpStatusImpl(nativeVal(item))
		assert.Equal(t, types.Int(-1), got)
	})

	t.Run("http_response content that is not a map is not applicable", func(t *testing.T) {
		item := map[string]any{"type": string(finding.EvidenceHTTPResponse), "content": "not a map"}
		got := httpStatusImpl(nativeVal(item))
		assert.Equal(t, types.Int(-1), got)
	})

	t.Run("http_response content with no status_code is not applicable", func(t *testing.T) {
		item := map[string]any{
			"type":    string(finding.EvidenceHTTPResponse),
			"content": map[string]any{"body": "no status here"},
		}
		got := httpStatusImpl(nativeVal(item))
		assert.Equal(t, types.Int(-1), got)
	})

	t.Run("http_response content with a status_code returns it", func(t *testing.T) {
		item := evidenceItemMap(httpResponseEvidence(204, ""))
		got := httpStatusImpl(nativeVal(item))
		assert.Equal(t, types.Int(204), got)
	})
}

func TestRegexMatchImpl(t *testing.T) {
	t.Run("a non-string text argument errors", func(t *testing.T) {
		got := regexMatchImpl(types.Int(1), types.String("x"))
		assert.True(t, types.IsError(got))
	})

	t.Run("a non-string pattern argument errors", func(t *testing.T) {
		got := regexMatchImpl(types.String("x"), types.Int(1))
		assert.True(t, types.IsError(got))
	})

	t.Run("an invalid regex pattern errors", func(t *testing.T) {
		got := regexMatchImpl(types.String("x"), types.String("(unbalanced"))
		assert.True(t, types.IsError(got))
	})

	t.Run("a matching pattern is true", func(t *testing.T) {
		got := regexMatchImpl(types.String("hello world"), types.String("^hello"))
		assert.Equal(t, types.Bool(true), got)
	})

	t.Run("a non-matching pattern is false", func(t *testing.T) {
		got := regexMatchImpl(types.String("hello world"), types.String("^bye"))
		assert.Equal(t, types.Bool(false), got)
	})
}

func TestJSONPathImpl(t *testing.T) {
	t.Run("a non-string text argument errors", func(t *testing.T) {
		got := jsonPathImpl(types.Int(1), types.String("a"))
		assert.True(t, types.IsError(got))
	})

	t.Run("a non-string path argument errors", func(t *testing.T) {
		got := jsonPathImpl(types.String("{}"), types.Int(1))
		assert.True(t, types.IsError(got))
	})

	t.Run("text that is not valid JSON is null", func(t *testing.T) {
		got := jsonPathImpl(types.String("not json"), types.String("a"))
		assert.Equal(t, types.NullValue, got)
	})

	t.Run("a path that selects nothing is null", func(t *testing.T) {
		got := jsonPathImpl(types.String(`{"a":1}`), types.String("b"))
		assert.Equal(t, types.NullValue, got)
	})

	t.Run("a path that resolves returns the value", func(t *testing.T) {
		got := jsonPathImpl(types.String(`{"a":1}`), types.String("a"))
		d, ok := got.(types.Double)
		require.True(t, ok, "expected a types.Double, got %T", got)
		assert.InDelta(t, float64(1), float64(d), 0.0001)
	})
}

func TestMarkerPresentImpl(t *testing.T) {
	evidenceList := func(items ...any) ref.Val {
		return nativeVal(items)
	}

	t.Run("a non-string marker is false", func(t *testing.T) {
		got := markerPresentImpl(evidenceList(), types.Int(5))
		assert.Equal(t, types.False, got)
	})

	t.Run("an empty marker is false", func(t *testing.T) {
		got := markerPresentImpl(evidenceList(), types.String(""))
		assert.Equal(t, types.False, got)
	})

	t.Run("a non-list first argument is false", func(t *testing.T) {
		got := markerPresentImpl(types.String("not a list"), types.String("marker"))
		assert.Equal(t, types.False, got)
	})

	t.Run("a non-map item in the list is skipped, not fatal", func(t *testing.T) {
		matching := evidenceItemMap(finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "has the marker-xyz in it"))
		got := markerPresentImpl(evidenceList("not a map item", matching), types.String("marker-xyz"))
		assert.Equal(t, types.True, got)
	})

	t.Run("no item matches", func(t *testing.T) {
		item := evidenceItemMap(finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "nothing here"))
		got := markerPresentImpl(evidenceList(item), types.String("marker-xyz"))
		assert.Equal(t, types.False, got)
	})
}

func TestEvidenceItemText(t *testing.T) {
	t.Run("conversation content that is not a map has no text", func(t *testing.T) {
		text, ok := evidenceItemText(map[string]any{
			"type":    string(finding.EvidenceConversation),
			"content": "not a map",
		})
		assert.False(t, ok)
		assert.Empty(t, text)
	})

	t.Run("a non-map message in a conversation is skipped, not fatal", func(t *testing.T) {
		text, ok := evidenceItemText(map[string]any{
			"type": string(finding.EvidenceConversation),
			"content": map[string]any{
				"messages": []any{
					"garbage",
					map[string]any{"role": "user", "content": "hi there"},
				},
			},
		})
		require.True(t, ok)
		assert.Equal(t, "hi there\n", text)
	})

	t.Run("log content that is not a string JSON-marshals", func(t *testing.T) {
		text, ok := evidenceItemText(map[string]any{
			"type":    string(finding.EvidenceLog),
			"content": map[string]any{"a": float64(1)},
		})
		require.True(t, ok)
		assert.JSONEq(t, `{"a":1}`, text)
	})

	t.Run("log content that will not JSON-marshal has no text", func(t *testing.T) {
		text, ok := evidenceItemText(map[string]any{
			"type":    string(finding.EvidenceLog),
			"content": make(chan int),
		})
		assert.False(t, ok)
		assert.Empty(t, text)
	})

	t.Run("http response content that is not a map has no text", func(t *testing.T) {
		text, ok := evidenceItemText(map[string]any{
			"type":    string(finding.EvidenceHTTPResponse),
			"content": "not a map",
		})
		assert.False(t, ok)
		assert.Empty(t, text)
	})

	t.Run("an evidence type this catalog does not know about has no text", func(t *testing.T) {
		text, ok := evidenceItemText(map[string]any{
			"type":    "some_future_evidence_type",
			"content": "whatever",
		})
		assert.False(t, ok)
		assert.Empty(t, text)
	})
}
