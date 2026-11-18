// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"testing"

	"github.com/stretchr/testify/assert"

	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

func TestDecodeContent(t *testing.T) {
	t.Run("empty text decodes to nil", func(t *testing.T) {
		assert.Nil(t, decodeContent(""))
	})

	t.Run("text that is not JSON decodes to nil", func(t *testing.T) {
		assert.Nil(t, decodeContent("not json {"))
	})

	t.Run("a JSON object decodes into JSON's own shapes", func(t *testing.T) {
		got := decodeContent(`{"a":1,"b":"x"}`)

		m, ok := got.(map[string]any)
		if assert.True(t, ok, "expected a map[string]any, got %T", got) {
			assert.InDelta(t, float64(1), m["a"], 0.0001)
			assert.Equal(t, "x", m["b"])
		}
	})
}

// TestEvidenceItemMap proves that the content of a request, a response and a
// conversation is decoded, and that the content of each other type stays text.
func TestEvidenceItemMap(t *testing.T) {
	response := evidenceItemMap(&typespb.Evidence{
		Type: typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE, Title: "r", Content: `{"status_code":200}`,
	})
	assert.Equal(t, "http_response", response["type"])
	assert.Equal(t, map[string]any{"status_code": float64(200)}, response["content"])

	logItem := evidenceItemMap(&typespb.Evidence{
		Type: typespb.EvidenceType_EVIDENCE_TYPE_LOG, Content: `{"status_code":200}`,
	})
	assert.Equal(t, "log", logItem["type"])
	assert.Equal(t, `{"status_code":200}`, logItem["content"], "a log item keeps its text")

	assert.Nil(t, evidenceItemMap(&typespb.Evidence{
		Type: typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE, Content: "oops",
	})["content"])
}
