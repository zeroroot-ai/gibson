// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package findingtest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	sdkfinding "github.com/zeroroot-ai/sdk/finding"
)

func TestNewEvidence_StringContentIsKeptAsIs(t *testing.T) {
	got := NewEvidence(sdkfinding.EvidenceScreenshot, "shot", "raw text")

	assert.Equal(t, "shot", got.GetTitle())
	assert.Equal(t, "raw text", got.GetContent())
	assert.Equal(t, typespb.EvidenceType_EVIDENCE_TYPE_SCREENSHOT, got.GetType())
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, got.GetTier())
	assert.Empty(t, got.GetToolCallId())
}

func TestNewEvidence_OtherContentIsJSON(t *testing.T) {
	got := NewEvidence(sdkfinding.EvidenceHTTPRequest, "req", map[string]int{"b": 2, "a": 1})

	assert.JSONEq(t, `{"a":1,"b":2}`, got.GetContent())
	assert.Equal(t, typespb.EvidenceType_EVIDENCE_TYPE_REQUEST, got.GetType())
}

func TestNewEvidence_PanicsOnContentThatDoesNotMarshal(t *testing.T) {
	assert.PanicsWithValue(t, "findingtest: marshal content: json: unsupported type: chan int", func() {
		NewEvidence(sdkfinding.EvidenceHTTPRequest, "bad", make(chan int))
	})
}

func TestNewHTTPResponseEvidence(t *testing.T) {
	got := NewHTTPResponseEvidence("resp", 404, map[string]string{"X-A": "1"}, "gone", 2*time.Second)

	assert.Equal(t, typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE, got.GetType())
	assert.JSONEq(t,
		`{"status_code":404,"headers":{"X-A":"1"},"body":"gone","duration":2000000000}`, got.GetContent())

	bare := NewHTTPResponseEvidence("resp", 200, nil, "", 0)
	assert.JSONEq(t, `{"status_code":200,"duration":0}`, bare.GetContent(), "empty headers and body are omitted")
}

func TestNewConversationEvidence(t *testing.T) {
	msgs := []ConversationMessage{
		NewConversationMessage("user", "hi"),
		NewConversationMessage("assistant", "hello"),
	}
	require.Equal(t, ConversationMessage{Role: "user", Content: "hi"}, msgs[0])

	got := NewConversationEvidence("chat", msgs)

	assert.Equal(t, "chat", got.GetTitle())
	assert.JSONEq(t,
		`{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"hello"}]}`, got.GetContent())
}
