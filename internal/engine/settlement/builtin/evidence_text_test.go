// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

func TestEvidenceText(t *testing.T) {
	tests := []struct {
		name     string
		evidence finding.EnhancedEvidence
		wantText string
		wantOK   bool
	}{
		{
			name:     "http request body",
			evidence: finding.NewHTTPRequestEvidence("req", "GET", "https://target.example/admin", nil, "body-of-request"),
			wantText: "body-of-request",
			wantOK:   true,
		},
		{
			name:     "http response body",
			evidence: finding.NewHTTPResponseEvidence("resp", 200, nil, "body-of-response", 0),
			wantText: "body-of-response",
			wantOK:   true,
		},
		{
			name: "conversation joins message content",
			evidence: finding.NewConversationEvidence("chat", []finding.ConversationMessage{
				finding.NewConversationMessage("user", "hello"),
				finding.NewConversationMessage("assistant", "world"),
			}),
			wantText: "hello\nworld\n",
			wantOK:   true,
		},
		{
			name:     "log with string content returned as-is",
			evidence: finding.NewEnhancedEvidence(finding.EvidenceLog, "log", "plain text log line"),
			wantText: "plain text log line",
			wantOK:   true,
		},
		{
			name:     "payload with structured content falls back to JSON",
			evidence: finding.NewEnhancedEvidence(finding.EvidencePayload, "payload", map[string]any{"nonce": "abc123"}),
			wantText: `{"nonce":"abc123"}`,
			wantOK:   true,
		},
		{
			name:     "code snippet with string content",
			evidence: finding.NewEnhancedEvidence(finding.EvidenceCodeSnippet, "snippet", "fn main() {}"),
			wantText: "fn main() {}",
			wantOK:   true,
		},
		{
			name:     "network trace with structured content falls back to JSON",
			evidence: finding.NewEnhancedEvidence(finding.EvidenceNetworkTrace, "trace", map[string]any{"bytes": float64(128)}),
			wantText: `{"bytes":128}`,
			wantOK:   true,
		},
		{
			name:     "screenshot has no text representation",
			evidence: finding.NewEnhancedEvidence(finding.EvidenceScreenshot, "shot", "base64-blob"),
			wantOK:   false,
		},
		{
			name:     "unknown evidence type has no text representation",
			evidence: finding.EnhancedEvidence{Type: finding.EvidenceType("future_type"), Title: "t", Content: "x"},
			wantOK:   false,
		},
		{
			name:     "http response content that will not decode as HTTPResponseEvidence",
			evidence: finding.EnhancedEvidence{Type: finding.EvidenceHTTPResponse, Title: "resp", Content: func() {}},
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, ok := evidenceText(tt.evidence)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantText, text)
			}
		})
	}
}

func TestDecodeContent(t *testing.T) {
	t.Run("decodes a matching shape", func(t *testing.T) {
		var out finding.HTTPResponseEvidence
		ok := decodeContent(finding.HTTPResponseEvidence{StatusCode: 200}, &out)
		assert.True(t, ok)
		assert.Equal(t, 200, out.StatusCode)
	})

	t.Run("fails when content cannot be marshaled to JSON", func(t *testing.T) {
		var out finding.HTTPResponseEvidence
		ok := decodeContent(func() {}, &out)
		assert.False(t, ok)
	})

	t.Run("fails when the JSON shape does not fit the target", func(t *testing.T) {
		var out int
		ok := decodeContent(map[string]any{"status_code": "not-a-number"}, &out)
		assert.False(t, ok)
	})
}
