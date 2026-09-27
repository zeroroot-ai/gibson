// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package builtin

import (
	"encoding/json"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

// evidenceText extracts a plain-text representation of one piece of
// evidence's content, if the evidence's type has one. It returns
// (text, false) for evidence with no meaningful text representation (a
// screenshot, or content that does not decode as its declared type), never
// an error: a single malformed or non-textual evidence item is skipped by
// its caller, not treated as a hard failure — the same evidence set always
// skips the same items, so this stays deterministic.
func evidenceText(e finding.EnhancedEvidence) (string, bool) {
	switch e.Type {
	case finding.EvidenceHTTPRequest:
		var req finding.HTTPRequestEvidence
		if !decodeContent(e.Content, &req) {
			return "", false
		}
		return req.Body, true

	case finding.EvidenceHTTPResponse:
		var resp finding.HTTPResponseEvidence
		if !decodeContent(e.Content, &resp) {
			return "", false
		}
		return resp.Body, true

	case finding.EvidenceConversation:
		var conv finding.ConversationEvidence
		if !decodeContent(e.Content, &conv) {
			return "", false
		}
		var b strings.Builder
		for _, m := range conv.Messages {
			b.WriteString(m.Content)
			b.WriteByte('\n')
		}
		return b.String(), true

	case finding.EvidenceLog, finding.EvidencePayload, finding.EvidenceCodeSnippet, finding.EvidenceNetworkTrace:
		if s, ok := e.Content.(string); ok {
			return s, true
		}
		data, err := json.Marshal(e.Content)
		if err != nil {
			return "", false
		}
		return string(data), true

	default:
		// EvidenceScreenshot and any evidence type this package does not
		// know about: no text representation.
		return "", false
	}
}

// decodeContent round-trips content through JSON into out, the same
// pattern EnhancedEvidence.Validate uses: content may already be the
// concrete struct a constructor built, or a generic map[string]any if it
// arrived via a JSON-deserialized graph read, and this normalizes both.
func decodeContent(content any, out any) bool {
	data, err := json.Marshal(content)
	if err != nil {
		return false
	}
	return json.Unmarshal(data, out) == nil
}
