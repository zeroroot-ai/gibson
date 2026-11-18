// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package findingtest builds evidence items for tests. The tests of the
// settlement predicates use it.
package findingtest

import (
	"encoding/json"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	sdkfinding "github.com/zeroroot-ai/sdk/finding"
)

// NewEvidence returns a tier 2 item of the type. A string is the content as it
// is. Any other value is the content as JSON text.
func NewEvidence(typ sdkfinding.EvidenceType, title string, content any) *typespb.Evidence {
	text, ok := content.(string)
	if !ok {
		raw, err := json.Marshal(content)
		if err != nil {
			panic("findingtest: marshal content: " + err.Error())
		}
		text = string(raw)
	}
	return &typespb.Evidence{
		Title:   title,
		Type:    finding.EvidenceTypeFromName(typ),
		Content: text,
		Tier:    typespb.EvidenceTier_EVIDENCE_TIER_TYPED,
	}
}

// HTTPResponseEvidence is the content of an HTTP response item.
type HTTPResponseEvidence struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Duration   time.Duration     `json:"duration"`
}

// NewHTTPResponseEvidence returns an HTTP response item.
func NewHTTPResponseEvidence(
	title string, statusCode int, headers map[string]string, body string, duration time.Duration,
) *typespb.Evidence {
	return NewEvidence(sdkfinding.EvidenceHTTPResponse, title, HTTPResponseEvidence{
		StatusCode: statusCode, Headers: headers, Body: body, Duration: duration,
	})
}

// ConversationMessage is one message of a conversation item.
type ConversationMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ConversationEvidence is the content of a conversation item.
type ConversationEvidence struct {
	Messages []ConversationMessage `json:"messages"`
}

// NewConversationMessage returns one message.
func NewConversationMessage(role, content string) ConversationMessage {
	return ConversationMessage{Role: role, Content: content}
}

// NewConversationEvidence returns a conversation item.
func NewConversationEvidence(title string, messages []ConversationMessage) *typespb.Evidence {
	return NewEvidence(sdkfinding.EvidenceConversation, title, ConversationEvidence{Messages: messages})
}
