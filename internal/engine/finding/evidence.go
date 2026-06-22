package finding

import (
	"encoding/json"
	"fmt"
	"time"
)

// EvidenceType represents the type of evidence collected
type EvidenceType string

const (
	EvidenceHTTPRequest  EvidenceType = "http_request"
	EvidenceHTTPResponse EvidenceType = "http_response"
	EvidenceScreenshot   EvidenceType = "screenshot"
	EvidenceLog          EvidenceType = "log"
	EvidencePayload      EvidenceType = "payload"
	EvidenceConversation EvidenceType = "conversation"
	EvidenceCodeSnippet  EvidenceType = "code_snippet"
	EvidenceNetworkTrace EvidenceType = "network_trace"
)

// EnhancedEvidence extends the base evidence type with structured data
type EnhancedEvidence struct {
	Type      EvidenceType `json:"type"`
	Title     string       `json:"title"`
	Content   any          `json:"content"` // Type-specific structured content
	Timestamp time.Time    `json:"timestamp"`
}

// HTTPRequestEvidence represents HTTP request evidence
type HTTPRequestEvidence struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// HTTPResponseEvidence represents HTTP response evidence
type HTTPResponseEvidence struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Duration   time.Duration     `json:"duration"` // Response time
}

// ConversationEvidence represents a conversation/dialogue evidence
type ConversationEvidence struct {
	Messages []ConversationMessage `json:"messages"`
}

// ConversationMessage represents a single message in a conversation
type ConversationMessage struct {
	Role      string    `json:"role"` // user, assistant, system
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

// NewEnhancedEvidence creates a new enhanced evidence object
func NewEnhancedEvidence(evidenceType EvidenceType, title string, content any) EnhancedEvidence {
	return EnhancedEvidence{
		Type:      evidenceType,
		Title:     title,
		Content:   content,
		Timestamp: time.Now(),
	}
}

// NewHTTPRequestEvidence creates HTTP request evidence
func NewHTTPRequestEvidence(title, method, url string, headers map[string]string, body string) EnhancedEvidence {
	content := HTTPRequestEvidence{
		Method:  method,
		URL:     url,
		Headers: headers,
		Body:    body,
	}
	return NewEnhancedEvidence(EvidenceHTTPRequest, title, content)
}

// NewHTTPResponseEvidence creates HTTP response evidence
func NewHTTPResponseEvidence(title string, statusCode int, headers map[string]string, body string, duration time.Duration) EnhancedEvidence {
	content := HTTPResponseEvidence{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
		Duration:   duration,
	}
	return NewEnhancedEvidence(EvidenceHTTPResponse, title, content)
}

// NewConversationEvidence creates conversation evidence
func NewConversationEvidence(title string, messages []ConversationMessage) EnhancedEvidence {
	content := ConversationEvidence{
		Messages: messages,
	}
	return NewEnhancedEvidence(EvidenceConversation, title, content)
}

// NewConversationMessage creates a new conversation message
func NewConversationMessage(role, content string) ConversationMessage {
	return ConversationMessage{
		Role:      role,
		Content:   content,
		Timestamp: time.Now(),
	}
}

// Validate validates the evidence based on its type
func (e EnhancedEvidence) Validate() error {
	if e.Title == "" {
		return fmt.Errorf("evidence title cannot be empty")
	}

	if e.Content == nil {
		return fmt.Errorf("evidence content cannot be nil")
	}

	switch e.Type {
	case EvidenceHTTPRequest:
		return e.validateHTTPRequest()
	case EvidenceHTTPResponse:
		return e.validateHTTPResponse()
	case EvidenceConversation:
		return e.validateConversation()
	case EvidenceScreenshot, EvidenceLog, EvidencePayload, EvidenceCodeSnippet, EvidenceNetworkTrace:
		// These types can have flexible content
		return nil
	default:
		return fmt.Errorf("unknown evidence type: %s", e.Type)
	}
}

// validateHTTPRequest validates HTTP request evidence
func (e EnhancedEvidence) validateHTTPRequest() error {
	// Try to unmarshal to HTTPRequestEvidence
	var req HTTPRequestEvidence
	data, err := json.Marshal(e.Content)
	if err != nil {
		return fmt.Errorf("failed to marshal HTTP request evidence: %w", err)
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("invalid HTTP request evidence format: %w", err)
	}

	if req.Method == "" {
		return fmt.Errorf("HTTP request method cannot be empty")
	}
	if req.URL == "" {
		return fmt.Errorf("HTTP request URL cannot be empty")
	}

	return nil
}

// validateHTTPResponse validates HTTP response evidence
func (e EnhancedEvidence) validateHTTPResponse() error {
	// Try to unmarshal to HTTPResponseEvidence
	var resp HTTPResponseEvidence
	data, err := json.Marshal(e.Content)
	if err != nil {
		return fmt.Errorf("failed to marshal HTTP response evidence: %w", err)
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("invalid HTTP response evidence format: %w", err)
	}

	if resp.StatusCode < 100 || resp.StatusCode > 599 {
		return fmt.Errorf("invalid HTTP status code: %d", resp.StatusCode)
	}

	return nil
}

// validateConversation validates conversation evidence
func (e EnhancedEvidence) validateConversation() error {
	// Try to unmarshal to ConversationEvidence
	var conv ConversationEvidence
	data, err := json.Marshal(e.Content)
	if err != nil {
		return fmt.Errorf("failed to marshal conversation evidence: %w", err)
	}
	if err := json.Unmarshal(data, &conv); err != nil {
		return fmt.Errorf("invalid conversation evidence format: %w", err)
	}

	if len(conv.Messages) == 0 {
		return fmt.Errorf("conversation must have at least one message")
	}

	for i, msg := range conv.Messages {
		if msg.Role == "" {
			return fmt.Errorf("message %d: role cannot be empty", i)
		}
		if msg.Content == "" {
			return fmt.Errorf("message %d: content cannot be empty", i)
		}
	}

	return nil
}

// GetHTTPRequest extracts HTTP request evidence from content
func (e EnhancedEvidence) GetHTTPRequest() (*HTTPRequestEvidence, error) {
	if e.Type != EvidenceHTTPRequest {
		return nil, fmt.Errorf("evidence is not HTTP request type")
	}

	var req HTTPRequestEvidence
	data, err := json.Marshal(e.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence content: %w", err)
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal HTTP request: %w", err)
	}

	return &req, nil
}

// GetHTTPResponse extracts HTTP response evidence from content
func (e EnhancedEvidence) GetHTTPResponse() (*HTTPResponseEvidence, error) {
	if e.Type != EvidenceHTTPResponse {
		return nil, fmt.Errorf("evidence is not HTTP response type")
	}

	var resp HTTPResponseEvidence
	data, err := json.Marshal(e.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence content: %w", err)
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal HTTP response: %w", err)
	}

	return &resp, nil
}

// GetConversation extracts conversation evidence from content
func (e EnhancedEvidence) GetConversation() (*ConversationEvidence, error) {
	if e.Type != EvidenceConversation {
		return nil, fmt.Errorf("evidence is not conversation type")
	}

	var conv ConversationEvidence
	data, err := json.Marshal(e.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence content: %w", err)
	}
	if err := json.Unmarshal(data, &conv); err != nil {
		return nil, fmt.Errorf("failed to unmarshal conversation: %w", err)
	}

	return &conv, nil
}
