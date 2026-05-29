package types

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TargetType is the type of target system (e.g. "llm_chat", "llm_api", "rag").
//
// Note: Although originally planned for removal in favor of plain string types with
// schema-based validation, TargetType remains in active use across attack/, payload/,
// and component/ packages (including payload analytics maps keyed by this type). A full
// migration requires updating all call sites and analytics structs simultaneously.
// New code should prefer string literals or NewTargetWithConnection; TargetType constants
// are kept to avoid breaking existing callers.
type TargetType string

const (
	TargetTypeLLMChat    TargetType = "llm_chat"
	TargetTypeLLMAPI     TargetType = "llm_api"
	TargetTypeRAG        TargetType = "rag"
	TargetTypeAgent      TargetType = "agent"
	TargetTypeEmbedding  TargetType = "embedding"
	TargetTypeMultimodal TargetType = "multimodal"
	TargetTypeCustom     TargetType = "custom"
)

// String returns the string representation of TargetType
func (t TargetType) String() string {
	return string(t)
}

// IsValid checks if the TargetType is a valid value
func (t TargetType) IsValid() bool {
	switch t {
	case TargetTypeLLMChat, TargetTypeLLMAPI, TargetTypeRAG,
		TargetTypeAgent, TargetTypeEmbedding, TargetTypeMultimodal, TargetTypeCustom:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler. It returns an error for invalid
// TargetType values so that callers are notified early rather than silently
// emitting an unrecognised string into JSON output.
func (t TargetType) MarshalJSON() ([]byte, error) {
	if !t.IsValid() {
		return nil, fmt.Errorf("invalid target type: %s", string(t))
	}
	return json.Marshal(string(t))
}

// UnmarshalJSON implements json.Unmarshaler
func (t *TargetType) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	targetType := TargetType(str)
	if !targetType.IsValid() {
		return fmt.Errorf("invalid target type: %s", str)
	}

	*t = targetType
	return nil
}

// AllTargetTypes returns a slice containing all valid TargetType values
func AllTargetTypes() []TargetType {
	return []TargetType{
		TargetTypeLLMChat,
		TargetTypeLLMAPI,
		TargetTypeRAG,
		TargetTypeAgent,
		TargetTypeEmbedding,
		TargetTypeMultimodal,
		TargetTypeCustom,
	}
}

// ParseTargetType parses a string into a TargetType, returning an error if invalid
func ParseTargetType(s string) (TargetType, error) {
	t := TargetType(s)
	if !t.IsValid() {
		return "", fmt.Errorf("invalid target type: %s", s)
	}
	return t, nil
}

// Provider represents the LLM service provider
type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderGoogle    Provider = "google"
	ProviderAzure     Provider = "azure"
	ProviderOllama    Provider = "ollama"
	ProviderCustom    Provider = "custom"
)

// String returns the string representation of Provider
func (p Provider) String() string {
	return string(p)
}

// IsValid checks if the Provider is a valid value
func (p Provider) IsValid() bool {
	switch p {
	case ProviderOpenAI, ProviderAnthropic, ProviderGoogle,
		ProviderAzure, ProviderOllama, ProviderCustom:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (p Provider) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(p))
}

// UnmarshalJSON implements json.Unmarshaler
func (p *Provider) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	provider := Provider(str)
	if !provider.IsValid() {
		return fmt.Errorf("invalid provider: %s", str)
	}

	*p = provider
	return nil
}

// AuthType represents the authentication method for a target
type AuthType string

const (
	AuthTypeNone   AuthType = "none"
	AuthTypeAPIKey AuthType = "api_key"
	AuthTypeBearer AuthType = "bearer"
	AuthTypeBasic  AuthType = "basic"
	AuthTypeOAuth  AuthType = "oauth"
)

// String returns the string representation of AuthType
func (a AuthType) String() string {
	return string(a)
}

// IsValid checks if the AuthType is a valid value
func (a AuthType) IsValid() bool {
	switch a {
	case AuthTypeNone, AuthTypeAPIKey, AuthTypeBearer, AuthTypeBasic, AuthTypeOAuth:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (a AuthType) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(a))
}

// UnmarshalJSON implements json.Unmarshaler
func (a *AuthType) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	authType := AuthType(str)
	if !authType.IsValid() {
		return fmt.Errorf("invalid auth type: %s", str)
	}

	*a = authType
	return nil
}

// Target represents a target LLM system to be tested
type Target struct {
	ID   ID     `json:"id"`
	Name string `json:"name"`
	// TenantID scopes the target to its owning tenant. Set server-side from the
	// caller's identity; never client-supplied and never exposed on the wire.
	// Reads/writes filter on it to enforce tenant isolation.
	TenantID     string                 `json:"tenant_id,omitempty"`
	Type         string                 `json:"type"` // Changed from TargetType enum to string for schema-based types
	Provider     Provider               `json:"provider,omitempty"`
	Connection   map[string]any         `json:"connection,omitempty"` // Schema-based connection parameters
	Model        string                 `json:"model,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
	Capabilities []string               `json:"capabilities,omitempty"`
	AuthType     AuthType               `json:"auth_type,omitempty"`
	CredentialID *ID                    `json:"credential_id,omitempty"` // Pointer for nullable FK
	Status       TargetStatus           `json:"status"`
	Description  string                 `json:"description,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	Timeout      int                    `json:"timeout"` // seconds
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`

	// URL is the target endpoint. New code should use Connection["url"] instead;
	// this field is read by mission_manager and attack/runner for backward compatibility.
	URL string `json:"url,omitempty"`
	// Headers provides default HTTP headers. New code should use Connection["headers"] instead;
	// this field is populated by NewTarget for backward compatibility with existing callers.
	Headers map[string]string `json:"headers,omitempty"`
}

// NewTarget creates a new Target with default values and sets both URL (for backward
// compatibility) and Connection["url"] (the preferred field for new code).
// New code should prefer NewTargetWithConnection for schema-based targets.
func NewTarget(name, url string, targetType TargetType) *Target {
	now := time.Now()
	return &Target{
		ID:           NewID(),
		Name:         name,
		Type:         string(targetType),
		URL:          url,
		Connection:   map[string]any{"url": url},
		Status:       TargetStatusActive,
		Headers:      make(map[string]string),
		Config:       make(map[string]interface{}),
		Capabilities: []string{},
		Tags:         []string{},
		Timeout:      30, // default 30 seconds
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// NewTargetWithConnection creates a new Target with schema-based connection parameters
// name: human-readable name for the target
// targetType: type of target system (http_api, kubernetes, smart_contract, etc.)
// connection: schema-based connection parameters
func NewTargetWithConnection(name, targetType string, connection map[string]any) *Target {
	now := time.Now()
	if connection == nil {
		connection = make(map[string]any)
	}
	return &Target{
		ID:           NewID(),
		Name:         name,
		Type:         targetType,
		Connection:   connection,
		Status:       TargetStatusActive,
		Config:       make(map[string]interface{}),
		Capabilities: []string{},
		Tags:         []string{},
		Timeout:      30, // default 30 seconds
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// GetURL returns the target URL for backward compatibility
// If Connection["url"] is set, it returns that value, otherwise falls back to the URL field
func (t *Target) GetURL() string {
	if t.Connection != nil {
		if url, ok := t.Connection["url"]; ok {
			if urlStr, ok := url.(string); ok {
				return urlStr
			}
		}
	}
	// Fall back to the URL field for backward compatibility with legacy targets.
	return t.URL
}

// Validate checks if the Target has all required fields and valid values
func (t *Target) Validate() error {
	// Validate ID
	if err := t.ID.Validate(); err != nil {
		return fmt.Errorf("invalid target ID: %w", err)
	}

	// Validate Name
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("target name cannot be empty")
	}

	// Validate Type (now string-based, no enum validation)
	if strings.TrimSpace(t.Type) == "" {
		return fmt.Errorf("target type cannot be empty")
	}

	// Validate URL/Connection: prefer Connection, fall back to the URL field for
	// backward compatibility. New targets should set Connection; legacy targets may have URL.
	hasConnection := t.Connection != nil && len(t.Connection) > 0
	hasURL := strings.TrimSpace(t.URL) != ""
	if !hasConnection && !hasURL {
		return fmt.Errorf("target must have either Connection parameters or URL")
	}

	// Validate Status
	if !t.Status.IsValid() {
		return fmt.Errorf("invalid target status: %s", t.Status)
	}

	// Validate Provider if set
	if t.Provider != "" && !t.Provider.IsValid() {
		return fmt.Errorf("invalid provider: %s", t.Provider)
	}

	// Validate AuthType if set
	if t.AuthType != "" && !t.AuthType.IsValid() {
		return fmt.Errorf("invalid auth type: %s", t.AuthType)
	}

	// Validate CredentialID if set
	if t.CredentialID != nil {
		if err := t.CredentialID.Validate(); err != nil {
			return fmt.Errorf("invalid credential ID: %w", err)
		}
	}

	// Validate Timeout
	if t.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	return nil
}

// HasCapability checks if the target has a specific capability.
func (t *Target) HasCapability(capability string) bool {
	if t.Capabilities == nil {
		return false
	}
	for _, cap := range t.Capabilities {
		if cap == capability {
			return true
		}
	}
	return false
}

// TargetFilter represents query filters for retrieving targets
type TargetFilter struct {
	Provider *Provider
	Type     *string // Changed from *TargetType to *string for schema-based types
	Status   *TargetStatus
	Tags     []string
	Limit    int
	Offset   int
}

// NewTargetFilter creates a new TargetFilter with default values
func NewTargetFilter() *TargetFilter {
	return &TargetFilter{
		Tags:   []string{},
		Limit:  100, // default limit
		Offset: 0,
	}
}

// WithProvider sets the Provider filter
func (f *TargetFilter) WithProvider(provider Provider) *TargetFilter {
	f.Provider = &provider
	return f
}

// WithType sets the Type filter
func (f *TargetFilter) WithType(targetType string) *TargetFilter {
	f.Type = &targetType
	return f
}

// WithStatus sets the Status filter
func (f *TargetFilter) WithStatus(status TargetStatus) *TargetFilter {
	f.Status = &status
	return f
}

// WithTags sets the Tags filter
func (f *TargetFilter) WithTags(tags []string) *TargetFilter {
	f.Tags = tags
	return f
}

// WithLimit sets the result limit
func (f *TargetFilter) WithLimit(limit int) *TargetFilter {
	f.Limit = limit
	return f
}

// WithOffset sets the result offset for pagination
func (f *TargetFilter) WithOffset(offset int) *TargetFilter {
	f.Offset = offset
	return f
}
