package types

import (
	"encoding/json"
	"fmt"
	"time"
)

// CredentialType represents the authentication mechanism type
type CredentialType string

const (
	CredentialTypeAPIKey CredentialType = "api_key"
	CredentialTypeBearer CredentialType = "bearer"
	CredentialTypeBasic  CredentialType = "basic"
	CredentialTypeOAuth  CredentialType = "oauth"
	CredentialTypeCustom CredentialType = "custom"
)

// String returns the string representation of CredentialType
func (t CredentialType) String() string {
	return string(t)
}

// IsValid checks if the CredentialType is a valid value
func (t CredentialType) IsValid() bool {
	switch t {
	case CredentialTypeAPIKey, CredentialTypeBearer, CredentialTypeBasic,
		CredentialTypeOAuth, CredentialTypeCustom:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (t CredentialType) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(t))
}

// UnmarshalJSON implements json.Unmarshaler
func (t *CredentialType) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	credType := CredentialType(str)
	if !credType.IsValid() {
		return fmt.Errorf("invalid credential type: %s", str)
	}

	*t = credType
	return nil
}

// CredentialRotation manages automatic credential rotation settings
type CredentialRotation struct {
	Enabled      bool       `json:"enabled"`
	AutoRotate   bool       `json:"auto_rotate"`
	Interval     string     `json:"interval,omitempty"`      // e.g., "30d", "90d"
	LastRotated  *time.Time `json:"last_rotated,omitempty"`  // When credential was last rotated
	NextRotation *time.Time `json:"next_rotation,omitempty"` // Scheduled next rotation time
}

// CredentialUsage tracks credential usage statistics and failures
type CredentialUsage struct {
	TotalUses    int64      `json:"total_uses"`             // Lifetime total uses
	Usage24h     int64      `json:"usage_24h"`              // Uses in last 24 hours
	Usage7d      int64      `json:"usage_7d"`               // Uses in last 7 days
	FailureCount int64      `json:"failure_count"`          // Total authentication failures
	LastFailure  *time.Time `json:"last_failure,omitempty"` // Timestamp of last failure
}

// Credential represents authentication credentials for external systems
// CRITICAL: Encrypted fields (EncryptedValue, EncryptionIV, KeyDerivationSalt)
// use json:"-" tags to prevent accidental serialization and exposure.
type Credential struct {
	ID          ID               `json:"id"`
	Name        string           `json:"name"`
	Type        CredentialType   `json:"type"`
	Provider    string           `json:"provider,omitempty"` // e.g., "openai", "anthropic", "aws"
	Status      CredentialStatus `json:"status"`
	Description string           `json:"description,omitempty"`

	// NEVER serialize these - encryption data
	// These fields contain sensitive encrypted data and MUST NOT be exposed in JSON
	EncryptedValue    []byte `json:"-"` // AES-256-GCM encrypted credential value
	EncryptionIV      []byte `json:"-"` // Initialization vector for AES-GCM
	KeyDerivationSalt []byte `json:"-"` // Salt for key derivation function

	Tags     []string           `json:"tags,omitempty"`
	Rotation CredentialRotation `json:"rotation"`
	Usage    CredentialUsage    `json:"usage"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"` // Last successful authentication
}

// NewCredential creates a new Credential with default values
func NewCredential(name string, credType CredentialType) *Credential {
	now := time.Now()
	return &Credential{
		ID:          NewID(),
		Name:        name,
		Type:        credType,
		Status:      CredentialStatusActive,
		Description: "",
		Provider:    "",
		Tags:        []string{},
		Rotation: CredentialRotation{
			Enabled:      false,
			AutoRotate:   false,
			Interval:     "",
			LastRotated:  nil,
			NextRotation: nil,
		},
		Usage: CredentialUsage{
			TotalUses:    0,
			Usage24h:     0,
			Usage7d:      0,
			FailureCount: 0,
			LastFailure:  nil,
		},
		CreatedAt: now,
		UpdatedAt: now,
		LastUsed:  nil,
	}
}

// Validate performs validation checks on the Credential
func (c *Credential) Validate() error {
	if err := c.ID.Validate(); err != nil {
		return fmt.Errorf("invalid credential ID: %w", err)
	}

	if c.Name == "" {
		return NewError(CREDENTIAL_INVALID, "credential name cannot be empty")
	}

	if !c.Type.IsValid() {
		return NewError(CREDENTIAL_INVALID, fmt.Sprintf("invalid credential type: %s", c.Type))
	}

	if !c.Status.IsValid() {
		return NewError(CREDENTIAL_INVALID, fmt.Sprintf("invalid credential status: %s", c.Status))
	}

	// Validate that encrypted fields are present
	// These should be set by the encryption layer before storage
	if len(c.EncryptedValue) == 0 {
		return NewError(CREDENTIAL_INVALID, "encrypted value cannot be empty - credential must be encrypted before storage")
	}

	if len(c.EncryptionIV) == 0 {
		return NewError(CREDENTIAL_INVALID, "encryption IV cannot be empty - credential must be encrypted before storage")
	}

	if len(c.KeyDerivationSalt) == 0 {
		return NewError(CREDENTIAL_INVALID, "key derivation salt cannot be empty - credential must be encrypted before storage")
	}

	return nil
}

// CredentialFilter provides filtering options for credential queries
type CredentialFilter struct {
	Provider *string           // Filter by provider (e.g., "openai")
	Type     *CredentialType   // Filter by credential type
	Status   *CredentialStatus // Filter by status
	Tags     []string          // Filter by tags (AND logic - credential must have all tags)
	Limit    int               // Maximum number of results (0 = no limit)
	Offset   int               // Number of results to skip for pagination
}
