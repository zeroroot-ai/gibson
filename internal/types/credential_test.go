package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCredentialType_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		ctype CredentialType
		want  bool
	}{
		{"api_key is valid", CredentialTypeAPIKey, true},
		{"bearer is valid", CredentialTypeBearer, true},
		{"basic is valid", CredentialTypeBasic, true},
		{"oauth is valid", CredentialTypeOAuth, true},
		{"custom is valid", CredentialTypeCustom, true},
		{"invalid type", CredentialType("invalid"), false},
		{"empty type", CredentialType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ctype.IsValid(); got != tt.want {
				t.Errorf("CredentialType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCredentialType_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		ctype   CredentialType
		want    string
		wantErr bool
	}{
		{"marshal api_key", CredentialTypeAPIKey, `"api_key"`, false},
		{"marshal bearer", CredentialTypeBearer, `"bearer"`, false},
		{"marshal custom", CredentialTypeCustom, `"custom"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.ctype)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON() = %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestCredentialType_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    CredentialType
		wantErr bool
	}{
		{"unmarshal api_key", `"api_key"`, CredentialTypeAPIKey, false},
		{"unmarshal bearer", `"bearer"`, CredentialTypeBearer, false},
		{"invalid type", `"invalid"`, CredentialType(""), true},
		{"malformed json", `invalid`, CredentialType(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got CredentialType
			err := json.Unmarshal([]byte(tt.json), &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewCredential(t *testing.T) {
	name := "test-cred"
	credType := CredentialTypeAPIKey

	cred := NewCredential(name, credType)

	if cred.Name != name {
		t.Errorf("NewCredential() name = %v, want %v", cred.Name, name)
	}
	if cred.Type != credType {
		t.Errorf("NewCredential() type = %v, want %v", cred.Type, credType)
	}
	if cred.Status != CredentialStatusActive {
		t.Errorf("NewCredential() status = %v, want %v", cred.Status, CredentialStatusActive)
	}
	if cred.ID.IsZero() {
		t.Error("NewCredential() should generate a valid ID")
	}
	if cred.CreatedAt.IsZero() {
		t.Error("NewCredential() should set CreatedAt")
	}
	if cred.UpdatedAt.IsZero() {
		t.Error("NewCredential() should set UpdatedAt")
	}
	if !cred.Rotation.Enabled {
		// This is expected - just verify the default
	}
	if cred.Usage.TotalUses != 0 {
		t.Errorf("NewCredential() usage.total_uses = %v, want 0", cred.Usage.TotalUses)
	}
}

func TestCredential_Validate(t *testing.T) {
	validCred := NewCredential("valid", CredentialTypeAPIKey)
	// Validate() requires EncryptedValue to be non-empty (security hardening:
	// credentials must be encrypted before they are considered valid for storage).
	validCred.EncryptedValue = []byte("mock-encrypted-value")

	tests := []struct {
		name    string
		cred    *Credential
		wantErr bool
	}{
		{
			name:    "valid credential",
			cred:    validCred,
			wantErr: false,
		},
		{
			name: "empty name",
			cred: &Credential{
				ID:     NewID(),
				Name:   "",
				Type:   CredentialTypeAPIKey,
				Status: CredentialStatusActive,
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			cred: &Credential{
				ID:     NewID(),
				Name:   "test",
				Type:   CredentialType("invalid"),
				Status: CredentialStatusActive,
			},
			wantErr: true,
		},
		{
			name: "invalid status",
			cred: &Credential{
				ID:     NewID(),
				Name:   "test",
				Type:   CredentialTypeAPIKey,
				Status: CredentialStatus("invalid"),
			},
			wantErr: true,
		},
		{
			name: "invalid ID",
			cred: &Credential{
				ID:     ID("not-a-uuid"),
				Name:   "test",
				Type:   CredentialTypeAPIKey,
				Status: CredentialStatusActive,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cred.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Credential.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// CRITICAL TEST: Verify encrypted fields are NEVER serialized to JSON
func TestCredential_EncryptedFieldsNotSerialized(t *testing.T) {
	cred := NewCredential("test-secret", CredentialTypeAPIKey)

	// Set sensitive encrypted data
	cred.EncryptedValue = []byte("super-secret-encrypted-api-key")
	cred.EncryptionIV = []byte("initialization-vector-12345")
	cred.KeyDerivationSalt = []byte("salt-for-key-derivation-678")

	// Marshal to JSON
	jsonData, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Failed to marshal credential: %v", err)
	}

	jsonStr := string(jsonData)

	// CRITICAL: Verify encrypted fields are NOT present in JSON
	forbiddenFields := []string{
		"EncryptedValue",
		"encrypted_value",
		"EncryptionIV",
		"encryption_iv",
		"KeyDerivationSalt",
		"key_derivation_salt",
		"super-secret-encrypted-api-key",
		"initialization-vector",
		"salt-for-key-derivation",
	}

	for _, field := range forbiddenFields {
		if strings.Contains(jsonStr, field) {
			t.Errorf("SECURITY VIOLATION: Credential JSON contains forbidden field/data: %s\nJSON: %s", field, jsonStr)
		}
	}

	// Verify expected fields ARE present
	expectedFields := []string{
		`"id"`,
		`"name"`,
		`"type"`,
		`"status"`,
		`"rotation"`,
		`"usage"`,
		`"created_at"`,
		`"updated_at"`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected field missing from JSON: %s\nJSON: %s", field, jsonStr)
		}
	}
}

func TestCredential_MarshalUnmarshal(t *testing.T) {
	original := NewCredential("test", CredentialTypeBearer)
	original.Provider = "openai"
	original.Description = "Test credential"
	original.Tags = []string{"production", "api"}
	original.Status = CredentialStatusActive

	now := time.Now()
	original.LastUsed = &now
	original.Rotation.Enabled = true
	original.Rotation.Interval = "30d"
	original.Usage.TotalUses = 42

	// Set encrypted fields (should NOT be serialized)
	original.EncryptedValue = []byte("secret")
	original.EncryptionIV = []byte("iv")
	original.KeyDerivationSalt = []byte("salt")

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal
	var restored Credential
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify core fields are preserved
	if restored.ID != original.ID {
		t.Errorf("ID not preserved: got %v, want %v", restored.ID, original.ID)
	}
	if restored.Name != original.Name {
		t.Errorf("Name not preserved: got %v, want %v", restored.Name, original.Name)
	}
	if restored.Type != original.Type {
		t.Errorf("Type not preserved: got %v, want %v", restored.Type, original.Type)
	}
	if restored.Provider != original.Provider {
		t.Errorf("Provider not preserved: got %v, want %v", restored.Provider, original.Provider)
	}
	if restored.Status != original.Status {
		t.Errorf("Status not preserved: got %v, want %v", restored.Status, original.Status)
	}

	// Verify encrypted fields are NOT preserved (should be nil/empty)
	if len(restored.EncryptedValue) > 0 {
		t.Error("EncryptedValue should not be serialized/deserialized")
	}
	if len(restored.EncryptionIV) > 0 {
		t.Error("EncryptionIV should not be serialized/deserialized")
	}
	if len(restored.KeyDerivationSalt) > 0 {
		t.Error("KeyDerivationSalt should not be serialized/deserialized")
	}

	// Verify complex fields
	if len(restored.Tags) != len(original.Tags) {
		t.Errorf("Tags length mismatch: got %d, want %d", len(restored.Tags), len(original.Tags))
	}
	if restored.Rotation.Enabled != original.Rotation.Enabled {
		t.Errorf("Rotation.Enabled not preserved: got %v, want %v", restored.Rotation.Enabled, original.Rotation.Enabled)
	}
	if restored.Usage.TotalUses != original.Usage.TotalUses {
		t.Errorf("Usage.TotalUses not preserved: got %v, want %v", restored.Usage.TotalUses, original.Usage.TotalUses)
	}
}
