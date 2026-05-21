package types

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIDIntegration tests ID generation, parsing, and JSON round-trip
func TestIDIntegration(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() ID
		wantErr bool
	}{
		{
			name: "new ID generates valid UUID",
			setup: func() ID {
				return NewID()
			},
			wantErr: false,
		},
		{
			name: "parse valid UUID string",
			setup: func() ID {
				id := NewID()
				parsed, err := ParseID(id.String())
				require.NoError(t, err)
				return parsed
			},
			wantErr: false,
		},
		{
			name: "empty ID fails validation",
			setup: func() ID {
				return ID("")
			},
			wantErr: true,
		},
		{
			name: "invalid UUID fails validation",
			setup: func() ID {
				return ID("not-a-uuid")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := tt.setup()
			err := id.Validate()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.False(t, id.IsZero())

			// Test JSON round-trip
			jsonData, err := json.Marshal(id)
			require.NoError(t, err)

			var decoded ID
			err = json.Unmarshal(jsonData, &decoded)
			require.NoError(t, err)
			assert.Equal(t, id, decoded)
		})
	}
}

// TestStatusEnumIntegration tests all status enum types for validation and serialization
func TestStatusEnumIntegration(t *testing.T) {
	tests := []struct {
		name        string
		statusType  string
		validValues []interface{}
		invalidVal  string
	}{
		{
			name:       "TargetStatus",
			statusType: "target",
			validValues: []interface{}{
				TargetStatusActive,
				TargetStatusInactive,
				TargetStatusError,
			},
			invalidVal: "unknown_status",
		},
		{
			name:       "CredentialStatus",
			statusType: "credential",
			validValues: []interface{}{
				CredentialStatusActive,
				CredentialStatusInactive,
				CredentialStatusExpired,
				CredentialStatusRevoked,
				CredentialStatusRotating,
			},
			invalidVal: "invalid_credential_status",
		},
		{
			name:       "MissionStatus",
			statusType: "mission",
			validValues: []interface{}{
				MissionStatusPending,
				MissionStatusRunning,
				MissionStatusCompleted,
				MissionStatusFailed,
				MissionStatusCancelled,
			},
			invalidVal: "bad_mission_status",
		},
		{
			name:       "FindingStatus",
			statusType: "finding",
			validValues: []interface{}{
				FindingStatusOpen,
				FindingStatusConfirmed,
				FindingStatusFixed,
				FindingStatusFalsePositive,
				FindingStatusWontFix,
			},
			invalidVal: "wrong_finding_status",
		},
		{
			name:       "HealthState",
			statusType: "health",
			validValues: []interface{}{
				HealthStateHealthy,
				HealthStateDegraded,
				HealthStateUnhealthy,
			},
			invalidVal: "invalid_health_state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test valid values
			for _, val := range tt.validValues {
				// Test JSON marshaling and unmarshaling
				jsonData, err := json.Marshal(val)
				require.NoError(t, err)

				// Decode based on type
				switch tt.statusType {
				case "target":
					var decoded TargetStatus
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())
					assert.Equal(t, val, decoded)

				case "credential":
					var decoded CredentialStatus
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())
					assert.Equal(t, val, decoded)

				case "mission":
					var decoded MissionStatus
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())
					assert.Equal(t, val, decoded)

				case "finding":
					var decoded FindingStatus
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())
					assert.Equal(t, val, decoded)

				case "health":
					var decoded HealthState
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())
					assert.Equal(t, val, decoded)
				}
			}

			// Test invalid value
			invalidJSON := `"` + tt.invalidVal + `"`
			switch tt.statusType {
			case "target":
				var decoded TargetStatus
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)

			case "credential":
				var decoded CredentialStatus
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)

			case "mission":
				var decoded MissionStatus
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)

			case "finding":
				var decoded FindingStatus
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)

			case "health":
				var decoded HealthState
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)
			}
		})
	}
}

// TestGibsonErrorIntegration tests error wrapping and Is() matching
func TestGibsonErrorIntegration(t *testing.T) {
	tests := []struct {
		name     string
		setupErr func() error
		checkErr func(t *testing.T, err error)
	}{
		{
			name: "simple error creation",
			setupErr: func() error {
				return NewError(CONFIG_LOAD_FAILED, "failed to load config")
			},
			checkErr: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "CONFIG_LOAD_FAILED")
				assert.Contains(t, err.Error(), "failed to load config")

				var gibsonErr *GibsonError
				assert.True(t, errors.As(err, &gibsonErr))
				assert.Equal(t, CONFIG_LOAD_FAILED, gibsonErr.Code)
				assert.False(t, gibsonErr.Retryable)
			},
		},
		{
			name: "retryable error",
			setupErr: func() error {
				return NewRetryableError(DB_CONNECTION_LOST, "connection timeout")
			},
			checkErr: func(t *testing.T, err error) {
				var gibsonErr *GibsonError
				require.True(t, errors.As(err, &gibsonErr))
				assert.True(t, gibsonErr.Retryable)
				assert.Equal(t, DB_CONNECTION_LOST, gibsonErr.Code)
			},
		},
		{
			name: "wrapped error chain",
			setupErr: func() error {
				original := errors.New("file not found")
				wrapped := WrapError(CONFIG_LOAD_FAILED, "cannot load config", original)
				return wrapped
			},
			checkErr: func(t *testing.T, err error) {
				// Check error message contains both
				assert.Contains(t, err.Error(), "CONFIG_LOAD_FAILED")
				assert.Contains(t, err.Error(), "cannot load config")
				assert.Contains(t, err.Error(), "file not found")

				// Test unwrapping
				var gibsonErr *GibsonError
				assert.True(t, errors.As(err, &gibsonErr))
				assert.NotNil(t, gibsonErr.Unwrap())

				// Verify the cause is accessible
				cause := gibsonErr.Unwrap()
				assert.Contains(t, cause.Error(), "file not found")
			},
		},
		{
			name: "error Is() matching by code",
			setupErr: func() error {
				err1 := NewError(TARGET_NOT_FOUND, "target A not found")
				err2 := NewError(TARGET_NOT_FOUND, "target B not found")
				// err1.Is(err2) should return true because same code
				if !err1.Is(err2) {
					t.Error("Expected err1.Is(err2) to be true")
				}
				return err1
			},
			checkErr: func(t *testing.T, err error) {
				var gibsonErr *GibsonError
				require.True(t, errors.As(err, &gibsonErr))
				assert.Equal(t, TARGET_NOT_FOUND, gibsonErr.Code)
			},
		},
		{
			name: "different error codes don't match",
			setupErr: func() error {
				err1 := NewError(TARGET_NOT_FOUND, "target not found")
				err2 := NewError(CREDENTIAL_NOT_FOUND, "credential not found")
				// err1.Is(err2) should return false
				if err1.Is(err2) {
					t.Error("Expected err1.Is(err2) to be false")
				}
				return err1
			},
			checkErr: func(t *testing.T, err error) {
				assert.NoError(t, nil) // Just verify setup ran
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.setupErr()
			tt.checkErr(t, err)
		})
	}
}

// TestTargetEntityIntegration tests Target entity JSON serialization and validation
func TestTargetEntityIntegration(t *testing.T) {
	tests := []struct {
		name        string
		setupTarget func() *Target
		wantErr     bool
		validate    func(t *testing.T, target *Target)
	}{
		{
			name: "valid target with all fields",
			setupTarget: func() *Target {
				target := NewTarget("Test LLM", "https://api.example.com/v1", TargetTypeLLMAPI)
				target.Provider = ProviderOpenAI
				target.Model = "gpt-4"
				target.AuthType = AuthTypeAPIKey
				credID := NewID()
				target.CredentialID = &credID
				target.Description = "Test target for integration"
				target.Tags = []string{"test", "integration"}
				target.Headers = map[string]string{"X-Custom": "value"}
				target.Config = map[string]interface{}{"temperature": 0.7}
				return target
			},
			wantErr: false,
			validate: func(t *testing.T, target *Target) {
				assert.Equal(t, "Test LLM", target.Name)
				assert.Equal(t, string(TargetTypeLLMAPI), target.Type)
				assert.Equal(t, ProviderOpenAI, target.Provider)
				assert.Equal(t, "gpt-4", target.Model)
				assert.NotNil(t, target.CredentialID)
				assert.Len(t, target.Tags, 2)
			},
		},
		{
			name: "target with empty name fails validation",
			setupTarget: func() *Target {
				target := NewTarget("", "https://api.example.com", TargetTypeLLMChat)
				return target
			},
			wantErr: true,
			validate: func(t *testing.T, target *Target) {
				err := target.Validate()
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "name cannot be empty")
			},
		},
		{
			name: "target with empty URL and no Connection fails validation",
			setupTarget: func() *Target {
				// Create target without URL and without Connection
				target := &Target{
					ID:      NewID(),
					Name:    "Valid Name",
					URL:     "",
					Type:    string(TargetTypeLLMChat),
					Status:  TargetStatusActive,
					Timeout: 30,
				}
				return target
			},
			wantErr: true,
			validate: func(t *testing.T, target *Target) {
				err := target.Validate()
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Connection")
			},
		},
		{
			name: "target with Connection but no URL is valid",
			setupTarget: func() *Target {
				// New schema-based targets use Connection map instead of URL
				target := NewTargetWithConnection("Valid", string(TargetTypeLLMChat), map[string]any{
					"url": "https://api.example.com",
				})
				return target
			},
			wantErr: false,
			validate: func(t *testing.T, target *Target) {
				err := target.Validate()
				assert.NoError(t, err)
				assert.Equal(t, "https://api.example.com", target.GetURL())
			},
		},
		{
			name: "target JSON round-trip",
			setupTarget: func() *Target {
				return NewTarget("API Target", "https://api.test.com", TargetTypeRAG)
			},
			wantErr: false,
			validate: func(t *testing.T, target *Target) {
				// Marshal to JSON
				jsonData, err := json.Marshal(target)
				require.NoError(t, err)

				// Unmarshal back
				var decoded Target
				err = json.Unmarshal(jsonData, &decoded)
				require.NoError(t, err)

				assert.Equal(t, target.ID, decoded.ID)
				assert.Equal(t, target.Name, decoded.Name)
				assert.Equal(t, target.Type, decoded.Type)
				assert.Equal(t, target.URL, decoded.URL)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.setupTarget()

			if tt.wantErr {
				err := target.Validate()
				assert.Error(t, err)
			} else {
				err := target.Validate()
				assert.NoError(t, err)
			}

			tt.validate(t, target)
		})
	}
}

// TestCredentialEntityIntegration tests Credential entity JSON serialization
// CRITICAL: This test verifies encrypted fields never appear in JSON output
func TestCredentialEntityIntegration(t *testing.T) {
	tests := []struct {
		name           string
		setupCred      func() *Credential
		wantErr        bool
		jsonValidation func(t *testing.T, jsonData []byte)
	}{
		{
			name: "valid credential with all fields",
			setupCred: func() *Credential {
				cred := NewCredential("Test API Key", CredentialTypeAPIKey)
				cred.Provider = "openai"
				cred.Description = "Test credential"
				cred.Tags = []string{"test"}
				// Validate() requires EncryptedValue (credentials must be encrypted
				// before storage; set a stub to satisfy the invariant).
				cred.EncryptedValue = []byte("mock-encrypted-value")
				return cred
			},
			wantErr: false,
			jsonValidation: func(t *testing.T, jsonData []byte) {
				// Verify normal fields are present
				assert.Contains(t, string(jsonData), `"name":"Test API Key"`)
				assert.Contains(t, string(jsonData), `"type":"api_key"`)
				assert.Contains(t, string(jsonData), `"provider":"openai"`)

				// CRITICAL: Verify encrypted fields are NOT present
				assert.NotContains(t, string(jsonData), "encrypted_value")
				assert.NotContains(t, string(jsonData), "encryption_iv")
				assert.NotContains(t, string(jsonData), "key_derivation_salt")
			},
		},
		{
			name: "credential with encrypted data never serializes sensitive fields",
			setupCred: func() *Credential {
				cred := NewCredential("Secret Key", CredentialTypeBearer)
				// Simulate encrypted data
				cred.EncryptedValue = []byte("SUPER_SECRET_ENCRYPTED_DATA")
				cred.EncryptionIV = []byte("RANDOM_IV_DATA")
				cred.KeyDerivationSalt = []byte("SALT_DATA")
				return cred
			},
			wantErr: false,
			jsonValidation: func(t *testing.T, jsonData []byte) {
				jsonStr := string(jsonData)

				// CRITICAL SECURITY TEST: Ensure NO encrypted data leaks
				assert.NotContains(t, jsonStr, "SUPER_SECRET_ENCRYPTED_DATA")
				assert.NotContains(t, jsonStr, "RANDOM_IV_DATA")
				assert.NotContains(t, jsonStr, "SALT_DATA")
				assert.NotContains(t, jsonStr, "encrypted_value")
				assert.NotContains(t, jsonStr, "encryption_iv")
				assert.NotContains(t, jsonStr, "key_derivation_salt")

				// Verify we can still unmarshal
				var decoded Credential
				err := json.Unmarshal(jsonData, &decoded)
				require.NoError(t, err)

				// Encrypted fields should be nil/empty after unmarshal
				assert.Nil(t, decoded.EncryptedValue)
				assert.Nil(t, decoded.EncryptionIV)
				assert.Nil(t, decoded.KeyDerivationSalt)
			},
		},
		{
			name: "credential with empty name fails validation",
			setupCred: func() *Credential {
				cred := NewCredential("", CredentialTypeAPIKey)
				return cred
			},
			wantErr: true,
			jsonValidation: func(t *testing.T, jsonData []byte) {
				// Still verify no encrypted data in JSON even on invalid cred
				assert.NotContains(t, string(jsonData), "encrypted_value")
				assert.NotContains(t, string(jsonData), "encryption_iv")
				assert.NotContains(t, string(jsonData), "key_derivation_salt")
			},
		},
		{
			name: "credential with invalid type fails validation",
			setupCred: func() *Credential {
				cred := NewCredential("Valid Name", "invalid_type")
				return cred
			},
			wantErr: true,
			jsonValidation: func(t *testing.T, jsonData []byte) {
				// Security check even on invalid credentials
				assert.NotContains(t, string(jsonData), "encrypted_value")
			},
		},
		{
			name: "credential usage and rotation serialize correctly",
			setupCred: func() *Credential {
				cred := NewCredential("Tracked Cred", CredentialTypeOAuth)
				cred.Usage.TotalUses = 100
				cred.Usage.Usage24h = 10
				cred.Usage.Usage7d = 50
				cred.Rotation.Enabled = true
				cred.Rotation.AutoRotate = true
				cred.Rotation.Interval = "90d"
				// Validate() requires EncryptedValue.
				cred.EncryptedValue = []byte("mock-encrypted-value")
				return cred
			},
			wantErr: false,
			jsonValidation: func(t *testing.T, jsonData []byte) {
				assert.Contains(t, string(jsonData), `"total_uses":100`)
				assert.Contains(t, string(jsonData), `"usage_24h":10`)
				assert.Contains(t, string(jsonData), `"enabled":true`)
				assert.Contains(t, string(jsonData), `"auto_rotate":true`)
				assert.Contains(t, string(jsonData), `"interval":"90d"`)

				// Still verify no encrypted data
				assert.NotContains(t, string(jsonData), "encrypted_value")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := tt.setupCred()

			// Test validation
			err := cred.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Marshal to JSON
			jsonData, err := json.Marshal(cred)
			require.NoError(t, err)

			// Run JSON validation checks
			tt.jsonValidation(t, jsonData)
		})
	}
}

// TestHealthStatusIntegration tests HealthStatus creation and state checking
func TestHealthStatusIntegration(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() HealthStatus
		validate  func(t *testing.T, status HealthStatus)
	}{
		{
			name: "healthy status",
			setupFunc: func() HealthStatus {
				return Healthy("All systems operational")
			},
			validate: func(t *testing.T, status HealthStatus) {
				assert.True(t, status.IsHealthy())
				assert.False(t, status.IsDegraded())
				assert.False(t, status.IsUnhealthy())
				assert.Equal(t, "All systems operational", status.Message)
				assert.Equal(t, HealthStateHealthy, status.State)
			},
		},
		{
			name: "degraded status",
			setupFunc: func() HealthStatus {
				return Degraded("Some services slow")
			},
			validate: func(t *testing.T, status HealthStatus) {
				assert.False(t, status.IsHealthy())
				assert.True(t, status.IsDegraded())
				assert.False(t, status.IsUnhealthy())
				assert.Equal(t, "Some services slow", status.Message)
			},
		},
		{
			name: "unhealthy status",
			setupFunc: func() HealthStatus {
				return Unhealthy("Database connection failed")
			},
			validate: func(t *testing.T, status HealthStatus) {
				assert.False(t, status.IsHealthy())
				assert.False(t, status.IsDegraded())
				assert.True(t, status.IsUnhealthy())
				assert.Equal(t, "Database connection failed", status.Message)
			},
		},
		{
			name: "health status JSON round-trip",
			setupFunc: func() HealthStatus {
				return NewHealthStatus(HealthStateDegraded, "Performance degraded")
			},
			validate: func(t *testing.T, status HealthStatus) {
				jsonData, err := json.Marshal(status)
				require.NoError(t, err)

				var decoded HealthStatus
				err = json.Unmarshal(jsonData, &decoded)
				require.NoError(t, err)

				assert.Equal(t, status.State, decoded.State)
				assert.Equal(t, status.Message, decoded.Message)
				// Time comparison with small delta for test execution time
				assert.WithinDuration(t, status.CheckedAt, decoded.CheckedAt, time.Second)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.setupFunc()
			tt.validate(t, status)
		})
	}
}

// TestCrossTypeIntegration tests interactions between different types
func TestCrossTypeIntegration(t *testing.T) {
	t.Run("Target with Credential relationship", func(t *testing.T) {
		// Create credential
		cred := NewCredential("OpenAI Key", CredentialTypeAPIKey)
		cred.Provider = "openai"
		// Validate() requires EncryptedValue.
		cred.EncryptedValue = []byte("mock-encrypted-value")
		require.NoError(t, cred.Validate())

		// Create target referencing credential
		target := NewTarget("OpenAI GPT-4", "https://api.openai.com/v1", TargetTypeLLMAPI)
		target.CredentialID = &cred.ID
		target.Provider = ProviderOpenAI
		target.AuthType = AuthTypeAPIKey
		require.NoError(t, target.Validate())

		// Verify relationship
		assert.Equal(t, cred.ID, *target.CredentialID)

		// JSON round-trip preserves relationship
		jsonData, err := json.Marshal(target)
		require.NoError(t, err)

		var decoded Target
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(t, err)

		assert.NotNil(t, decoded.CredentialID)
		assert.Equal(t, cred.ID, *decoded.CredentialID)
	})

	t.Run("Error handling with entity validation", func(t *testing.T) {
		// Invalid target triggers error
		target := NewTarget("", "", "bad_type")
		err := target.Validate()
		require.Error(t, err)

		// Wrap in GibsonError
		gibsonErr := WrapError(TARGET_INVALID, "target validation failed", err)

		// Verify error chain
		assert.Contains(t, gibsonErr.Error(), "TARGET_INVALID")
		assert.Contains(t, gibsonErr.Error(), "target validation failed")

		var ge *GibsonError
		assert.True(t, errors.As(gibsonErr, &ge))
		assert.Equal(t, TARGET_INVALID, ge.Code)
	})

	t.Run("Multiple entity JSON serialization", func(t *testing.T) {
		// Create multiple entities
		entities := struct {
			Target     *Target      `json:"target"`
			Credential *Credential  `json:"credential"`
			Health     HealthStatus `json:"health"`
			Error      *GibsonError `json:"error,omitempty"`
		}{
			Target:     NewTarget("Test", "https://test.com", TargetTypeLLMChat),
			Credential: NewCredential("Test Key", CredentialTypeAPIKey),
			Health:     Healthy("System ready"),
			Error:      nil,
		}

		// Marshal all together
		jsonData, err := json.Marshal(entities)
		require.NoError(t, err)

		// Verify structure
		assert.Contains(t, string(jsonData), `"target"`)
		assert.Contains(t, string(jsonData), `"credential"`)
		assert.Contains(t, string(jsonData), `"health"`)

		// CRITICAL: Verify no encrypted data leak
		assert.NotContains(t, string(jsonData), "encrypted_value")
		assert.NotContains(t, string(jsonData), "encryption_iv")
		assert.NotContains(t, string(jsonData), "key_derivation_salt")

		// Verify unmarshal
		var decoded struct {
			Target     *Target      `json:"target"`
			Credential *Credential  `json:"credential"`
			Health     HealthStatus `json:"health"`
		}
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(t, err)

		assert.Equal(t, entities.Target.ID, decoded.Target.ID)
		assert.Equal(t, entities.Credential.ID, decoded.Credential.ID)
		assert.Equal(t, entities.Health.State, decoded.Health.State)
	})
}

// TestEnumTypeIntegration tests TargetType, Provider, AuthType enums
func TestEnumTypeIntegration(t *testing.T) {
	tests := []struct {
		name       string
		enumType   string
		validVals  []interface{}
		invalidVal string
	}{
		{
			name:     "TargetType",
			enumType: "target_type",
			validVals: []interface{}{
				TargetTypeLLMChat,
				TargetTypeLLMAPI,
				TargetTypeRAG,
				TargetTypeAgent,
				TargetTypeEmbedding,
				TargetTypeMultimodal,
			},
			invalidVal: "invalid_target_type",
		},
		{
			name:     "Provider",
			enumType: "provider",
			validVals: []interface{}{
				ProviderOpenAI,
				ProviderAnthropic,
				ProviderGoogle,
				ProviderAzure,
				ProviderOllama,
				ProviderCustom,
			},
			invalidVal: "unknown_provider",
		},
		{
			name:     "AuthType",
			enumType: "auth_type",
			validVals: []interface{}{
				AuthTypeNone,
				AuthTypeAPIKey,
				AuthTypeBearer,
				AuthTypeBasic,
				AuthTypeOAuth,
			},
			invalidVal: "bad_auth",
		},
		{
			name:     "CredentialType",
			enumType: "credential_type",
			validVals: []interface{}{
				CredentialTypeAPIKey,
				CredentialTypeBearer,
				CredentialTypeBasic,
				CredentialTypeOAuth,
				CredentialTypeCustom,
			},
			invalidVal: "wrong_cred_type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, val := range tt.validVals {
				// Marshal
				jsonData, err := json.Marshal(val)
				require.NoError(t, err)

				// Unmarshal based on type
				switch tt.enumType {
				case "target_type":
					var decoded TargetType
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())

				case "provider":
					var decoded Provider
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())

				case "auth_type":
					var decoded AuthType
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())

				case "credential_type":
					var decoded CredentialType
					err = json.Unmarshal(jsonData, &decoded)
					require.NoError(t, err)
					assert.True(t, decoded.IsValid())
				}
			}

			// Test invalid value
			invalidJSON := `"` + tt.invalidVal + `"`
			switch tt.enumType {
			case "target_type":
				var decoded TargetType
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)

			case "provider":
				var decoded Provider
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)

			case "auth_type":
				var decoded AuthType
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)

			case "credential_type":
				var decoded CredentialType
				err := json.Unmarshal([]byte(invalidJSON), &decoded)
				assert.Error(t, err)
			}
		})
	}
}

// TestEdgeCases tests edge cases and corner scenarios
func TestEdgeCases(t *testing.T) {
	t.Run("nil credential ID in target", func(t *testing.T) {
		target := NewTarget("Test", "https://test.com", TargetTypeLLMChat)
		target.CredentialID = nil
		assert.NoError(t, target.Validate()) // nil credential is valid

		jsonData, err := json.Marshal(target)
		require.NoError(t, err)

		var decoded Target
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(t, err)
		assert.Nil(t, decoded.CredentialID)
	})

	t.Run("empty maps and slices", func(t *testing.T) {
		target := NewTarget("Test", "https://test.com", TargetTypeAgent)
		assert.NotNil(t, target.Headers)
		assert.NotNil(t, target.Config)
		assert.NotNil(t, target.Tags)
		assert.Len(t, target.Headers, 0)
		assert.Len(t, target.Config, 0)
		assert.Len(t, target.Tags, 0)
	})

	t.Run("nil time pointers", func(t *testing.T) {
		cred := NewCredential("Test", CredentialTypeAPIKey)
		assert.Nil(t, cred.LastUsed)
		assert.Nil(t, cred.Rotation.LastRotated)
		assert.Nil(t, cred.Rotation.NextRotation)
		assert.Nil(t, cred.Usage.LastFailure)

		jsonData, err := json.Marshal(cred)
		require.NoError(t, err)

		var decoded Credential
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(t, err)
		assert.Nil(t, decoded.LastUsed)
	})

	t.Run("zero-value ID marshals to null", func(t *testing.T) {
		var id ID
		jsonData, err := json.Marshal(id)
		require.NoError(t, err)
		assert.Equal(t, "null", string(jsonData))
	})

	t.Run("timeout validation", func(t *testing.T) {
		target := NewTarget("Test", "https://test.com", TargetTypeLLMAPI)
		target.Timeout = 0
		err := target.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timeout must be greater than 0")

		target.Timeout = -1
		err = target.Validate()
		assert.Error(t, err)

		target.Timeout = 30
		err = target.Validate()
		assert.NoError(t, err)
	})
}
