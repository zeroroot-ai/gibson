package vector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestQdrantConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  QdrantConfig
		wantErr bool
		errCode types.ErrorCode
		errMsg  string
	}{
		{
			name: "valid config",
			config: QdrantConfig{
				Host:       "localhost",
				Port:       6334,
				Collection: "test_collection",
				APIKey:     "",
				UseTLS:     false,
			},
			wantErr: false,
		},
		{
			name: "valid config with TLS and API key",
			config: QdrantConfig{
				Host:       "qdrant.example.com",
				Port:       6334,
				Collection: "vectors",
				APIKey:     "test-api-key",
				UseTLS:     true,
			},
			wantErr: false,
		},
		{
			name: "empty host",
			config: QdrantConfig{
				Host:       "",
				Port:       6334,
				Collection: "test_collection",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "qdrant host cannot be empty",
		},
		{
			name: "port too low",
			config: QdrantConfig{
				Host:       "localhost",
				Port:       0,
				Collection: "test_collection",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "qdrant port must be between 1 and 65535",
		},
		{
			name: "port too high",
			config: QdrantConfig{
				Host:       "localhost",
				Port:       65536,
				Collection: "test_collection",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "qdrant port must be between 1 and 65535",
		},
		{
			name: "negative port",
			config: QdrantConfig{
				Host:       "localhost",
				Port:       -1,
				Collection: "test_collection",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "qdrant port must be between 1 and 65535",
		},
		{
			name: "empty collection",
			config: QdrantConfig{
				Host:       "localhost",
				Port:       6334,
				Collection: "",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "qdrant collection name cannot be empty",
		},
		{
			name: "valid with minimum port",
			config: QdrantConfig{
				Host:       "localhost",
				Port:       1,
				Collection: "test_collection",
			},
			wantErr: false,
		},
		{
			name: "valid with maximum port",
			config: QdrantConfig{
				Host:       "localhost",
				Port:       65535,
				Collection: "test_collection",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				var gibsonErr *types.GibsonError
				require.ErrorAs(t, err, &gibsonErr)
				assert.Equal(t, tt.errCode, gibsonErr.Code)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestQdrantConfig_Defaults(t *testing.T) {
	cfg := DefaultQdrantConfig()

	// Verify all default values
	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, 6334, cfg.Port)
	assert.Equal(t, "gibson_vectors", cfg.Collection)
	assert.Equal(t, "", cfg.APIKey)
	assert.Equal(t, false, cfg.UseTLS)

	// Verify the default config is valid
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestQdrantConfig_DefaultsAreValid(t *testing.T) {
	// Ensure that the default configuration passes validation
	cfg := DefaultQdrantConfig()
	err := cfg.Validate()
	require.NoError(t, err, "default Qdrant config should be valid")
}
