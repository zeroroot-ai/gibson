package vector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestMilvusConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  MilvusConfig
		wantErr bool
		errCode types.ErrorCode
		errMsg  string
	}{
		{
			name: "valid config",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       19530,
				Collection: "test_collection",
				Username:   "",
				Password:   "",
			},
			wantErr: false,
		},
		{
			name: "valid config with authentication",
			config: MilvusConfig{
				Host:       "milvus.example.com",
				Port:       19530,
				Collection: "vectors",
				Username:   "admin",
				Password:   "password123",
			},
			wantErr: false,
		},
		{
			name: "empty host",
			config: MilvusConfig{
				Host:       "",
				Port:       19530,
				Collection: "test_collection",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "milvus host cannot be empty",
		},
		{
			name: "port too low",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       0,
				Collection: "test_collection",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "milvus port must be between 1 and 65535",
		},
		{
			name: "port too high",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       65536,
				Collection: "test_collection",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "milvus port must be between 1 and 65535",
		},
		{
			name: "negative port",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       -1,
				Collection: "test_collection",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "milvus port must be between 1 and 65535",
		},
		{
			name: "empty collection",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       19530,
				Collection: "",
			},
			wantErr: true,
			errCode: ErrCodeInvalidConfig,
			errMsg:  "milvus collection name cannot be empty",
		},
		{
			name: "valid with minimum port",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       1,
				Collection: "test_collection",
			},
			wantErr: false,
		},
		{
			name: "valid with maximum port",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       65535,
				Collection: "test_collection",
			},
			wantErr: false,
		},
		{
			name: "valid with username only",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       19530,
				Collection: "test_collection",
				Username:   "admin",
				Password:   "",
			},
			wantErr: false,
		},
		{
			name: "valid with password only",
			config: MilvusConfig{
				Host:       "localhost",
				Port:       19530,
				Collection: "test_collection",
				Username:   "",
				Password:   "password123",
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

func TestMilvusConfig_Defaults(t *testing.T) {
	cfg := DefaultMilvusConfig()

	// Verify all default values
	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, 19530, cfg.Port)
	assert.Equal(t, "gibson_vectors", cfg.Collection)
	assert.Equal(t, "", cfg.Username)
	assert.Equal(t, "", cfg.Password)

	// Verify the default config is valid
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestMilvusConfig_DefaultsAreValid(t *testing.T) {
	// Ensure that the default configuration passes validation
	cfg := DefaultMilvusConfig()
	err := cfg.Validate()
	require.NoError(t, err, "default Milvus config should be valid")
}
