package memory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkingMemoryConfig_Validate tests validation of WorkingMemoryConfig
func TestWorkingMemoryConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  WorkingMemoryConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: WorkingMemoryConfig{
				MaxTokens:      100000,
				EvictionPolicy: "lru",
			},
			wantErr: false,
		},
		{
			name: "zero max tokens",
			config: WorkingMemoryConfig{
				MaxTokens:      0,
				EvictionPolicy: "lru",
			},
			wantErr: true,
		},
		{
			name: "negative max tokens",
			config: WorkingMemoryConfig{
				MaxTokens:      -1000,
				EvictionPolicy: "lru",
			},
			wantErr: true,
		},
		{
			name: "invalid eviction policy",
			config: WorkingMemoryConfig{
				MaxTokens:      100000,
				EvictionPolicy: "fifo",
			},
			wantErr: true,
		},
		{
			name: "small max tokens is valid",
			config: WorkingMemoryConfig{
				MaxTokens:      1,
				EvictionPolicy: "lru",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestWorkingMemoryConfig_ApplyDefaults tests default application
func TestWorkingMemoryConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		initial  WorkingMemoryConfig
		expected WorkingMemoryConfig
	}{
		{
			name:    "all defaults",
			initial: WorkingMemoryConfig{},
			expected: WorkingMemoryConfig{
				MaxTokens:      100000,
				EvictionPolicy: "lru",
			},
		},
		{
			name: "partial defaults",
			initial: WorkingMemoryConfig{
				MaxTokens: 50000,
			},
			expected: WorkingMemoryConfig{
				MaxTokens:      50000,
				EvictionPolicy: "lru",
			},
		},
		{
			name: "no defaults needed",
			initial: WorkingMemoryConfig{
				MaxTokens:      200000,
				EvictionPolicy: "lru",
			},
			expected: WorkingMemoryConfig{
				MaxTokens:      200000,
				EvictionPolicy: "lru",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.initial
			config.ApplyDefaults()
			assert.Equal(t, tt.expected, config)
		})
	}
}

// TestMissionMemoryConfig_Validate tests validation of MissionMemoryConfig
func TestMissionMemoryConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  MissionMemoryConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: MissionMemoryConfig{
				CacheSize: 1000,
				EnableFTS: true,
			},
			wantErr: false,
		},
		{
			name: "zero cache size is valid",
			config: MissionMemoryConfig{
				CacheSize: 0,
				EnableFTS: true,
			},
			wantErr: false,
		},
		{
			name: "negative cache size",
			config: MissionMemoryConfig{
				CacheSize: -100,
				EnableFTS: true,
			},
			wantErr: true,
		},
		{
			name: "FTS disabled is valid",
			config: MissionMemoryConfig{
				CacheSize: 1000,
				EnableFTS: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMissionMemoryConfig_ApplyDefaults tests default application
func TestMissionMemoryConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		initial  MissionMemoryConfig
		expected MissionMemoryConfig
	}{
		{
			name:    "all defaults",
			initial: MissionMemoryConfig{},
			expected: MissionMemoryConfig{
				CacheSize:    1000,
				EnableFTS:    false,          // Default is false (zero value)
				TTL:          24 * time.Hour, // Default set by ApplyDefaults
				CompletedTTL: 2 * time.Hour,  // Default set by ApplyDefaults
			},
		},
		{
			name: "custom cache size",
			initial: MissionMemoryConfig{
				CacheSize: 5000,
			},
			expected: MissionMemoryConfig{
				CacheSize:    5000,
				EnableFTS:    false,
				TTL:          24 * time.Hour,
				CompletedTTL: 2 * time.Hour,
			},
		},
		{
			name: "no defaults needed",
			initial: MissionMemoryConfig{
				CacheSize:    2000,
				EnableFTS:    true,
				TTL:          48 * time.Hour,
				CompletedTTL: 4 * time.Hour,
			},
			expected: MissionMemoryConfig{
				CacheSize:    2000,
				EnableFTS:    true,
				TTL:          48 * time.Hour,
				CompletedTTL: 4 * time.Hour,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.initial
			config.ApplyDefaults()
			assert.Equal(t, tt.expected, config)
		})
	}
}

// TestEmbedderConfig_Validate tests validation of EmbedderConfig
func TestEmbedderConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  EmbedderConfig
		wantErr bool
	}{
		{
			name: "valid native config",
			config: EmbedderConfig{
				Provider: "native",
			},
			wantErr: false,
		},
		{
			name: "empty provider defaults to native",
			config: EmbedderConfig{
				Provider: "",
			},
			wantErr: false,
		},
		{
			name: "invalid provider",
			config: EmbedderConfig{
				Provider: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestEmbedderConfig_ApplyDefaults tests default application
func TestEmbedderConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		initial  EmbedderConfig
		expected EmbedderConfig
	}{
		{
			name:    "empty provider defaults to native",
			initial: EmbedderConfig{},
			expected: EmbedderConfig{
				Provider: "native",
			},
		},
		{
			name: "native provider unchanged",
			initial: EmbedderConfig{
				Provider: "native",
			},
			expected: EmbedderConfig{
				Provider: "native",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.initial
			config.ApplyDefaults()
			assert.Equal(t, tt.expected, config)
		})
	}
}

// TestLongTermMemoryConfig_Validate tests validation of LongTermMemoryConfig
func TestLongTermMemoryConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  LongTermMemoryConfig
		wantErr bool
	}{
		{
			name: "valid embedded config",
			config: LongTermMemoryConfig{
				Backend: "embedded",
				Embedder: EmbedderConfig{
					Provider: "native",
				},
			},
			wantErr: false,
		},
		{
			name: "valid redis config",
			config: LongTermMemoryConfig{
				Backend:       "redis",
				ConnectionURL: "redis://localhost:6379",
				Embedder: EmbedderConfig{
					Provider: "native",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid backend",
			config: LongTermMemoryConfig{
				Backend: "invalid_store",
				Embedder: EmbedderConfig{
					Provider: "native",
				},
			},
			wantErr: true,
		},
		{
			name: "embedded with connection url is valid",
			config: LongTermMemoryConfig{
				Backend:       "embedded",
				ConnectionURL: "not-needed-but-ok",
				Embedder: EmbedderConfig{
					Provider: "native",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid embedder config",
			config: LongTermMemoryConfig{
				Backend: "embedded",
				Embedder: EmbedderConfig{
					Provider: "invalid",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestLongTermMemoryConfig_ApplyDefaults tests default application
func TestLongTermMemoryConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		initial  LongTermMemoryConfig
		expected LongTermMemoryConfig
	}{
		{
			name:    "all defaults",
			initial: LongTermMemoryConfig{},
			expected: LongTermMemoryConfig{
				Backend: "embedded",
				Embedder: EmbedderConfig{
					Provider: "native",
				},
			},
		},
		{
			name: "custom backend",
			initial: LongTermMemoryConfig{
				Backend:       "qdrant",
				ConnectionURL: "http://localhost:6333",
			},
			expected: LongTermMemoryConfig{
				Backend:       "qdrant",
				ConnectionURL: "http://localhost:6333",
				Embedder: EmbedderConfig{
					Provider: "native",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.initial
			config.ApplyDefaults()
			assert.Equal(t, tt.expected, config)
		})
	}
}

// TestMemoryConfig_Validate tests validation of top-level MemoryConfig
func TestMemoryConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  MemoryConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: MemoryConfig{
				Working: WorkingMemoryConfig{
					MaxTokens:      100000,
					EvictionPolicy: "lru",
				},
				Mission: MissionMemoryConfig{
					CacheSize: 1000,
					EnableFTS: true,
				},
				LongTerm: LongTermMemoryConfig{
					Backend: "embedded",
					Embedder: EmbedderConfig{
						Provider: "native",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid working config",
			config: MemoryConfig{
				Working: WorkingMemoryConfig{
					MaxTokens:      -1,
					EvictionPolicy: "lru",
				},
				Mission: MissionMemoryConfig{
					CacheSize: 1000,
				},
				LongTerm: LongTermMemoryConfig{
					Backend: "embedded",
					Embedder: EmbedderConfig{
						Provider: "native",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid mission config",
			config: MemoryConfig{
				Working: WorkingMemoryConfig{
					MaxTokens:      100000,
					EvictionPolicy: "lru",
				},
				Mission: MissionMemoryConfig{
					CacheSize: -1,
				},
				LongTerm: LongTermMemoryConfig{
					Backend: "embedded",
					Embedder: EmbedderConfig{
						Provider: "native",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid longterm config",
			config: MemoryConfig{
				Working: WorkingMemoryConfig{
					MaxTokens:      100000,
					EvictionPolicy: "lru",
				},
				Mission: MissionMemoryConfig{
					CacheSize: 1000,
				},
				LongTerm: LongTermMemoryConfig{
					Backend: "qdrant",
					// Missing ConnectionURL
					Embedder: EmbedderConfig{
						Provider: "native",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMemoryConfig_ApplyDefaults tests default application for top-level config
func TestMemoryConfig_ApplyDefaults(t *testing.T) {
	config := &MemoryConfig{}
	config.ApplyDefaults()

	// Verify all sub-configs have defaults applied
	assert.Equal(t, 100000, config.Working.MaxTokens)
	assert.Equal(t, "lru", config.Working.EvictionPolicy)
	assert.Equal(t, 1000, config.Mission.CacheSize)
	assert.Equal(t, "embedded", config.LongTerm.Backend)
	assert.Equal(t, "native", config.LongTerm.Embedder.Provider)
}

// TestNewDefaultMemoryConfig tests the default config constructor
func TestNewDefaultMemoryConfig(t *testing.T) {
	config := NewDefaultMemoryConfig()

	require.NotNil(t, config)

	// Verify defaults are applied
	assert.Equal(t, 100000, config.Working.MaxTokens)
	assert.Equal(t, "lru", config.Working.EvictionPolicy)
	assert.Equal(t, 1000, config.Mission.CacheSize)
	assert.Equal(t, "embedded", config.LongTerm.Backend)
	assert.Equal(t, "native", config.LongTerm.Embedder.Provider)

	// Verify config is valid
	err := config.Validate()
	require.NoError(t, err)
}
