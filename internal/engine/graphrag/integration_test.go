// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIntegration_ProviderSwitching tests provider switching between
// different backend types (neo4j, neptune, memgraph).
func TestIntegration_ProviderSwitching(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		expectError  bool
	}{
		{
			name:         "neo4j provider",
			providerType: "neo4j",
			expectError:  true, // Validation fails without URI
		},
		{
			name:         "memgraph provider",
			providerType: "memgraph",
			expectError:  false, // Memgraph doesn't require special config in this implementation
		},
		{
			name:         "invalid provider",
			providerType: "unknown",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GraphRAGConfig{
				Provider: tt.providerType,
			}

			// Note: This would use the actual factory in production
			// For now, we test the configuration validation
			config.ApplyDefaults()
			err := config.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
