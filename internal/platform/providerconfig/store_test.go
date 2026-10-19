// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

func TestValidateType(t *testing.T) {
	tests := []struct {
		name    string
		typ     llm.ProviderType
		wantErr bool
	}{
		{name: "supported type", typ: llm.ProviderAnthropic},
		{name: "empty type", typ: "", wantErr: true},
		{name: "unknown type", typ: "no-such-provider", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateType(tt.typ)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrUnsupportedType)
			// The message lists the supported types, never the fixture type.
			assert.Contains(t, err.Error(), string(llm.ProviderAnthropic))
		})
	}
}

func TestJoinTypes(t *testing.T) {
	assert.Equal(t, "", joinTypes(nil))
	assert.Equal(t, "a, b", joinTypes([]llm.ProviderType{"a", "b"}))
}
