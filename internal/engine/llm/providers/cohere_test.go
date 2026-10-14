// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

func TestCohereProvider_Name(t *testing.T) {
	p := &CohereProvider{}
	assert.Equal(t, "cohere", p.Name())
}

func TestNewCohereProvider_MissingToken(t *testing.T) {
	t.Setenv("COHERE_API_KEY", "")
	_, err := newCohereProviderWithContext(context.Background(), llm.ProviderConfig{
		Type:         llm.ProviderCohere,
		DefaultModel: "command-r",
	})
	require.Error(t, err)
}

func TestCohereCredentialSchema(t *testing.T) {
	schema := CohereCredentialSchema()
	require.NotEmpty(t, schema)
	found := false
	for _, f := range schema {
		if f.Key == "api_key" {
			found = true
			assert.True(t, f.Required)
			assert.True(t, f.Secret)
		}
	}
	assert.True(t, found)
}

func TestTranslateCohereError(t *testing.T) {
	assert.Contains(t, strings.ToLower(translateCohereError(errors.New("429 rate limit")).Error()), "rate limit")
	assert.Contains(t, strings.ToLower(translateCohereError(errors.New("401 unauthorized")).Error()), "auth")
	assert.Contains(t, strings.ToLower(translateCohereError(errors.New("400 bad request")).Error()), "invalid")
	assert.Nil(t, translateCohereError(nil))
}
