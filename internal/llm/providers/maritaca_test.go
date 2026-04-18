package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestMaritacaProvider_Name(t *testing.T) {
	p := &MaritacaProvider{}
	assert.Equal(t, "maritaca", p.Name())
}

func TestNewMaritacaProvider_MissingToken(t *testing.T) {
	t.Setenv("MARITACA_API_KEY", "")
	_, err := NewMaritacaProvider(llm.ProviderConfig{
		Type:         llm.ProviderMaritaca,
		DefaultModel: "sabia-3",
	})
	require.Error(t, err)
}

func TestNewMaritacaProvider_EnvFallback(t *testing.T) {
	t.Setenv("MARITACA_API_KEY", "env-key")
	p, err := NewMaritacaProvider(llm.ProviderConfig{
		Type:         llm.ProviderMaritaca,
		DefaultModel: "sabia-3",
	})
	require.NoError(t, err)
	require.NotNil(t, p.client)
}

func TestMaritacaCredentialSchema(t *testing.T) {
	schema := MaritacaCredentialSchema()
	require.NotEmpty(t, schema)
}

func TestTranslateMaritacaError(t *testing.T) {
	assert.Contains(t, strings.ToLower(translateMaritacaError(errors.New("429 rate")).Error()), "rate limit")
	assert.Nil(t, translateMaritacaError(nil))
}
