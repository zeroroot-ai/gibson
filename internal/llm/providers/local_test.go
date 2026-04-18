package providers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestLocalProvider_Name(t *testing.T) {
	p := &LocalProvider{}
	assert.Equal(t, "local", p.Name())
}

func TestNewLocalProvider_MissingBin(t *testing.T) {
	t.Setenv("LOCAL_LLM_BIN", "")
	_, err := NewLocalProvider(llm.ProviderConfig{
		Type:         llm.ProviderLocal,
		DefaultModel: "llama-7b",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bin")
}

func TestNewLocalProvider_BinFromExtra(t *testing.T) {
	// Use a real binary that exists on almost every system.
	binPath := "/bin/true"
	if _, err := os.Stat(binPath); err != nil {
		t.Skipf("%s not present on this system", binPath)
	}
	p, err := NewLocalProvider(llm.ProviderConfig{
		Type:         llm.ProviderLocal,
		DefaultModel: "llama-7b",
		Extra: map[string]string{
			"bin": binPath,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, p.client)
	assert.Equal(t, binPath, p.bin)
}

func TestLocalProvider_Models_SyntheticEntry(t *testing.T) {
	p := &LocalProvider{
		config: llm.ProviderConfig{
			DefaultModel: "llama-7b",
			Extra:        map[string]string{"features": "chat,streaming,tools"},
		},
	}
	models, err := p.Models(nil)
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Equal(t, "llama-7b", models[0].Name)
	assert.ElementsMatch(t, []string{"chat", "streaming", "tools"}, models[0].Features)
}

func TestLocalProvider_Models_DefaultModelNameAndFeatures(t *testing.T) {
	p := &LocalProvider{config: llm.ProviderConfig{}}
	models, err := p.Models(nil)
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Equal(t, "local-model", models[0].Name)
	assert.Equal(t, []string{"chat"}, models[0].Features)
}

func TestLocalProvider_Health_MissingBin(t *testing.T) {
	p := &LocalProvider{bin: filepath.Join(t.TempDir(), "does-not-exist")}
	status := p.Health(nil)
	assert.NotEqual(t, "healthy", string(status.State))
}

func TestLocalCredentialSchema(t *testing.T) {
	schema := LocalCredentialSchema()
	keys := map[string]llm.CredentialField{}
	for _, f := range schema {
		keys[f.Key] = f
	}
	require.Contains(t, keys, "bin")
	assert.True(t, keys["bin"].Required)
}

func TestParseCSV(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "c"}, parseCSV("a,b,c"))
	assert.Equal(t, []string{"a", "b"}, parseCSV("a, b"))
	assert.Equal(t, []string{"a"}, parseCSV("  a  "))
	assert.Nil(t, parseCSV(""))
	assert.Nil(t, parseCSV(",,"))
}
