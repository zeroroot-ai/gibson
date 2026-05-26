package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/crypto"
)

func TestNewGCPProvider_MissingSecretName(t *testing.T) {
	cfg := &crypto.GCPKeyConfig{
		ProjectID: "my-gcp-project",
	}
	_, err := NewGCPProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret_name is required")
}

func TestNewGCPProvider_MissingProjectID(t *testing.T) {
	cfg := &crypto.GCPKeyConfig{
		SecretName: "gibson-encryption-key",
	}
	_, err := NewGCPProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "project_id is required")
}

func TestNewGCPProvider_EmptyConfig(t *testing.T) {
	cfg := &crypto.GCPKeyConfig{}
	_, err := NewGCPProvider(cfg)
	assert.Error(t, err)
	// Should fail on first validation (secret_name)
	assert.Contains(t, err.Error(), "secret_name is required")
}

func TestGCPProvider_Name(t *testing.T) {
	p := &GCPProvider{}
	assert.Equal(t, "gcp", p.Name())
}
