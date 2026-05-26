package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/crypto"
)

func TestNewAzureProvider_MissingVaultURL(t *testing.T) {
	cfg := &crypto.AzureKeyConfig{
		SecretName: "gibson-encryption-key",
	}
	_, err := NewAzureProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault_url is required")
}

func TestNewAzureProvider_MissingSecretName(t *testing.T) {
	cfg := &crypto.AzureKeyConfig{
		VaultURL: "https://gibson-vault.vault.azure.net/",
	}
	_, err := NewAzureProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret_name is required")
}

func TestNewAzureProvider_EmptyConfig(t *testing.T) {
	cfg := &crypto.AzureKeyConfig{}
	_, err := NewAzureProvider(cfg)
	assert.Error(t, err)
	// Should fail on first validation (vault_url)
	assert.Contains(t, err.Error(), "vault_url is required")
}

func TestAzureProvider_Name(t *testing.T) {
	p := &AzureProvider{}
	assert.Equal(t, "azure", p.Name())
}
