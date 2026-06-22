package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/platform/crypto"
)

func TestNewVaultProvider_MissingAddress(t *testing.T) {
	cfg := &crypto.VaultKeyConfig{
		SecretPath: "secret/gibson/encryption-key",
		KeyField:   "key",
	}
	_, err := NewVaultProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address is required")
}

func TestNewVaultProvider_MissingSecretPath(t *testing.T) {
	cfg := &crypto.VaultKeyConfig{
		Address:  "https://vault.example.com",
		KeyField: "key",
	}
	_, err := NewVaultProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret_path is required")
}

func TestNewVaultProvider_MissingKeyField(t *testing.T) {
	cfg := &crypto.VaultKeyConfig{
		Address:    "https://vault.example.com",
		SecretPath: "secret/gibson/encryption-key",
	}
	_, err := NewVaultProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key_field is required")
}

func TestNewVaultProvider_EmptyConfig(t *testing.T) {
	cfg := &crypto.VaultKeyConfig{}
	_, err := NewVaultProvider(cfg)
	assert.Error(t, err)
	// Should fail on first validation (address)
	assert.Contains(t, err.Error(), "address is required")
}

func TestVaultProvider_Name(t *testing.T) {
	p := &VaultProvider{}
	assert.Equal(t, "vault", p.Name())
}
