package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/crypto"
)

func TestNewKeyProvider_NilConfig(t *testing.T) {
	_, err := NewKeyProvider(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type is required")
}

func TestNewKeyProvider_EmptyType(t *testing.T) {
	cfg := &crypto.KeyProviderConfig{}
	_, err := NewKeyProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type is required")
}

func TestNewKeyProvider_UnknownType(t *testing.T) {
	cfg := &crypto.KeyProviderConfig{Type: "unknown"}
	_, err := NewKeyProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key provider type")
	assert.Contains(t, err.Error(), "unknown")
}

func TestNewKeyProvider_KubernetesTypeRemoved(t *testing.T) {
	// ADR-0023 (gibson#212/S10): the 'kubernetes' provider type was
	// removed. Asking for it now produces the "unknown type" error with
	// a hint pointing at the file-mount replacement.
	cfg := &crypto.KeyProviderConfig{Type: "kubernetes"}
	_, err := NewKeyProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key provider type")
	assert.Contains(t, err.Error(), "file")
}

func TestNewKeyProvider_FileMissingConfig(t *testing.T) {
	cfg := &crypto.KeyProviderConfig{Type: "file"}
	_, err := NewKeyProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file")
	assert.Contains(t, err.Error(), "configuration required")
}

func TestNewKeyProvider_VaultMissingConfig(t *testing.T) {
	cfg := &crypto.KeyProviderConfig{Type: "vault"}
	_, err := NewKeyProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault")
	assert.Contains(t, err.Error(), "configuration required")
}

func TestNewKeyProvider_AWSMissingConfig(t *testing.T) {
	cfg := &crypto.KeyProviderConfig{Type: "aws"}
	_, err := NewKeyProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aws")
	assert.Contains(t, err.Error(), "configuration required")
}

func TestNewKeyProvider_AzureMissingConfig(t *testing.T) {
	cfg := &crypto.KeyProviderConfig{Type: "azure"}
	_, err := NewKeyProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "azure")
	assert.Contains(t, err.Error(), "configuration required")
}

func TestNewKeyProvider_GCPMissingConfig(t *testing.T) {
	cfg := &crypto.KeyProviderConfig{Type: "gcp"}
	_, err := NewKeyProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "gcp")
	assert.Contains(t, err.Error(), "configuration required")
}
