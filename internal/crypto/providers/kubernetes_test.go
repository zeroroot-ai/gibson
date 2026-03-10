package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zero-day-ai/gibson/internal/crypto"
)

func TestNewKubernetesProvider_MissingSecretName(t *testing.T) {
	cfg := &crypto.KubernetesKeyConfig{
		SecretKey: "encryption-key",
	}
	_, err := NewKubernetesProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret_name is required")
}

func TestNewKubernetesProvider_MissingSecretKey(t *testing.T) {
	cfg := &crypto.KubernetesKeyConfig{
		SecretName: "gibson-encryption-key",
	}
	_, err := NewKubernetesProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret_key is required")
}

func TestNewKubernetesProvider_EmptyConfig(t *testing.T) {
	cfg := &crypto.KubernetesKeyConfig{}
	_, err := NewKubernetesProvider(cfg)
	assert.Error(t, err)
	// Should fail on first validation (secret_name)
	assert.Contains(t, err.Error(), "secret_name is required")
}

func TestNewKubernetesProvider_ValidConfigButNotInCluster(t *testing.T) {
	cfg := &crypto.KubernetesKeyConfig{
		SecretName: "gibson-encryption-key",
		SecretKey:  "encryption-key",
	}
	_, err := NewKubernetesProvider(cfg)
	// This will fail because we're not running in a Kubernetes cluster
	// but it validates the config structure is correct
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "in-cluster config")
}
