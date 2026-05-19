package crypto

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/types"
)

// KeyProvider retrieves encryption keys from external secret stores.
// Implementations must be safe for concurrent use and should cache
// the key after first retrieval (keys don't change during pod lifetime).
type KeyProvider interface {
	// GetEncryptionKey returns the 32-byte master encryption key.
	// Returns error if key cannot be retrieved or is invalid size.
	GetEncryptionKey(ctx context.Context) ([]byte, error)

	// Name returns the provider identifier (e.g., "kubernetes", "vault").
	Name() string

	// Health checks provider connectivity and key availability.
	Health(ctx context.Context) types.HealthStatus

	// Close releases any resources held by the provider.
	Close() error
}

// KeyProviderConfig holds configuration for key provider instantiation.
type KeyProviderConfig struct {
	Type       string               `yaml:"type" mapstructure:"type"`
	Kubernetes *KubernetesKeyConfig `yaml:"kubernetes,omitempty" mapstructure:"kubernetes"`
	Vault      *VaultKeyConfig      `yaml:"vault,omitempty" mapstructure:"vault"`
	AWS        *AWSKeyConfig        `yaml:"aws,omitempty" mapstructure:"aws"`
	Azure      *AzureKeyConfig      `yaml:"azure,omitempty" mapstructure:"azure"`
	GCP        *GCPKeyConfig        `yaml:"gcp,omitempty" mapstructure:"gcp"`
}

// KubernetesKeyConfig configures the Kubernetes Secrets provider.
type KubernetesKeyConfig struct {
	SecretName      string `yaml:"secret_name" mapstructure:"secret_name"`
	SecretNamespace string `yaml:"secret_namespace,omitempty" mapstructure:"secret_namespace"`
	SecretKey       string `yaml:"secret_key" mapstructure:"secret_key"`
}

// VaultKeyConfig configures the HashiCorp Vault provider.
//
// Authentication is delegated to the standard Vault env-var surface (e.g.
// VAULT_TOKEN). Per ADR-0009 (jwt-spiffe-everywhere), this provider does
// not initiate a Vault `auth/kubernetes` login, and the previous `Role`
// field used solely for that login has been removed.
type VaultKeyConfig struct {
	Address    string `yaml:"address" mapstructure:"address"`
	MountPath  string `yaml:"mount_path,omitempty" mapstructure:"mount_path"`
	SecretPath string `yaml:"secret_path" mapstructure:"secret_path"`
	KeyField   string `yaml:"key_field" mapstructure:"key_field"`
}

// AWSKeyConfig configures the AWS Secrets Manager provider.
type AWSKeyConfig struct {
	Region    string `yaml:"region,omitempty" mapstructure:"region"`
	SecretARN string `yaml:"secret_arn" mapstructure:"secret_arn"`
}

// AzureKeyConfig configures the Azure Key Vault provider.
type AzureKeyConfig struct {
	VaultURL   string `yaml:"vault_url" mapstructure:"vault_url"`
	SecretName string `yaml:"secret_name" mapstructure:"secret_name"`
}

// GCPKeyConfig configures the GCP Secret Manager provider.
type GCPKeyConfig struct {
	ProjectID  string `yaml:"project_id,omitempty" mapstructure:"project_id"`
	SecretName string `yaml:"secret_name" mapstructure:"secret_name"`
	Version    string `yaml:"version,omitempty" mapstructure:"version"`
}
