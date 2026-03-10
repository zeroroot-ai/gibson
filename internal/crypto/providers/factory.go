package providers

import (
	"fmt"

	"github.com/zero-day-ai/gibson/internal/crypto"
)

// NewKeyProvider creates a KeyProvider based on configuration.
func NewKeyProvider(cfg *crypto.KeyProviderConfig) (crypto.KeyProvider, error) {
	if cfg == nil || cfg.Type == "" {
		return nil, fmt.Errorf("security.key_provider.type is required")
	}

	switch cfg.Type {
	case "kubernetes":
		if cfg.Kubernetes == nil {
			return nil, fmt.Errorf("security.key_provider.kubernetes configuration required when type is 'kubernetes'")
		}
		return NewKubernetesProvider(cfg.Kubernetes)
	case "vault":
		if cfg.Vault == nil {
			return nil, fmt.Errorf("security.key_provider.vault configuration required when type is 'vault'")
		}
		return NewVaultProvider(cfg.Vault)
	case "aws":
		if cfg.AWS == nil {
			return nil, fmt.Errorf("security.key_provider.aws configuration required when type is 'aws'")
		}
		return NewAWSProvider(cfg.AWS)
	case "azure":
		if cfg.Azure == nil {
			return nil, fmt.Errorf("security.key_provider.azure configuration required when type is 'azure'")
		}
		return NewAzureProvider(cfg.Azure)
	case "gcp":
		if cfg.GCP == nil {
			return nil, fmt.Errorf("security.key_provider.gcp configuration required when type is 'gcp'")
		}
		return NewGCPProvider(cfg.GCP)
	default:
		return nil, fmt.Errorf("unknown key provider type: %q (valid types: kubernetes, vault, aws, azure, gcp)", cfg.Type)
	}
}
