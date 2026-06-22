package providers

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/crypto"
)

// NewKeyProvider creates a KeyProvider based on configuration.
func NewKeyProvider(cfg *crypto.KeyProviderConfig) (crypto.KeyProvider, error) {
	if cfg == nil || cfg.Type == "" {
		return nil, fmt.Errorf("security.key_provider.type is required")
	}

	switch cfg.Type {
	case "file":
		if cfg.File == nil {
			return nil, fmt.Errorf("security.key_provider.file configuration required when type is 'file' (path is required)")
		}
		return NewFileProvider(cfg.File)
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
		return nil, fmt.Errorf("unknown key provider type: %q (valid types: file, vault, aws, azure, gcp) — the previous 'kubernetes' value was removed by ADR-0023 (gibson#212/S10); use 'file' with a chart-mounted Secret volume", cfg.Type)
	}
}
