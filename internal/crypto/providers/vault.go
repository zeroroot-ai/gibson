package providers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/zeroroot-ai/gibson/internal/crypto"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// VaultProvider retrieves encryption keys from HashiCorp Vault.
//
// Authentication: per ADR-0009 (jwt-spiffe-everywhere), this provider does
// NOT initiate a Vault `auth/kubernetes` login. The hashicorp
// `vault/api/auth/kubernetes` helper has been removed entirely. Operators
// who run the daemon against a remote Vault must supply a pre-issued client
// token via the standard `VAULT_TOKEN` environment variable (honoured by
// `api.DefaultConfig()`), or run the SDK-side broker pipeline (which
// supports AppRole/JWT/AWS IAM via `internal/daemon/broker_init_vault_auth.go`)
// instead of this KEK shortcut.
type VaultProvider struct {
	client *api.Client
	config *crypto.VaultKeyConfig

	key     []byte
	keyOnce sync.Once
	keyErr  error
}

// NewVaultProvider creates a new HashiCorp Vault key provider.
//
// The returned client picks up `VAULT_TOKEN`, `VAULT_ADDR`, and the rest of
// the standard Vault env-var surface via `api.DefaultConfig()`; cfg.Address
// overrides VAULT_ADDR when set. No auth/kubernetes login is performed
// (see ADR-0009).
func NewVaultProvider(cfg *crypto.VaultKeyConfig) (*VaultProvider, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault.address is required")
	}
	if cfg.SecretPath == "" {
		return nil, fmt.Errorf("vault.secret_path is required")
	}
	if cfg.KeyField == "" {
		return nil, fmt.Errorf("vault.key_field is required")
	}

	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = cfg.Address
	vaultConfig.Timeout = 10 * time.Second

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	return &VaultProvider{
		client: client,
		config: cfg,
	}, nil
}

// GetEncryptionKey retrieves the encryption key from Vault.
func (p *VaultProvider) GetEncryptionKey(ctx context.Context) ([]byte, error) {
	p.keyOnce.Do(func() {
		mountPath := p.config.MountPath
		if mountPath == "" {
			mountPath = "secret"
		}

		secret, err := p.client.KVv2(mountPath).Get(ctx, p.config.SecretPath)
		if err != nil {
			p.keyErr = fmt.Errorf("failed to read secret at %s/%s: %w", mountPath, p.config.SecretPath, err)
			return
		}

		if secret == nil || secret.Data == nil {
			p.keyErr = fmt.Errorf("secret not found at path %s/%s", mountPath, p.config.SecretPath)
			return
		}

		keyValue, ok := secret.Data[p.config.KeyField]
		if !ok {
			p.keyErr = fmt.Errorf("field %q not found in secret at %s/%s", p.config.KeyField, mountPath, p.config.SecretPath)
			return
		}

		keyStr, ok := keyValue.(string)
		if !ok {
			p.keyErr = fmt.Errorf("key field %q is not a string", p.config.KeyField)
			return
		}

		keyBytes := []byte(keyStr)
		if len(keyBytes) != expectedKeySize {
			p.keyErr = fmt.Errorf("invalid key size: expected %d bytes, got %d", expectedKeySize, len(keyBytes))
			return
		}

		p.key = make([]byte, expectedKeySize)
		copy(p.key, keyBytes)
	})

	if p.keyErr != nil {
		return nil, p.keyErr
	}
	return p.key, nil
}

// Name returns the provider identifier.
func (p *VaultProvider) Name() string {
	return "vault"
}

// Health checks provider connectivity and key availability.
func (p *VaultProvider) Health(ctx context.Context) types.HealthStatus {
	_, err := p.GetEncryptionKey(ctx)
	if err != nil {
		return types.HealthStatus{
			State:   types.HealthStateUnhealthy,
			Message: fmt.Sprintf("vault provider error: %v", err),
		}
	}
	return types.HealthStatus{
		State:   types.HealthStateHealthy,
		Message: fmt.Sprintf("key loaded from vault path %s", p.config.SecretPath),
	}
}

// Close releases resources and zeros out the key from memory.
func (p *VaultProvider) Close() error {
	for i := range p.key {
		p.key[i] = 0
	}
	return nil
}
