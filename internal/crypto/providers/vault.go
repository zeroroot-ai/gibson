package providers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/types"
)

// VaultProvider retrieves encryption keys from HashiCorp Vault.
type VaultProvider struct {
	client *api.Client
	config *crypto.VaultKeyConfig

	key     []byte
	keyOnce sync.Once
	keyErr  error
}

// NewVaultProvider creates a new HashiCorp Vault key provider using Kubernetes auth.
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
	if cfg.Role == "" {
		return nil, fmt.Errorf("vault.role is required for kubernetes auth")
	}

	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = cfg.Address
	vaultConfig.Timeout = 10 * time.Second

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Authenticate using Kubernetes auth method
	k8sAuth, err := kubernetes.NewKubernetesAuth(
		cfg.Role,
		kubernetes.WithServiceAccountTokenPath("/var/run/secrets/kubernetes.io/serviceaccount/token"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes auth: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), k8sAuth)
	if err != nil {
		return nil, fmt.Errorf("vault kubernetes auth failed (check role %q exists and is configured): %w", cfg.Role, err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("vault auth returned nil auth info")
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
