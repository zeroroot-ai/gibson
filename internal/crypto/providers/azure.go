package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/types"
)

// AzureProvider retrieves encryption keys from Azure Key Vault.
type AzureProvider struct {
	client     *azsecrets.Client
	secretName string
	vaultURL   string

	key     []byte
	keyOnce sync.Once
	keyErr  error
}

// NewAzureProvider creates a new Azure Key Vault key provider.
func NewAzureProvider(cfg *crypto.AzureKeyConfig) (*AzureProvider, error) {
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("azure.vault_url is required")
	}
	if cfg.SecretName == "" {
		return nil, fmt.Errorf("azure.secret_name is required")
	}

	// Use DefaultAzureCredential which supports Workload Identity
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	client, err := azsecrets.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault client: %w", err)
	}

	return &AzureProvider{
		client:     client,
		secretName: cfg.SecretName,
		vaultURL:   cfg.VaultURL,
	}, nil
}

// GetEncryptionKey retrieves the encryption key from Azure Key Vault.
func (p *AzureProvider) GetEncryptionKey(ctx context.Context) ([]byte, error) {
	p.keyOnce.Do(func() {
		resp, err := p.client.GetSecret(ctx, p.secretName, "", nil)
		if err != nil {
			p.keyErr = fmt.Errorf("failed to get secret %s from %s: %w", p.secretName, p.vaultURL, err)
			return
		}

		if resp.Value == nil {
			p.keyErr = fmt.Errorf("secret %s has no value", p.secretName)
			return
		}

		keyBytes := []byte(*resp.Value)

		// Handle base64-encoded keys
		if len(keyBytes) != expectedKeySize {
			decoded, err := base64.StdEncoding.DecodeString(string(keyBytes))
			if err == nil && len(decoded) == expectedKeySize {
				keyBytes = decoded
			}
		}

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
func (p *AzureProvider) Name() string {
	return "azure"
}

// Health checks provider connectivity and key availability.
func (p *AzureProvider) Health(ctx context.Context) types.HealthStatus {
	_, err := p.GetEncryptionKey(ctx)
	if err != nil {
		return types.HealthStatus{
			State:   types.HealthStateUnhealthy,
			Message: fmt.Sprintf("azure provider error: %v", err),
		}
	}
	return types.HealthStatus{
		State:   types.HealthStateHealthy,
		Message: fmt.Sprintf("key loaded from Azure Key Vault %s", p.vaultURL),
	}
}

// Close releases resources and zeros out the key from memory.
func (p *AzureProvider) Close() error {
	for i := range p.key {
		p.key[i] = 0
	}
	return nil
}
