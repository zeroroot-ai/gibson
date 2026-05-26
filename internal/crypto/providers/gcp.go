package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/zeroroot-ai/gibson/internal/crypto"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// GCPProvider retrieves encryption keys from GCP Secret Manager.
type GCPProvider struct {
	client     *secretmanager.Client
	projectID  string
	secretName string
	version    string

	key     []byte
	keyOnce sync.Once
	keyErr  error
}

// NewGCPProvider creates a new GCP Secret Manager key provider.
func NewGCPProvider(cfg *crypto.GCPKeyConfig) (*GCPProvider, error) {
	if cfg.SecretName == "" {
		return nil, fmt.Errorf("gcp.secret_name is required")
	}
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("gcp.project_id is required")
	}

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP Secret Manager client: %w", err)
	}

	version := cfg.Version
	if version == "" {
		version = "latest"
	}

	return &GCPProvider{
		client:     client,
		projectID:  cfg.ProjectID,
		secretName: cfg.SecretName,
		version:    version,
	}, nil
}

// GetEncryptionKey retrieves the encryption key from GCP Secret Manager.
func (p *GCPProvider) GetEncryptionKey(ctx context.Context) ([]byte, error) {
	p.keyOnce.Do(func() {
		name := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", p.projectID, p.secretName, p.version)

		req := &secretmanagerpb.AccessSecretVersionRequest{
			Name: name,
		}

		result, err := p.client.AccessSecretVersion(ctx, req)
		if err != nil {
			p.keyErr = fmt.Errorf("failed to access secret %s: %w", name, err)
			return
		}

		keyBytes := result.Payload.Data

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
func (p *GCPProvider) Name() string {
	return "gcp"
}

// Health checks provider connectivity and key availability.
func (p *GCPProvider) Health(ctx context.Context) types.HealthStatus {
	_, err := p.GetEncryptionKey(ctx)
	if err != nil {
		return types.HealthStatus{
			State:   types.HealthStateUnhealthy,
			Message: fmt.Sprintf("gcp provider error: %v", err),
		}
	}
	return types.HealthStatus{
		State:   types.HealthStateHealthy,
		Message: fmt.Sprintf("key loaded from GCP secret %s", p.secretName),
	}
}

// Close releases resources and zeros out the key from memory.
func (p *GCPProvider) Close() error {
	for i := range p.key {
		p.key[i] = 0
	}
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}
