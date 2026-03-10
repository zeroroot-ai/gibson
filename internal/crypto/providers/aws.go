package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/types"
)

// AWSProvider retrieves encryption keys from AWS Secrets Manager.
type AWSProvider struct {
	client    *secretsmanager.Client
	secretARN string

	key     []byte
	keyOnce sync.Once
	keyErr  error
}

// NewAWSProvider creates a new AWS Secrets Manager key provider.
func NewAWSProvider(cfg *crypto.AWSKeyConfig) (*AWSProvider, error) {
	if cfg.SecretARN == "" {
		return nil, fmt.Errorf("aws.secret_arn is required")
	}

	var opts []func(*config.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, config.WithRegion(cfg.Region))
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	return &AWSProvider{
		client:    client,
		secretARN: cfg.SecretARN,
	}, nil
}

// GetEncryptionKey retrieves the encryption key from AWS Secrets Manager.
func (p *AWSProvider) GetEncryptionKey(ctx context.Context) ([]byte, error) {
	p.keyOnce.Do(func() {
		input := &secretsmanager.GetSecretValueInput{
			SecretId: &p.secretARN,
		}

		result, err := p.client.GetSecretValue(ctx, input)
		if err != nil {
			p.keyErr = fmt.Errorf("failed to get secret %s: %w", p.secretARN, err)
			return
		}

		var keyBytes []byte
		if result.SecretString != nil {
			keyBytes = []byte(*result.SecretString)
		} else if result.SecretBinary != nil {
			keyBytes = result.SecretBinary
		} else {
			p.keyErr = fmt.Errorf("secret %s has no value", p.secretARN)
			return
		}

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
func (p *AWSProvider) Name() string {
	return "aws"
}

// Health checks provider connectivity and key availability.
func (p *AWSProvider) Health(ctx context.Context) types.HealthStatus {
	_, err := p.GetEncryptionKey(ctx)
	if err != nil {
		return types.HealthStatus{
			State:   types.HealthStateUnhealthy,
			Message: fmt.Sprintf("aws provider error: %v", err),
		}
	}
	return types.HealthStatus{
		State:   types.HealthStateHealthy,
		Message: fmt.Sprintf("key loaded from AWS secret %s", p.secretARN),
	}
}

// Close releases resources and zeros out the key from memory.
func (p *AWSProvider) Close() error {
	for i := range p.key {
		p.key[i] = 0
	}
	return nil
}
