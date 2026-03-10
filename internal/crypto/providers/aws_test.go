package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zero-day-ai/gibson/internal/crypto"
)

func TestNewAWSProvider_MissingSecretARN(t *testing.T) {
	cfg := &crypto.AWSKeyConfig{}
	_, err := NewAWSProvider(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secret_arn is required")
}

func TestNewAWSProvider_ValidConfigButNoCredentials(t *testing.T) {
	cfg := &crypto.AWSKeyConfig{
		SecretARN: "arn:aws:secretsmanager:us-east-1:123456789012:secret:gibson-key",
		Region:    "us-east-1",
	}
	// This will fail if AWS credentials are not available
	// but it validates the config structure is correct
	_, err := NewAWSProvider(cfg)
	// We expect either success or a credential error, not a validation error
	if err != nil {
		// Should not be a validation error
		assert.NotContains(t, err.Error(), "secret_arn is required")
	}
}

func TestAWSProvider_Name(t *testing.T) {
	p := &AWSProvider{}
	assert.Equal(t, "aws", p.Name())
}
