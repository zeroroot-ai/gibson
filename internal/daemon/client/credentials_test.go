package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenCredentials(t *testing.T) {
	token := "test-token-123"
	creds := NewTokenCredentials(token)

	require.NotNil(t, creds)
	assert.IsType(t, &TokenCredentials{}, creds)
}

func TestTokenCredentials_GetRequestMetadata_WithToken(t *testing.T) {
	token := "test-token-123"
	creds := NewTokenCredentials(token)

	ctx := context.Background()
	metadata, err := creds.GetRequestMetadata(ctx)

	require.NoError(t, err)
	require.NotNil(t, metadata)
	assert.Equal(t, "Bearer test-token-123", metadata["authorization"])
}

func TestTokenCredentials_GetRequestMetadata_EmptyToken(t *testing.T) {
	creds := NewTokenCredentials("")

	ctx := context.Background()
	metadata, err := creds.GetRequestMetadata(ctx)

	require.NoError(t, err)
	assert.Nil(t, metadata, "Empty token should return nil metadata")
}

func TestTokenCredentials_GetRequestMetadata_WithURI(t *testing.T) {
	token := "test-token-456"
	creds := NewTokenCredentials(token)

	ctx := context.Background()
	// URI parameter should be ignored for token auth
	metadata, err := creds.GetRequestMetadata(ctx, "unix:///path/to/socket")

	require.NoError(t, err)
	require.NotNil(t, metadata)
	assert.Equal(t, "Bearer test-token-456", metadata["authorization"])
}

func TestTokenCredentials_RequireTransportSecurity(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "with token",
			token: "test-token",
		},
		{
			name:  "empty token",
			token: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := NewTokenCredentials(tt.token)
			require := creds.RequireTransportSecurity()
			assert.False(t, require, "Should allow insecure connections for development")
		})
	}
}

func TestTokenCredentials_MetadataFormat(t *testing.T) {
	// Test that the authorization header format matches gRPC bearer token expectations
	creds := NewTokenCredentials("my-secret-token")

	ctx := context.Background()
	metadata, err := creds.GetRequestMetadata(ctx)

	require.NoError(t, err)
	require.NotNil(t, metadata)
	require.Contains(t, metadata, "authorization")

	authHeader := metadata["authorization"]
	assert.True(t, len(authHeader) > len("Bearer "), "Authorization header should contain Bearer prefix plus token")
	assert.Contains(t, authHeader, "Bearer ", "Authorization header should use Bearer scheme")
	assert.Contains(t, authHeader, "my-secret-token", "Authorization header should contain the token")
}
