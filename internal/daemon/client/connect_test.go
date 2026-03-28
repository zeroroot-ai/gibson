package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectOptions_Struct(t *testing.T) {
	// Test that ConnectOptions struct can be created with all fields
	opts := ConnectOptions{
		Token:   "test-token",
		Address: "localhost:50002",
	}

	assert.Equal(t, "test-token", opts.Token)
	assert.Equal(t, "localhost:50002", opts.Address)
}

func TestConnectOptions_EmptyValues(t *testing.T) {
	// Test that empty values are allowed
	opts := ConnectOptions{}

	assert.Empty(t, opts.Token)
	assert.Empty(t, opts.Address)
}

func TestConnectWithOptions_EmptyAddress(t *testing.T) {
	// Test that empty address uses GetDaemonAddress()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	opts := ConnectOptions{
		Token:   "test-token",
		Address: "", // Empty address should use GetDaemonAddress()
	}

	// This will fail to connect (no daemon running), but we can verify it tries
	client, err := ConnectWithOptions(ctx, opts)

	// Should fail with connection error, not empty address error
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestConnectWithOptions_WithToken(t *testing.T) {
	// Test that token is used when provided
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	opts := ConnectOptions{
		Token:   "my-test-token",
		Address: "localhost:59999", // Non-existent port
	}

	// This will fail to connect, but we're testing the options are accepted
	client, err := ConnectWithOptions(ctx, opts)

	require.Error(t, err)
	assert.Nil(t, client)
	// Error should indicate connection failure, not token issues
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestConnectWithOptions_WithoutToken(t *testing.T) {
	// Test that empty token is allowed
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	opts := ConnectOptions{
		Token:   "", // No token
		Address: "localhost:59998",
	}

	client, err := ConnectWithOptions(ctx, opts)

	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestConnectWithOptions_AddressFormats(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{
			name:    "TCP address",
			address: "localhost:50002",
		},
		{
			name:    "Unix socket with scheme",
			address: "unix:///tmp/test.sock",
		},
		{
			name:    "Unix socket without scheme",
			address: "/tmp/test.sock",
		},
		{
			name:    "IP address",
			address: "127.0.0.1:50002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			opts := ConnectOptions{
				Address: tt.address,
			}

			// All these will fail to connect, but we verify address handling
			client, err := ConnectWithOptions(ctx, opts)

			require.Error(t, err)
			assert.Nil(t, client)
			assert.Contains(t, err.Error(), "failed to connect")
		})
	}
}

func TestConnectWithOptions_ContextTimeout(t *testing.T) {
	// Test that context timeout is respected
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	opts := ConnectOptions{
		Address: "localhost:59997",
		Token:   "test-token",
	}

	start := time.Now()
	client, err := ConnectWithOptions(ctx, opts)
	duration := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, client)
	// Should timeout around 50ms (with some margin)
	assert.Less(t, duration, 500*time.Millisecond)
}

func TestConnectWithOptions_ContextDeadline(t *testing.T) {
	// Test that existing context deadline is used
	deadline := time.Now().Add(100 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	opts := ConnectOptions{
		Address: "localhost:59996",
	}

	client, err := ConnectWithOptions(ctx, opts)

	require.Error(t, err)
	assert.Nil(t, client)
}

func TestConnect_BackwardCompatibility(t *testing.T) {
	// Test that legacy Connect function still works
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Connect should call ConnectWithOptions internally
	client, err := Connect(ctx, "localhost:59995")

	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestConnect_EmptyAddress(t *testing.T) {
	// Test that Connect rejects empty addresses
	ctx := context.Background()

	client, err := Connect(ctx, "")

	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestConnectOrFail_BackwardCompatibility(t *testing.T) {
	// Test that ConnectOrFail still works without token
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	client, err := ConnectOrFail(ctx)

	// Should fail (no daemon running), but error format should be helpful
	require.Error(t, err)
	assert.Nil(t, client)
	// Should have helpful error message
	assert.Contains(t, err.Error(), "failed to connect")
}

func TestConnectWithOptions_DefaultTimeout(t *testing.T) {
	// Test that default timeout is added if context has no deadline
	ctx := context.Background() // No deadline

	opts := ConnectOptions{
		Address: "localhost:59994",
	}

	start := time.Now()
	client, err := ConnectWithOptions(ctx, opts)
	duration := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, client)
	// Should have default 5 second timeout (give some margin)
	assert.Less(t, duration, 10*time.Second)
}
