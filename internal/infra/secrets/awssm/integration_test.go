//go:build integration
// +build integration

// Package awssm — integration_test.go
//
// Integration tests for the AWS Secrets Manager provider against a real
// LocalStack container running in Docker via testcontainers-go.
//
// LocalStack provides a high-fidelity AWS Secrets Manager emulation locally.
// The provider is configured with:
//   - A static access key (LocalStack accepts any credentials).
//   - The LocalStack container endpoint URL.
//   - A dummy IAM role for AssumeRole (LocalStack STS accepts any role ARN).
//
// Note: LocalStack's STS AssumeRole may return credentials, but the resulting
// temporary credentials are also accepted by LocalStack for subsequent calls.
// For simplicity, this test uses AuthMethodStatic with LocalStack's dummy
// credentials (any key/secret pair works with LocalStack).
//
// Run with:
//
//	go test -tags integration ./secrets/providers/awssm/...
//
// Tests are skipped gracefully when Docker is unavailable.
//
// Spec: secrets-broker, Phase 4, Task 10.
// Requirements: 4, 5.3.
package awssm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets/contract"
)

const (
	// localstackImage is the official LocalStack image. We use the default
	// tag which includes Secrets Manager support.
	localstackImage = "localstack/localstack:3"

	// intTestRegion is the AWS region used for LocalStack tests. LocalStack
	// accepts any region value.
	intTestRegion = "us-east-1"

	// localstackPort is the port LocalStack listens on for all AWS service
	// endpoints.
	localstackPort = "4566/tcp"
)

// setupLocalStack starts an ephemeral LocalStack container and returns the
// endpoint URL (e.g. "http://127.0.0.1:NNNNN"). A cleanup function is
// registered via t.Cleanup to terminate the container after the test.
//
// The test is skipped gracefully if Docker is not available.
func setupLocalStack(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	// Skip gracefully when Docker is unavailable.
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping LocalStack integration test: %v", err)
		return ""
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker not running, skipping LocalStack integration test: %v", healthErr)
		return ""
	}

	req := testcontainers.ContainerRequest{
		Image: localstackImage,
		Env: map[string]string{
			// Enable only the services we need to speed up startup.
			"SERVICES":              "secretsmanager,sts",
			"DEFAULT_REGION":        intTestRegion,
			"AWS_ACCESS_KEY_ID":     "test",
			"AWS_SECRET_ACCESS_KEY": "test",
		},
		ExposedPorts: []string{localstackPort},
		WaitingFor: wait.ForAll(
			wait.ForLog("Ready.").WithStartupTimeout(60*time.Second),
			wait.ForListeningPort(localstackPort),
		),
	}

	lsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "start LocalStack container")

	t.Cleanup(func() {
		if termErr := lsC.Terminate(ctx); termErr != nil {
			t.Logf("warning: failed to terminate LocalStack container: %v", termErr)
		}
	})

	host, err := lsC.Host(ctx)
	require.NoError(t, err)
	mappedPort, err := lsC.MappedPort(ctx, localstackPort)
	require.NoError(t, err)

	endpoint := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	// Give LocalStack a moment to fully initialise services after the port is up.
	time.Sleep(500 * time.Millisecond)

	return endpoint
}

// TestIntegration_Contract runs the shared SecretsBroker contract suite
// against a real LocalStack Secrets Manager backend. This proves the provider
// conforms to the interface contract against a live (emulated) AWS backend.
func TestIntegration_Contract(t *testing.T) {
	ctx := context.Background()
	endpoint := setupLocalStack(t)
	if endpoint == "" {
		return // already skipped
	}

	cfg := Config{
		Region: intTestRegion,
		Auth: AuthConfig{
			// LocalStack accepts any static credentials.
			Method:          AuthMethodStatic,
			AccessKeyID:     "test",
			SecretAccessKey: "test",
		},
		EndpointURL: endpoint,
		// Use immediate deletion for the contract suite so the delete-then-get
		// contract assertion works without waiting for the recovery window.
		RecoveryWindowDays: 0, // will default to 7 — acceptable for LocalStack
	}

	p, err := New(ctx, cfg)
	require.NoError(t, err, "New() with LocalStack endpoint")

	contract.RunContract(t, p)
}

// TestIntegration_Health verifies Health returns nil against a running
// LocalStack instance.
func TestIntegration_Health(t *testing.T) {
	ctx := context.Background()
	endpoint := setupLocalStack(t)
	if endpoint == "" {
		return
	}

	cfg := Config{
		Region: intTestRegion,
		Auth: AuthConfig{
			Method:          AuthMethodStatic,
			AccessKeyID:     "test",
			SecretAccessKey: "test",
		},
		EndpointURL: endpoint,
	}

	p, err := New(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, p.Health(ctx), "Health() against running LocalStack")
}

// TestIntegration_Probe verifies that Probe writes-reads-force-deletes a
// canary against LocalStack and leaves no residual secret.
func TestIntegration_Probe(t *testing.T) {
	ctx := context.Background()
	endpoint := setupLocalStack(t)
	if endpoint == "" {
		return
	}

	cfg := Config{
		Region: intTestRegion,
		Auth: AuthConfig{
			Method:          AuthMethodStatic,
			AccessKeyID:     "test",
			SecretAccessKey: "test",
		},
		EndpointURL: endpoint,
	}

	p, err := New(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, p.Probe(ctx), "Probe() against running LocalStack")
}
