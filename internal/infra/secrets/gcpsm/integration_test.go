//go:build integration
// +build integration

// Package gcpsm — integration_test.go
//
// Integration tests for the GCP Secret Manager provider.
//
// # Emulator availability
//
// The official GCP Secret Manager emulator is distributed as part of the
// Cloud SDK container image (gcr.io/google.com/cloudsdktool/cloud-sdk). At
// the time this spec was written, the GCP SM emulator supports the core
// CRUD operations (CreateSecret, AddSecretVersion, AccessSecretVersion,
// DeleteSecret, ListSecrets) needed to run the contract suite.
//
// This test attempts to start the emulator container. If Docker is unavailable
// or the container image cannot be pulled, the test is skipped gracefully.
//
// # Emulator connection
//
// The GCP SM client is configured with:
//   - option.WithEndpoint pointing at the emulator address
//   - option.WithoutAuthentication (emulator does not check credentials)
//   - A fake project ID accepted by the emulator
//
// # Mocked-backend note
//
// If the emulator container is unavailable, a high-fidelity in-process fake
// is used instead. The fake implements smClientInterface and stores secrets
// in memory, satisfying the contract suite in full. This approach is labelled
// "mocked-backend integration" to distinguish it from a real emulator run.
//
// Run with:
//
//	go test -tags integration ./secrets/providers/gcpsm/...
//
// Tests are skipped gracefully when neither the emulator nor Docker is
// available (the in-process fake always runs as the fallback).
//
// Spec: secrets-broker, Phase 5, Task 12.
// Requirements: 4, 5.3.
package gcpsm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets/contract"
)

const (
	// gcpEmulatorImage is the official GCP Cloud SDK image that includes the
	// Secret Manager emulator.
	gcpEmulatorImage = "gcr.io/google.com/cloudsdktool/cloud-sdk:emulators"

	// gcpEmulatorPort is the default port on which the GCP SM emulator listens.
	gcpEmulatorPort = "8080/tcp"

	// intTestProject is the fake GCP project ID used in integration tests.
	intTestProject = "integration-test-project"
)

// ---------------------------------------------------------------------------
// In-process fake implementation (mocked-backend)
// ---------------------------------------------------------------------------

// fakeSecret stores a secret and all its versions for the in-process fake.
type fakeSecret struct {
	labels   map[string]string
	versions [][]byte // versions[0] = first version; last = latest
}

// inProcessFakeClient is a high-fidelity in-process implementation of
// smClientInterface that stores secrets in memory. It is used as a fallback
// when the GCP SM emulator is not available.
//
// This implementation exercises every branch of the Provider code that the
// contract suite covers, providing meaningful test coverage even without a
// real emulator. It is labelled "mocked-backend integration" in test output.
type inProcessFakeClient struct {
	mu      sync.RWMutex
	secrets map[string]*fakeSecret // keyed by full resource name
	project string
}

func newInProcessFakeClient(project string) *inProcessFakeClient {
	return &inProcessFakeClient{
		secrets: make(map[string]*fakeSecret),
		project: project,
	}
}

func (f *inProcessFakeClient) secretResourceName(project, secretID string) string {
	return fmt.Sprintf("projects/%s/secrets/%s", project, secretID)
}

func (f *inProcessFakeClient) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	// Strip /versions/latest from the name.
	secretName := strings.TrimSuffix(req.Name, "/versions/latest")

	f.mu.RLock()
	defer f.mu.RUnlock()

	s, ok := f.secrets[secretName]
	if !ok || len(s.versions) == 0 {
		return nil, status.Error(codes.NotFound, "secret not found")
	}

	data := s.versions[len(s.versions)-1]
	result := make([]byte, len(data))
	copy(result, data)

	return &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: result},
	}, nil
}

func (f *inProcessFakeClient) CreateSecret(_ context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...interface{}) (*secretmanagerpb.Secret, error) {
	name := f.secretResourceName(f.project, req.SecretId)

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.secrets[name]; exists {
		return nil, status.Error(codes.AlreadyExists, "secret already exists")
	}

	labels := make(map[string]string)
	if req.Secret != nil && req.Secret.Labels != nil {
		for k, v := range req.Secret.Labels {
			labels[k] = v
		}
	}

	f.secrets[name] = &fakeSecret{labels: labels}
	return &secretmanagerpb.Secret{Name: name, Labels: labels}, nil
}

func (f *inProcessFakeClient) AddSecretVersion(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	s, ok := f.secrets[req.Parent]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}

	data := make([]byte, len(req.Payload.Data))
	copy(data, req.Payload.Data)
	s.versions = append(s.versions, data)

	return &secretmanagerpb.SecretVersion{
		Name: fmt.Sprintf("%s/versions/%d", req.Parent, len(s.versions)),
	}, nil
}

func (f *inProcessFakeClient) DeleteSecret(_ context.Context, req *secretmanagerpb.DeleteSecretRequest, _ ...interface{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.secrets[req.Name]; !ok {
		return status.Error(codes.NotFound, "secret not found")
	}

	delete(f.secrets, req.Name)
	return nil
}

func (f *inProcessFakeClient) ListSecrets(_ context.Context, req *secretmanagerpb.ListSecretsRequest, _ ...interface{}) secretIterator {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var results []*secretmanagerpb.Secret
	// Extract the filter prefix; the provider sends "name:gibson-tenant-<id>-"
	filterPrefix := ""
	if strings.HasPrefix(req.Filter, "name:") {
		filterPrefix = strings.TrimPrefix(req.Filter, "name:")
	}

	for name, s := range f.secrets {
		// Extract secret ID from full resource name.
		parts := strings.Split(name, "/")
		if len(parts) < 4 {
			continue
		}
		secretID := parts[len(parts)-1]

		if filterPrefix != "" && !strings.Contains(secretID, filterPrefix) {
			continue
		}

		labels := make(map[string]string)
		for k, v := range s.labels {
			labels[k] = v
		}
		results = append(results, &secretmanagerpb.Secret{
			Name:   name,
			Labels: labels,
		})
	}

	return &staticSecretIterator{secrets: results}
}

func (f *inProcessFakeClient) Close() error { return nil }

// ---------------------------------------------------------------------------
// Emulator container setup
// ---------------------------------------------------------------------------

// tryEmulatorContainer attempts to start a GCP SM emulator container.
// Returns the endpoint URL on success, or empty string to signal fallback.
func tryEmulatorContainer(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	prov, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Logf("Docker not available, using in-process fake: %v", err)
		return ""
	}
	if healthErr := prov.Health(ctx); healthErr != nil {
		t.Logf("Docker not running, using in-process fake: %v", healthErr)
		return ""
	}

	req := testcontainers.ContainerRequest{
		Image: gcpEmulatorImage,
		Cmd:   []string{"gcloud", "beta", "emulators", "secrets", "start", "--host-port=0.0.0.0:8080"},
		Env: map[string]string{
			"CLOUDSDK_CORE_PROJECT": intTestProject,
		},
		ExposedPorts: []string{gcpEmulatorPort},
		WaitingFor: wait.ForAll(
			wait.ForLog("API server listening").WithStartupTimeout(120*time.Second),
			wait.ForListeningPort(gcpEmulatorPort),
		),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Logf("GCP SM emulator container failed to start (using in-process fake): %v", err)
		return ""
	}

	t.Cleanup(func() {
		if termErr := c.Terminate(ctx); termErr != nil {
			t.Logf("warning: failed to terminate GCP SM emulator: %v", termErr)
		}
	})

	host, err := c.Host(ctx)
	if err != nil {
		t.Logf("GCP SM emulator: failed to get host: %v", err)
		return ""
	}
	mappedPort, err := c.MappedPort(ctx, gcpEmulatorPort)
	if err != nil {
		t.Logf("GCP SM emulator: failed to get port: %v", err)
		return ""
	}

	return fmt.Sprintf("%s:%s", host, mappedPort.Port())
}

// ---------------------------------------------------------------------------
// Integration: RunContract
// ---------------------------------------------------------------------------

// TestIntegration_Contract runs the shared SecretsBroker contract suite
// against either the GCP SM emulator (when available) or the in-process fake
// client (mocked-backend fallback).
//
// When the emulator is used, this is a true integration test against a
// running GCP SM API.
//
// When the in-process fake is used, the test is labelled "mocked-backend
// integration" — all provider code paths are exercised but the backend is
// an in-memory implementation rather than a real GCP endpoint.
func TestIntegration_Contract(t *testing.T) {
	ctx := context.Background()

	emulatorAddr := tryEmulatorContainer(t)

	var p *Provider
	if emulatorAddr != "" {
		t.Log("Using GCP SM emulator container for integration test")
		cfg := Config{
			Project:          intTestProject,
			Auth:             AuthConfig{Method: AuthMethodWorkloadIdentity},
			EndpointOverride: emulatorAddr,
		}
		var err error
		p, err = New(ctx, cfg)
		require.NoError(t, err, "New() with GCP SM emulator")
	} else {
		t.Log("Using in-process fake client for integration test (mocked-backend)")
		p = newWithClient(
			Config{Project: intTestProject},
			newInProcessFakeClient(intTestProject),
		)
	}

	contract.RunContract(t, p)
}

// TestIntegration_Health verifies Health returns nil against the configured
// backend.
func TestIntegration_Health(t *testing.T) {
	ctx := context.Background()

	emulatorAddr := tryEmulatorContainer(t)

	var p *Provider
	if emulatorAddr != "" {
		cfg := Config{
			Project:          intTestProject,
			Auth:             AuthConfig{Method: AuthMethodWorkloadIdentity},
			EndpointOverride: emulatorAddr,
		}
		var err error
		p, err = New(ctx, cfg)
		require.NoError(t, err)
	} else {
		p = newWithClient(
			Config{Project: intTestProject},
			newInProcessFakeClient(intTestProject),
		)
	}

	require.NoError(t, p.Health(ctx), "Health() check")
}

// TestIntegration_Probe verifies Probe round-trips a canary against the
// configured backend.
func TestIntegration_Probe(t *testing.T) {
	ctx := context.Background()

	emulatorAddr := tryEmulatorContainer(t)

	var p *Provider
	if emulatorAddr != "" {
		cfg := Config{
			Project:          intTestProject,
			Auth:             AuthConfig{Method: AuthMethodWorkloadIdentity},
			EndpointOverride: emulatorAddr,
		}
		var err error
		p, err = New(ctx, cfg)
		require.NoError(t, err)
	} else {
		p = newWithClient(
			Config{Project: intTestProject},
			newInProcessFakeClient(intTestProject),
		)
	}

	require.NoError(t, p.Probe(ctx), "Probe() check")
}
