// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// mockCAEnv names the variable that holds the PEM CA of the mock provider,
	// in base64. tests/fixtures/mockprovider/deploy.sh sets it. The mock serves
	// a certificate that this private CA signed, so the gateway needs the CA to
	// verify it.
	mockCAEnv = "GIBSON_E2E_MOCK_CA_B64"
	// mockCASecret is the name of the tenant secret that holds the CA. A provider
	// record names it in the field ca_bundle_secret.
	mockCASecret = "e2e-mock-provider-ca"
)

// saveMockProviderCA stores the CA of the mock provider as a tenant secret of the
// tenant in ctx, and returns the secret name for the field ca_bundle_secret of a
// provider. The daemon checks at save time that the secret holds certificates.
func saveMockProviderCA(ctx context.Context, t *testing.T, tenant string, secrets secretsv1.SecretsServiceClient) string {
	t.Helper()
	encoded := os.Getenv(mockCAEnv)
	if encoded == "" {
		t.Fatalf("%s is not set: the test needs the CA of tests/fixtures/mockprovider", mockCAEnv)
	}
	pemData, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err, "decode %s", mockCAEnv)
	_, err = secrets.SetSecret(ctx, &secretsv1.SetSecretRequest{
		Name: mockCASecret, Category: secretsv1.SecretCategory_SECRET_CATEGORY_CRED, Value: pemData,
	})
	require.NoError(t, err, "SetSecret(%s)", mockCASecret)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), tenant), 30*time.Second)
		defer cancel()
		_, _ = secrets.DeleteSecret(c, &secretsv1.DeleteSecretRequest{Name: mockCASecret})
	})
	return mockCASecret
}

// mockProviderCredentials returns the credential fields of a provider that points
// at the mock provider: a key, the https URL and the CA bundle secret.
func mockProviderCredentials(mockURL, caSecret string) map[string]string {
	return map[string]string{"api_key": "mock-key-e2e-only", "base_url": mockURL, "ca_bundle_secret": caSecret}
}
