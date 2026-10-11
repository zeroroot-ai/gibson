// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

package authz_test

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// The platform runs OpenFGA with the preshared key method. Against a real
// OpenFGA with that method: a call with no key and a call with a wrong key
// are refused, the platform client works with the key, and a client whose
// current key OpenFGA does not know yet works with its previous key.
func TestIntegration_FGA_PresharedKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, baseURL, cleanup := setupFGAContainer(t, ctx,
		"--authn-method", "preshared", "--authn-preshared-keys", testFGAKey)
	defer cleanup()

	// No key: OpenFGA refuses the call.
	resp, err := http.Post(baseURL+"/stores", "application/json", strings.NewReader(`{"name":"no-key"}`))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a call with no key must be refused")

	// A wrong key: refused.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/stores", strings.NewReader(`{"name":"wrong-key"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer not-the-key")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a call with a wrong key must be refused")

	// The health check stays open for the kubelet probes.
	resp, err = http.Get(baseURL + "/healthz")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	mgmt, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl: baseURL,
		Credentials: &credentials.Credentials{
			Method: credentials.CredentialsMethodApiToken,
			Config: &credentials.Config{ApiToken: testFGAKey},
		},
	})
	require.NoError(t, err)
	store, err := mgmt.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{Name: "preshared"}).Execute()
	require.NoError(t, err)
	storeID := store.GetId()
	modelID := loadModelFromDSLWithKey(t, ctx, baseURL, storeID, testFGAKey)

	check := func(keyDir string) error {
		a, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
			Endpoint:  baseURL,
			KeyDir:    keyDir,
			StoreID:   storeID,
			ModelID:   modelID,
			TimeoutMs: 5000,
			Logger:    slog.Default(),
		})
		require.NoError(t, err)
		defer func() { _ = a.Close() }()
		_, err = a.Check(ctx, "user:_system", "platform_operator", "system_tenant:_system")
		return err //nolint:wrapcheck // the assertion subject
	}

	require.NoError(t, check(writeKeyDir(t, testFGAKey)), "the platform client with the key")
	require.Error(t, check(writeKeyDir(t, "not-the-key")), "the platform client with a wrong key")

	// A rotation reached the client before OpenFGA: the current key is new,
	// and the previous key is the one OpenFGA runs with.
	rotated := writeKeyDir(t, "next-key")
	require.NoError(t, os.WriteFile(filepath.Join(rotated, "key_previous"), []byte(testFGAKey), 0o600))
	require.NoError(t, check(rotated), "the previous key during a rotation")
}
