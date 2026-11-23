// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
)

// readCABundleSecret reads the tenant secret that holds the PEM CA bundle of a
// backend, and checks that it holds certificates. The context must carry the
// tenant. The error names the secret and never holds the content.
//
// The field names the secret as the dashboard shows it. SetSecret stores a
// credential under "cred:<name>", so the read uses the same rule
// (secrets.StoredName). The daemon log holds the error of the store, and the
// error to the caller does not. The log holds no name of a secret, because the
// name comes from a field that the CodeQL query secret-to-log treats as secret
// material. The error to the caller names the secret.
func readCABundleSecret(ctx context.Context, store ConnectorSecretResolver, secretName string) ([]byte, error) {
	return readCABundleAt(ctx, store, secrets.StoredName(secretsv1.SecretCategory_SECRET_CATEGORY_CRED, secretName), secretName)
}

// readCABundleAt reads the secret under the stored key and returns the CA
// certificates of it as new PEM (cabundle.Normalize). The caller names the
// secret as the user wrote it in shown, and the error uses that name.
func readCABundleAt(ctx context.Context, store ConnectorSecretResolver, storedKey, shown string) ([]byte, error) {
	pemData, err := store.Resolve(ctx, storedKey)
	if err != nil {
		slog.WarnContext(ctx, "the tenant secret of a CA bundle cannot be read", "error", err)
		return nil, fmt.Errorf("the tenant secret %q for the CA bundle cannot be read", shown)
	}
	clean, err := cabundle.Normalize(pemData)
	if err != nil {
		return nil, fmt.Errorf("the tenant secret %q is not a CA bundle: %w", shown, err)
	}
	return clean, nil
}
