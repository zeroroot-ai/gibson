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
// error to the caller does not.
func readCABundleSecret(ctx context.Context, store ConnectorSecretResolver, secretName string) ([]byte, error) {
	stored := secrets.StoredName(secretsv1.SecretCategory_SECRET_CATEGORY_CRED, secretName)
	pemData, err := store.Resolve(ctx, stored)
	if err != nil {
		slog.WarnContext(ctx, "the tenant secret of a CA bundle cannot be read",
			"secret", secretName, "stored_name", stored, "error", err)
		return nil, fmt.Errorf("the tenant secret %q for the CA bundle cannot be read", secretName)
	}
	if err := cabundle.Check(pemData); err != nil {
		return nil, fmt.Errorf("the tenant secret %q is not a CA bundle: %w", secretName, err)
	}
	return pemData, nil
}
