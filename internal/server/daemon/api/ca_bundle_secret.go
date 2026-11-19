// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
)

// readCABundleSecret reads the tenant secret that holds the PEM CA bundle of a
// backend, and checks that it holds certificates. The context must carry the
// tenant. The error names the secret and never holds the content.
func readCABundleSecret(ctx context.Context, store ConnectorSecretResolver, secretName string) ([]byte, error) {
	pemData, err := store.Resolve(ctx, secretName)
	if err != nil {
		return nil, fmt.Errorf("the tenant secret %q for the CA bundle cannot be read", secretName)
	}
	if err := cabundle.Check(pemData); err != nil {
		return nil, fmt.Errorf("the tenant secret %q is not a CA bundle: %w", secretName, err)
	}
	return pemData, nil
}
