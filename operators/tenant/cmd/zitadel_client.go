// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
)

// newZitadelClient builds the operator's Zitadel client. It authenticates as
// the operator's own machine user with a client_credentials token, never with
// the Zitadel owner credentials.
func newZitadelClient(ctx context.Context, apiURL, externalDomain, clientID, clientSecret string) (zitadel.Client, error) {
	tokens, err := zitadel.TokenSource(ctx, apiURL, externalDomain, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("zitadel client: %w", err)
	}
	return zitadel.New(apiURL, tokens, externalDomain), nil
}
