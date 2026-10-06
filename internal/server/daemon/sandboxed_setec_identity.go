// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build setec_integration

package daemon

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
)

// The adapter checks a sandbox identity for the fork checks of the callback
// service (setec#235, D74).
var _ harness.SandboxIdentityVerifier = (*setecClient)(nil)

// NewSetecIdentityVerifier dials setec and returns the check of the sandbox
// identity. The setec address is required (#979), so each daemon has one.
func NewSetecIdentityVerifier(cfg config.SandboxConfig) (harness.SandboxIdentityVerifier, error) {
	c, err := NewSetecSandboxClient(cfg)
	if err != nil {
		return nil, err
	}
	v, ok := c.(harness.SandboxIdentityVerifier)
	if !ok {
		return nil, errors.New("setec: client does not implement the sandbox identity check")
	}
	return v, nil
}

// VerifySandboxIdentity asks setec which sandbox of the tenant an identity
// token names (SandboxService.VerifySandboxIdentity). A token that setec
// does not accept wraps harness.ErrSandboxIdentityRefused. Any other error
// means setec cannot answer now.
func (c *setecClient) VerifySandboxIdentity(ctx context.Context, tenant, token, audience string) (string, error) {
	if tenant == "" {
		return "", errNoTenant
	}
	resp, err := c.inner.VerifySandboxIdentity(ctx, &setecv1.VerifySandboxIdentityRequest{
		Token: token, Audience: audience, Tenant: tenant,
	})
	if err != nil {
		if identityRefused(status.Code(err)) {
			return "", fmt.Errorf("setec: verify sandbox identity: %w: %w", harness.ErrSandboxIdentityRefused, err)
		}
		return "", fmt.Errorf("setec: verify sandbox identity: %w", err)
	}
	if resp.GetSandboxId() == "" {
		return "", fmt.Errorf("setec: verify sandbox identity: %w: no sandbox id", harness.ErrSandboxIdentityRefused)
	}
	return resp.GetSandboxId(), nil
}

// identityRefused reports whether a setec code means that the token does not
// verify for the tenant, as opposed to setec that cannot answer.
func identityRefused(c codes.Code) bool {
	return c == codes.Unauthenticated || c == codes.InvalidArgument ||
		c == codes.PermissionDenied || c == codes.NotFound
}
