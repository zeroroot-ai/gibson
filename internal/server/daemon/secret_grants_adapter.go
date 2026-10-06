// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	"github.com/zeroroot-ai/gibson/internal/server/admin"
	"github.com/zeroroot-ai/sdk/auth"
)

// secretNameListerAdapter lists the secret names of a tenant for the secret
// grant RPCs of GrantsService (dashboard#174). secrets.Service reads the
// tenant from the context, so the adapter puts the tenant there.
type secretNameListerAdapter struct {
	svc *secrets.Service
}

var _ admin.SecretNameLister = (*secretNameListerAdapter)(nil)

func (a *secretNameListerAdapter) List(ctx context.Context, tenant auth.TenantID) ([]string, error) {
	return a.svc.List(auth.WithTenant(ctx, tenant), sdksecrets.Filter{})
}
