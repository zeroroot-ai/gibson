// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"

	"github.com/zeroroot-ai/sdk/auth"
)

// ReadActor is the audit actor of a read of the infra secrets of a tenant
// (postgres, neo4j, vector) that no caller started. The data pool reads them
// to open a connection, and a secret read records its actor (gibson#676). With
// no actor on the context the audit logger refuses the entry, so the read left
// no record.
const ReadActor = "system:datastore-credential-reader"

// WithReadActor returns ctx with the daemon as the actor when ctx names none.
// A request that carries an identity keeps it, so the record of the read names
// the caller. The tenant of the read is the tenant of ctx, or tenant when ctx
// names none.
func WithReadActor(ctx context.Context, tenant auth.TenantID) context.Context {
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		return ctx
	}
	if t, ok := auth.TenantFromContext(ctx); ok {
		tenant = t
	}
	return auth.WithIdentity(auth.WithTenant(ctx, tenant), auth.Identity{
		Subject:        ReadActor,
		Tenant:         tenant,
		CredentialType: auth.CredentialClientCredentials,
	})
}
