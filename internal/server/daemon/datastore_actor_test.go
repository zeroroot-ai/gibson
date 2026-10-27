// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
)

// A read with no caller gets the daemon as its actor, so the audit logger takes
// the entry. Without the actor the logger refuses it (gibson#1331).
func TestWithDatastoreActor_GivesAnActorlessReadTheDaemon(t *testing.T) {
	tenant := auth.MustNewTenantID("primary")
	ctx := withDatastoreActor(context.Background(), tenant)
	id, err := auth.IdentityFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, datastoreCredentialActor, id.Subject)
	got, ok := auth.TenantFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "primary", got.String())
}

// A read that has a caller keeps the caller and its tenant.
func TestWithDatastoreActor_KeepsTheCaller(t *testing.T) {
	acme := auth.MustNewTenantID("acme")
	ctx := auth.WithIdentity(auth.WithTenant(context.Background(), acme), auth.Identity{
		Subject: "user-1", Tenant: acme, CredentialType: auth.CredentialOIDCUser,
	})
	out := withDatastoreActor(ctx, auth.MustNewTenantID("other"))
	id, err := auth.IdentityFromContext(out)
	require.NoError(t, err)
	assert.Equal(t, "user-1", id.Subject)
	got, _ := auth.TenantFromContext(out)
	assert.Equal(t, "acme", got.String())
}

// The vector resolver reads with an actor on the context.
func TestResolveVectorIndex_ReadCarriesAnActor(t *testing.T) {
	f := &actorProbeResolver{}
	_, _ = resolveVectorIndex(context.Background(), f, auth.MustNewTenantID("primary"))
	assert.Equal(t, datastoreCredentialActor, f.subject)
}

type actorProbeResolver struct{ subject string }

func (f *actorProbeResolver) Resolve(ctx context.Context, _ string) ([]byte, error) {
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		f.subject = id.Subject
	}
	return nil, context.Canceled
}
