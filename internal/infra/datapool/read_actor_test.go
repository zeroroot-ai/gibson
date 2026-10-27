// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
)

// A read with no caller gets the daemon as its actor, so the audit logger takes
// the entry. Without the actor the logger refuses it (gibson#1331).
func TestWithReadActor_GivesAnActorlessReadTheDaemon(t *testing.T) {
	ctx := WithReadActor(context.Background(), auth.MustNewTenantID("primary"))
	id, err := auth.IdentityFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, ReadActor, id.Subject)
	got, ok := auth.TenantFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "primary", got.String())
}

// A read that has a caller keeps the caller and its tenant.
func TestWithReadActor_KeepsTheCaller(t *testing.T) {
	acme := auth.MustNewTenantID("acme")
	ctx := auth.WithIdentity(auth.WithTenant(context.Background(), acme), auth.Identity{
		Subject: "user-1", Tenant: acme, CredentialType: auth.CredentialOIDCUser,
	})
	out := WithReadActor(ctx, auth.MustNewTenantID("other"))
	id, err := auth.IdentityFromContext(out)
	require.NoError(t, err)
	assert.Equal(t, "user-1", id.Subject)
	got, _ := auth.TenantFromContext(out)
	assert.Equal(t, "acme", got.String())
}

// A context with a tenant and no identity keeps its tenant.
func TestWithReadActor_KeepsTheTenantOfTheContext(t *testing.T) {
	ctx := WithReadActor(auth.WithTenant(context.Background(), auth.MustNewTenantID("acme")), auth.MustNewTenantID("other"))
	got, _ := auth.TenantFromContext(ctx)
	assert.Equal(t, "acme", got.String())
}

// actorReader records the actor of the context of each read.
type actorReader struct {
	inner   *mockSecretsReader
	subject string
}

func (a *actorReader) Resolve(ctx context.Context, name string) ([]byte, error) {
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		a.subject = id.Subject
	}
	return a.inner.Resolve(ctx, name)
}

// The neo4j read of a tenant has the daemon as its actor.
func TestInstanceResolver_ReadCarriesAnActor(t *testing.T) {
	rd := &actorReader{inner: vaultPayloadReader("bolt://primary-neo4j:7687", "u", "p")}
	_, err := newInstanceResolver(rd).Resolve(context.Background(), auth.MustNewTenantID("primary"))
	require.NoError(t, err)
	assert.Equal(t, ReadActor, rd.subject)
}

// The postgres read of a tenant has the daemon as its actor.
func TestResolveDSN_ReadCarriesAnActor(t *testing.T) {
	var subject string
	p := newPgPerTenant(Config{PostgresDSNResolver: PostgresDSNResolverFunc(
		func(ctx context.Context, _ auth.TenantID) (string, string, error) {
			if id, err := auth.IdentityFromContext(ctx); err == nil {
				subject = id.Subject
			}
			return "postgres://u:p@h:5432/db", "db", nil
		})})
	_, _, err := p.resolveDSN(context.Background(), auth.MustNewTenantID("primary"), nil)
	require.NoError(t, err)
	assert.Equal(t, ReadActor, subject)
}
