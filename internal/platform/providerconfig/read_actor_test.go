// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// actorSpy is a secrets service that records the actor of each call.
type actorSpy struct{ actors []string }

func (a *actorSpy) note(ctx context.Context) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil {
		a.actors = append(a.actors, "")
		return
	}
	a.actors = append(a.actors, id.Subject)
}

func (a *actorSpy) Put(ctx context.Context, _ string, _ []byte) error { a.note(ctx); return nil }
func (a *actorSpy) Delete(ctx context.Context, _ string) error        { a.note(ctx); return nil }
func (a *actorSpy) Resolve(ctx context.Context, _ string) ([]byte, error) {
	a.note(ctx)
	return []byte("v"), nil
}
func (a *actorSpy) List(ctx context.Context, _ sdksecrets.Filter) ([]string, error) {
	a.note(ctx)
	return []string{"provider_cred:p:api_key"}, nil
}

// A read that no caller started carries the daemon as its actor. Without one the
// audit logger refuses the entry of each secret read and secret list.
func TestGetCredentials_AnInternalReadHasTheDaemonActor(t *testing.T) {
	spy := &actorSpy{}
	s := &brokerBackedStore{svc: spy}
	_, err := s.getCredentials(context.Background(), "acme", "p")
	require.NoError(t, err)
	assert.Equal(t, []string{ReadActor, ReadActor}, spy.actors, "the list and the resolve both name the daemon")
}

// A read for a request keeps the identity of the caller.
func TestGetCredentials_ARequestKeepsItsCaller(t *testing.T) {
	spy := &actorSpy{}
	s := &brokerBackedStore{svc: spy}
	tid := auth.MustNewTenantID("acme")
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "user:alice", Tenant: tid})
	_, err := s.getCredentials(ctx, "acme", "p")
	require.NoError(t, err)
	assert.Equal(t, []string{"user:alice", "user:alice"}, spy.actors)
}
