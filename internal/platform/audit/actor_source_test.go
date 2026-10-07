// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditLogger_ActorSourceReachesTheTailAndTheDurableRow: the actor
// source that the writer derives from the credential is the actor_type of
// the durable row, and the live tail returns it (gibson#544).
func TestAuditLogger_ActorSourceReachesTheTailAndTheDurableRow(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-7", "")

	al.Log(ctx, "apikey.revoke", "apikey", "key-9", nil)

	got := durableOf(t, al).recorded()
	require.Len(t, got, 1)
	assert.Equal(t, "user", got[0].ActorType)

	require.True(t, waitForQueue(al, time.Second))
	require.Eventually(t, func() bool {
		entries, err := al.Query(context.Background(), "acme", AuditQueryOptions{})
		return err == nil && len(entries) == 1 && entries[0].ActorSource == "user" && entries[0].ActorID == "user-7"
	}, time.Second, 5*time.Millisecond, "the live tail must return the actor source")
}
