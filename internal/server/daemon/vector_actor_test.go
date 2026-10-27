// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

type actorProbeResolver struct{ subject string }

func (f *actorProbeResolver) Resolve(ctx context.Context, _ string) ([]byte, error) {
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		f.subject = id.Subject
	}
	return nil, context.Canceled
}

// The vector resolver reads with an actor on the context. Without it the audit
// logger refuses the entry of the read (gibson#1331).
func TestResolveVectorIndex_ReadCarriesAnActor(t *testing.T) {
	f := &actorProbeResolver{}
	_, _ = resolveVectorIndex(context.Background(), f, auth.MustNewTenantID("primary"))
	assert.Equal(t, datapool.ReadActor, f.subject)
}
