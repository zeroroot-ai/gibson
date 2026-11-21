// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
)

func readMarkerService(t *testing.T) *HarnessCallbackService {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	return NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), NewCallbackHarnessRegistry(),
		WithReadMarkerStore(NewBrainReadMarkerStore(reg)), testEventBus())
}

func readMarkerCtx(tenant, subject string) context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: subject, Tenant: auth.MustNewTenantID(tenant)})
}

// A component reads back only its own marker, and the value of
// ContextInfo.agent_name moves neither a read nor a write (gibson#1569).
func TestWriteReadMarker_AComponentReadsOnlyItsOwnMarker(t *testing.T) {
	svc := readMarkerService(t)
	a := readMarkerCtx("acme", "spiffe://acme/agent-a")
	b := readMarkerCtx("acme", "spiffe://acme/agent-b")

	// Agent A writes and names agent B in the field that the caller sets.
	w, err := svc.WriteReadMarker(a, &harnesspb.WriteReadMarkerRequest{
		Context:   &harnesspb.ContextInfo{AgentName: "agent-b"},
		Connector: "edr", Cursor: "42", ResultIds: []string{"r1", "r2"},
	})
	require.NoError(t, err)
	require.Nil(t, w.GetError())

	// Agent B reads, and claims to be agent A.
	got, err := svc.LastReadMarker(b, &harnesspb.LastReadMarkerRequest{
		Context: &harnesspb.ContextInfo{AgentName: "agent-a"}, Connector: "edr",
	})
	require.NoError(t, err)
	require.Nil(t, got.GetError())
	assert.False(t, got.GetFound(), "agent B read the marker of agent A")

	// Agent A reads its own, whatever name it sends.
	got, err = svc.LastReadMarker(a, &harnesspb.LastReadMarkerRequest{
		Context: &harnesspb.ContextInfo{AgentName: "agent-b"}, Connector: "edr",
	})
	require.NoError(t, err)
	require.True(t, got.GetFound())
	assert.Equal(t, "42", got.GetMarker().GetCursor())
	assert.Equal(t, []string{"r1", "r2"}, got.GetMarker().GetResultIds())
	assert.Equal(t, "edr", got.GetMarker().GetConnector())
	assert.NotNil(t, got.GetMarker().GetAt())
}

// A marker of one tenant is not visible to the same identity name in another
// tenant, and a call with no authenticated identity is refused.
func TestLastReadMarker_TenantAndIdentityComeFromTheAuthContext(t *testing.T) {
	svc := readMarkerService(t)
	_, err := svc.WriteReadMarker(readMarkerCtx("acme", "s"), &harnesspb.WriteReadMarkerRequest{Connector: "c", Cursor: "1"})
	require.NoError(t, err)

	got, err := svc.LastReadMarker(readMarkerCtx("other", "s"), &harnesspb.LastReadMarkerRequest{Connector: "c"})
	require.NoError(t, err)
	assert.False(t, got.GetFound())

	for _, ctx := range []context.Context{
		context.Background(),
		auth.ContextWithTenantString(context.Background(), "acme"),
	} {
		w, err := svc.WriteReadMarker(ctx, &harnesspb.WriteReadMarkerRequest{Connector: "c"})
		require.NoError(t, err)
		assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, w.GetError().GetCode())
		r, err := svc.LastReadMarker(ctx, &harnesspb.LastReadMarkerRequest{Connector: "c"})
		require.NoError(t, err)
		assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, r.GetError().GetCode())
	}
}

// A daemon with no store, and a request with no Connector, answer in-band.
func TestWriteReadMarker_RefusalsUseHarnessError(t *testing.T) {
	bare := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), NewCallbackHarnessRegistry(), testEventBus())
	r, err := bare.LastReadMarker(readMarkerCtx("acme", "s"), &harnesspb.LastReadMarkerRequest{Connector: "c"})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, r.GetError().GetCode())
	assert.False(t, r.GetFound(), "a failed read must not look like no marker")

	svc := readMarkerService(t)
	w, err := svc.WriteReadMarker(readMarkerCtx("acme", "s"), &harnesspb.WriteReadMarkerRequest{})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, w.GetError().GetCode())
}
