// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func worldViewRequest(missionID string, focus ...string) *harnesspb.WorldViewRequest {
	return &harnesspb.WorldViewRequest{
		Context: &harnesspb.ContextInfo{MissionId: missionID, AgentName: "recon-agent"},
		Focus:   focus,
	}
}

func newWorldViewService(t *testing.T, h *observeMockHarness, source WorldViewSource) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	registry.Register(h.missionID.String(), "recon-agent", h)
	svc := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry)
	// Production wires the source through CallbackManager.SetWorldViewSource;
	// tests set the field directly (same package) to avoid a test-only option.
	svc.worldViewSource = source
	return svc
}

// TestWorldView_FailsWhenUnsinked: with no source wired the read FAILS.
//
// This test previously asserted the opposite — that an unsinked read returns an
// empty slice, mirroring Observe's no-op-when-unsinked contract. That symmetry
// was wrong. Dropping an emission loses one observation; answering a READ with
// an empty World tells the agent the tenant knows nothing, and the agent cannot
// tell that apart from a World that is genuinely empty. It then proceeds on a
// false negative: "no prior findings for this target" when the truth is "I could
// not look". In a security product that is the worst available failure.
//
// The SDK's half of this same RPC already refuses to do it — "Failing is the
// only honest answer" (serve/worldview.go). Both halves now agree.
func TestWorldView_FailsWhenUnsinked(t *testing.T) {
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	svc := newWorldViewService(t, h, nil)

	resp, err := svc.WorldView(acmeCtx(), worldViewRequest(mid.String()))
	require.Error(t, err, "an unsinked read must fail, never report an empty World")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Nil(t, resp)
}

// TestWorldView_EmptyWorldIsNotAnError: a World that really is empty still
// answers with an empty slice and no error. The failure above is about an
// unreachable source, not an absence of entities — conflating the two would
// swap one silent lie for a loud one.
func TestWorldView_EmptyWorldIsNotAnError(t *testing.T) {
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	svc := newWorldViewService(t, h, func(context.Context, WorldViewQuery) (WorldViewResult, error) {
		return WorldViewResult{}, nil
	})

	resp, err := svc.WorldView(acmeCtx(), worldViewRequest(mid.String()))
	require.NoError(t, err)
	assert.Empty(t, resp.Entities)
	assert.Nil(t, resp.Error)
}

// TestWorldView_AttributionComesFromTheMissionRecord: the tenant and scope the
// source is queried with are read off the daemon's mission record, never off the
// request, so an agent cannot widen its slice (ADR-0012).
func TestWorldView_AttributionComesFromTheMissionRecord(t *testing.T) {
	mid := types.NewID()
	target := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: target}

	var gotQuery WorldViewQuery
	source := func(_ context.Context, q WorldViewQuery) (WorldViewResult, error) {
		gotQuery = q
		return WorldViewResult{
			Entities: []WorldEntityRecord{{
				Handle:     "h-1",
				Kind:       harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_HOST,
				Label:      "10.0.0.1",
				Attributes: map[string]string{"open_ports": "1"},
			}},
			Truncated: true,
		}, nil
	}
	svc := newWorldViewService(t, h, source)

	resp, err := svc.WorldView(acmeCtx(), worldViewRequest(mid.String()))
	require.NoError(t, err)

	assert.Equal(t, "acme", gotQuery.Tenant, "tenant must come from the mission record")
	assert.Equal(t, target.String(), gotQuery.ScopeID, "scope must be the mission target, not the request")
	assert.Equal(t, mid.String(), gotQuery.MissionID)

	require.Len(t, resp.Entities, 1)
	assert.Equal(t, "h-1", resp.Entities[0].Handle)
	assert.Equal(t, "10.0.0.1", resp.Entities[0].Label)
	assert.True(t, resp.Truncated)
}

// TestWorldView_FocusPassedThrough: the request's focus handles reach the source
// verbatim (the source is what validates them).
func TestWorldView_FocusPassedThrough(t *testing.T) {
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	var gotFocus []string
	source := func(_ context.Context, q WorldViewQuery) (WorldViewResult, error) {
		gotFocus = q.Focus
		return WorldViewResult{}, nil
	}
	svc := newWorldViewService(t, h, source)

	_, err := svc.WorldView(acmeCtx(), worldViewRequest(mid.String(), "h-1", "h-2"))
	require.NoError(t, err)
	assert.Equal(t, []string{"h-1", "h-2"}, gotFocus)
}

// TestWorldView_FocusRefusalIsInBand: a refused focus handle (the source returns
// PermissionDenied) surfaces as an in-band HarnessError, not a transport error,
// so the SDK client sees the emit-contract error shape.
func TestWorldView_FocusRefusalIsInBand(t *testing.T) {
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	source := func(_ context.Context, _ WorldViewQuery) (WorldViewResult, error) {
		return WorldViewResult{}, status.Error(codes.PermissionDenied, "focus handle not issued to this slice")
	}
	svc := newWorldViewService(t, h, source)

	resp, err := svc.WorldView(acmeCtx(), worldViewRequest(mid.String(), "forged"))
	require.NoError(t, err, "a refused focus is an in-band error, not a transport failure")
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.Error.Code)
}

// TestWorldView_SourceErrorIsInternal: a non-permission source error surfaces as
// an in-band INTERNAL HarnessError.
func TestWorldView_SourceErrorIsInternal(t *testing.T) {
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	source := func(_ context.Context, _ WorldViewQuery) (WorldViewResult, error) {
		return WorldViewResult{}, errors.New("brain unavailable")
	}
	svc := newWorldViewService(t, h, source)

	resp, err := svc.WorldView(acmeCtx(), worldViewRequest(mid.String()))
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, resp.Error.Code)
}

// TestWorldView_UnknownMissionRejected: a request whose mission the daemon does
// not know is refused by getHarness before the source is ever reached.
func TestWorldView_UnknownMissionRejected(t *testing.T) {
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	called := false
	source := func(_ context.Context, _ WorldViewQuery) (WorldViewResult, error) {
		called = true
		return WorldViewResult{}, nil
	}
	svc := newWorldViewService(t, h, source)

	_, err := svc.WorldView(acmeCtx(), worldViewRequest(types.NewID().String()))
	require.Error(t, err, "an unknown mission must be refused")
	assert.False(t, called, "the source must not run for an unresolved mission")
}

func acmeCtx() context.Context {
	return auth.ContextWithTenantString(context.Background(), "acme")
}

// TestWorldView_AttributionRefusedWhenTenantMissing: with no tenant on the
// context, getHarness refuses before the source runs — the agent cannot read a
// World slice it has no authenticated tenant for.
func TestWorldView_AttributionRefusedWhenTenantMissing(t *testing.T) {
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	called := false
	svc := newWorldViewService(t, h, func(context.Context, WorldViewQuery) (WorldViewResult, error) {
		called = true
		return WorldViewResult{}, nil
	})

	_, err := svc.WorldView(context.Background(), worldViewRequest(mid.String()))
	require.Error(t, err, "a tenant-less caller must be refused")
	assert.False(t, called, "the source must not run without a resolved tenant")
}

// TestSetWorldViewSource wires a source onto a CallbackManager's service and
// confirms it reaches the WorldView handler.
func TestSetWorldViewSource(t *testing.T) {
	mgr := NewCallbackManager(CallbackConfig{ListenAddress: "127.0.0.1:0"}, slog.New(slog.DiscardHandler))
	called := false
	mgr.SetWorldViewSource(func(context.Context, WorldViewQuery) (WorldViewResult, error) {
		called = true
		return WorldViewResult{Entities: []WorldEntityRecord{{Handle: "h"}}}, nil
	})

	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	mgr.server.service.registry.Register(mid.String(), "recon-agent", h)

	resp, err := mgr.server.service.WorldView(acmeCtx(), worldViewRequest(mid.String()))
	require.NoError(t, err)
	assert.True(t, called, "SetWorldViewSource must wire the source the handler calls")
	assert.Len(t, resp.Entities, 1)
}
