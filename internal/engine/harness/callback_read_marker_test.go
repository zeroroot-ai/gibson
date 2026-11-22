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
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

func readMarkerService(t *testing.T) *HarnessCallbackService {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	return NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), NewCallbackHarnessRegistry(),
		WithReadMarkerStore(NewBrainReadMarkerStore(reg)), WithConnectors(markerConnectors()), testEventBus())
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

type failingMarkerStore struct{}

func (failingMarkerStore) WriteReadMarker(context.Context, string, brain.ReadMarker) error {
	return assert.AnError
}

func (failingMarkerStore) LastReadMarker(context.Context, string, string, string) (brain.ReadMarker, bool, error) {
	return brain.ReadMarker{}, false, assert.AnError
}

// A store that fails answers with an in-band INTERNAL error. A failed read
// never looks like "no marker" (gibson#1569).
func TestLastReadMarker_AFailingStoreIsAnErrorNotNoMarker(t *testing.T) {
	svc := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), NewCallbackHarnessRegistry(),
		WithReadMarkerStore(failingMarkerStore{}), WithConnectors(markerConnectors()), testEventBus())
	ctx := readMarkerCtx("acme", "s")

	r, err := svc.LastReadMarker(ctx, &harnesspb.LastReadMarkerRequest{Connector: "c"})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, r.GetError().GetCode())
	assert.False(t, r.GetFound())

	w, err := svc.WriteReadMarker(ctx, &harnesspb.WriteReadMarkerRequest{Connector: "c"})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, w.GetError().GetCode())

	r, err = svc.LastReadMarker(ctx, &harnesspb.LastReadMarkerRequest{})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, r.GetError().GetCode())
}

func TestWriteReadMarker_ANilTimelineFails(t *testing.T) {
	store := NewBrainReadMarkerStore(nil)
	require.Error(t, store.WriteReadMarker(context.Background(), "acme", brain.ReadMarker{Subject: "s", Connector: "c"}))
	_, _, err := store.LastReadMarker(context.Background(), "acme", "s", "c")
	require.Error(t, err)
}

func TestSetReadMarkerStore_WiresTheStore(t *testing.T) {
	m := &CallbackManager{server: &CallbackServer{service: &HarnessCallbackService{}}}
	m.SetReadMarkerStore(failingMarkerStore{})
	require.NotNil(t, m.server.service.readMarkers)
}

// markerConnectors is the connectors of the test tenant: edr, siem and c.
func markerConnectors() fakeConnectors {
	var tools []catalog.ToolEntry
	for _, c := range []string{"edr", "siem", "c"} {
		tools = append(tools, catalog.ToolEntry{Source: toolid.SourceMCP, Connector: c, Tool: "list"})
	}
	return fakeConnectors{tools: tools}
}

// A marker for a name that is no connector of the tenant is refused, and a
// daemon that cannot list the connectors fails the write (gibson#1569).
func TestWriteReadMarker_TheConnectorMustBeOneOfTheTenant(t *testing.T) {
	svc := readMarkerService(t)
	ctx := readMarkerCtx("acme", "s")
	w, err := svc.WriteReadMarker(ctx, &harnesspb.WriteReadMarkerRequest{Connector: "no-such-connector", Cursor: "1"})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, w.GetError().GetCode())
	r, err := svc.LastReadMarker(ctx, &harnesspb.LastReadMarkerRequest{Connector: "no-such-connector"})
	require.NoError(t, err)
	assert.False(t, r.GetFound(), "a refused write left a marker")

	for name, conns := range map[string]ConnectorClient{
		"no client":   nil,
		"list failed": fakeConnectors{listErr: errors.New("down")},
	} {
		ctxc, cancel := context.WithCancel(context.Background())
		reg := brain.NewRegistry(ctxc, braintest.StoreFactory())
		opts := []CallbackServiceOption{WithReadMarkerStore(NewBrainReadMarkerStore(reg)), testEventBus()}
		if conns != nil {
			opts = append(opts, WithConnectors(conns))
		}
		s := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), NewCallbackHarnessRegistry(), opts...)
		w, err := s.WriteReadMarker(ctx, &harnesspb.WriteReadMarkerRequest{Connector: "edr"})
		cancel()
		require.NoError(t, err)
		assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, w.GetError().GetCode(), name)
	}
}

type countingMarkerStore struct {
	ReadMarkerStore
	writes int
}

func (c *countingMarkerStore) WriteReadMarker(ctx context.Context, tenant string, m brain.ReadMarker) error {
	c.writes++
	return c.ReadMarkerStore.WriteReadMarker(ctx, tenant, m)
}

// A write that holds the marker that is already there adds no Timeline event,
// so an agent that polls in a loop does not grow the Timeline (gibson#1569).
func TestWriteReadMarker_AnUnchangedWriteIsANoOp(t *testing.T) {
	ctxb, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	store := &countingMarkerStore{ReadMarkerStore: NewBrainReadMarkerStore(brain.NewRegistry(ctxb, braintest.StoreFactory()))}
	svc := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), NewCallbackHarnessRegistry(),
		WithReadMarkerStore(store), WithConnectors(markerConnectors()), testEventBus())
	ctx := readMarkerCtx("acme", "s")
	write := func(cursor string, ids ...string) {
		t.Helper()
		w, err := svc.WriteReadMarker(ctx, &harnesspb.WriteReadMarkerRequest{Connector: "edr", Cursor: cursor, ResultIds: ids})
		require.NoError(t, err)
		require.Nil(t, w.GetError())
	}
	write("1", "a")
	write("1", "a")
	write("1", "a")
	assert.Equal(t, 1, store.writes, "an unchanged write added a Timeline event")
	write("2", "a")
	write("2", "a", "b")
	assert.Equal(t, 3, store.writes, "a changed cursor or result list must write")
	got, err := svc.LastReadMarker(ctx, &harnesspb.LastReadMarkerRequest{Connector: "edr"})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, got.GetMarker().GetResultIds())
}
