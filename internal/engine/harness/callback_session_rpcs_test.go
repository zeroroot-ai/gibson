// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The session-context store handlers (gibson#1184) landed in
// callback_session_context.go; their tests below exercise the real handlers
// against an in-memory SessionContextStore, replacing the deny-until-handler
// pins this file used to carry for them (per the per-RPC walker, gibson#793).
//
// DevboxExec (gibson#1183) is no longer pinned denied: setec#239 landed the
// in-VM exec channel and callback_devbox_exec.go plumbs to it, so the RPC is
// classified onto the agent surface. The pin is inverted rather than deleted —
// see TestDevboxExec_IsOnTheAgentSurface.

func requireSessionRPCDenied(t *testing.T, method string) {
	t.Helper()
	logger, _ := newBufferLogger()
	err := checkCallbackPeerAuthz(
		context.Background(),
		callbackEnvoySVID, true,
		method,
		callbackPeerMethodPolicies(), logger,
	)
	require.Error(t, err,
		"an unimplemented session RPC must be denied to every peer until its handler lands")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// DevboxExec is now ON the agent surface (gibson#1183): setec#239 landed the
// in-VM exec channel and callback_devbox_exec.go plumbs to it. This replaces
// TestDevboxExec_DeniedUntilHandlerLands, which pinned the pre-handler denial.
//
// The assertion is kept rather than deleted, inverted: the method must be
// REACHABLE by an agent-callback peer. A silent regression to denied would
// otherwise look like a working daemon that never runs a command.
func TestDevboxExec_IsOnTheAgentSurface(t *testing.T) {
	logger, _ := newBufferLogger()
	err := checkCallbackPeerAuthz(
		context.Background(),
		callbackEnvoySVID, true,
		harnesspb.HarnessCallbackService_DevboxExec_FullMethodName,
		callbackPeerMethodPolicies(), logger,
	)
	require.NoError(t, err,
		"DevboxExec must be reachable now that its handler exists; a silent "+
			"regression to denied looks like a working daemon that never runs a command")
}

// ---------------------------------------------------------------------------
// Session-context store handler tests (gibson#1184)
// ---------------------------------------------------------------------------

// memSessionContextStore is an in-memory SessionContextStore honouring the
// full contract: (tenant, session_id) keying, etag CAS (empty ifMatch =
// create-only), absent-is-not-an-error Get, no-op Delete of a missing blob.
type memSessionContextStore struct {
	blobs map[string][]byte // key: tenant + "\x00" + sessionID
	etags map[string]string
	seq   int
}

func newMemSessionContextStore() *memSessionContextStore {
	return &memSessionContextStore{
		blobs: map[string][]byte{},
		etags: map[string]string{},
	}
}

func (m *memSessionContextStore) key(tenant, sessionID string) string {
	return tenant + "\x00" + sessionID
}

func (m *memSessionContextStore) Put(_ context.Context, tenant, sessionID string, data []byte, ifMatch string) (string, error) {
	k := m.key(tenant, sessionID)
	current, exists := m.etags[k]
	if ifMatch == "" {
		if exists {
			return "", ErrSessionContextConflict
		}
	} else if !exists || current != ifMatch {
		return "", ErrSessionContextConflict
	}
	m.seq++
	etag := fmt.Sprintf("v%d", m.seq)
	m.blobs[k] = append([]byte(nil), data...)
	m.etags[k] = etag
	return etag, nil
}

func (m *memSessionContextStore) Get(_ context.Context, tenant, sessionID string) ([]byte, string, error) {
	k := m.key(tenant, sessionID)
	etag, exists := m.etags[k]
	if !exists {
		return nil, "", nil
	}
	return append([]byte(nil), m.blobs[k]...), etag, nil
}

func (m *memSessionContextStore) Delete(_ context.Context, tenant, sessionID string) error {
	k := m.key(tenant, sessionID)
	delete(m.blobs, k)
	delete(m.etags, k)
	return nil
}

func newSessionContextTestService(t *testing.T, store SessionContextStore) *HarnessCallbackService {
	t.Helper()
	logger, _ := newBufferLogger()
	s := NewHarnessCallbackServiceWithRegistry(logger, NewCallbackHarnessRegistry())
	s.sessionContextStore = store
	return s
}

// sessionCallerCtx builds a request context carrying the component identity
// the SDK auth interceptor would have placed there from the
// x-gibson-identity-* headers after ext-authz verified the CG-JWT.
func sessionCallerCtx(t *testing.T, tenant string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	require.NoError(t, err)
	return auth.WithIdentity(context.Background(), auth.Identity{
		Subject:  "plugin_principal:zerocool",
		Issuer:   auth.IssuerOIDC,
		Tenant:   tid,
		IssuedAt: time.Now(),
	})
}

func TestPutSessionContext_CreateReadRoundtrip(t *testing.T) {
	s := newSessionContextTestService(t, newMemSessionContextStore())
	ctx := sessionCallerCtx(t, "acme")

	put, err := s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1",
		Data:      []byte("opaque-checkpoint"),
		// empty if_match = create
	})
	require.NoError(t, err)
	require.NotEmpty(t, put.GetEtag(), "a successful Put must name the version it produced")

	got, err := s.GetSessionContext(ctx, &harnesspb.GetSessionContextRequest{SessionId: "sess-1"})
	require.NoError(t, err)
	assert.True(t, bytes.Equal([]byte("opaque-checkpoint"), got.GetData()),
		"the blob must round-trip byte-identically — the daemon never interprets it")
	assert.Equal(t, put.GetEtag(), got.GetEtag())
}

func TestPutSessionContext_StaleIfMatchAborted(t *testing.T) {
	s := newSessionContextTestService(t, newMemSessionContextStore())
	ctx := sessionCallerCtx(t, "acme")

	first, err := s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("v1"),
	})
	require.NoError(t, err)

	// Winner advances the version.
	_, err = s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("v2"), IfMatch: first.GetEtag(),
	})
	require.NoError(t, err)

	// The stale writer (still holding the first etag) must lose, distinguishably.
	_, err = s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("clobber"), IfMatch: first.GetEtag(),
	})
	require.Error(t, err, "a stale if_match must not clobber the winner")
	assert.Equal(t, codes.Aborted, status.Code(err))

	// Create against an existing blob is a conflict too.
	_, err = s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("recreate"),
	})
	require.Error(t, err, "empty if_match is create-only; an existing blob is a conflict")
	assert.Equal(t, codes.Aborted, status.Code(err))

	// The winner's write survived.
	got, err := s.GetSessionContext(ctx, &harnesspb.GetSessionContextRequest{SessionId: "sess-1"})
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got.GetData())
}

func TestPutSessionContext_SizeCapEnforced(t *testing.T) {
	store := newMemSessionContextStore()
	s := newSessionContextTestService(t, store)
	ctx := sessionCallerCtx(t, "acme")

	_, err := s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1",
		Data:      make([]byte, maxSessionContextBytes+1),
	})
	require.Error(t, err, "an oversized blob must be refused server-side")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Empty(t, store.blobs, "an oversized blob must never reach the store")
}

func TestPutSessionContext_RequiresTenantAndSessionID(t *testing.T) {
	s := newSessionContextTestService(t, newMemSessionContextStore())

	// No identity on the context → fail closed with PermissionDenied.
	_, err := s.PutSessionContext(context.Background(), &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("x"),
	})
	require.Error(t, err, "an identity-less request has no tenant and no session namespace")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Missing session_id → InvalidArgument.
	ctx := sessionCallerCtx(t, "acme")
	_, err = s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{Data: []byte("x")})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// Missing data → InvalidArgument (Delete exists for removal).
	_, err = s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{SessionId: "sess-1"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestPutSessionContext_UnavailableWithoutStore(t *testing.T) {
	s := newSessionContextTestService(t, nil)
	_, err := s.PutSessionContext(sessionCallerCtx(t, "acme"), &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("x"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestGetSessionContext_FreshSessionIsNotAnError(t *testing.T) {
	s := newSessionContextTestService(t, newMemSessionContextStore())
	got, err := s.GetSessionContext(sessionCallerCtx(t, "acme"),
		&harnesspb.GetSessionContextRequest{SessionId: "never-written"})
	require.NoError(t, err, "a fresh session is not an error (wire contract)")
	assert.Empty(t, got.GetData())
	assert.Empty(t, got.GetEtag())
}

// TestGetSessionContext_TenantIsolation pins the invariant the whole store
// exists for: the tenant half of the key comes from the caller's identity,
// never from the request, so one tenant's component can never name — let
// alone read or delete — another tenant's session state, even with an
// identical agent-chosen session_id.
func TestGetSessionContext_TenantIsolation(t *testing.T) {
	s := newSessionContextTestService(t, newMemSessionContextStore())
	acme := sessionCallerCtx(t, "acme")
	rival := sessionCallerCtx(t, "rival")

	_, err := s.PutSessionContext(acme, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("acme-private"),
	})
	require.NoError(t, err)

	// Same session_id, different tenant → a different (empty) namespace.
	got, err := s.GetSessionContext(rival, &harnesspb.GetSessionContextRequest{SessionId: "sess-1"})
	require.NoError(t, err)
	assert.Empty(t, got.GetData(), "tenant rival must not read tenant acme's blob")
	assert.Empty(t, got.GetEtag())

	// A cross-tenant delete is a no-op in the rival's own namespace.
	_, err = s.DeleteSessionContext(rival, &harnesspb.DeleteSessionContextRequest{SessionId: "sess-1"})
	require.NoError(t, err)
	got, err = s.GetSessionContext(acme, &harnesspb.GetSessionContextRequest{SessionId: "sess-1"})
	require.NoError(t, err)
	assert.Equal(t, []byte("acme-private"), got.GetData(),
		"tenant rival's delete must not touch tenant acme's blob")
}

func TestGetSessionContext_RequiresTenant(t *testing.T) {
	s := newSessionContextTestService(t, newMemSessionContextStore())
	_, err := s.GetSessionContext(context.Background(),
		&harnesspb.GetSessionContextRequest{SessionId: "sess-1"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestDeleteSessionContext_RemovesBlobAndMissingIsNoop(t *testing.T) {
	s := newSessionContextTestService(t, newMemSessionContextStore())
	ctx := sessionCallerCtx(t, "acme")

	_, err := s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("x"),
	})
	require.NoError(t, err)

	_, err = s.DeleteSessionContext(ctx, &harnesspb.DeleteSessionContextRequest{SessionId: "sess-1"})
	require.NoError(t, err)

	got, err := s.GetSessionContext(ctx, &harnesspb.GetSessionContextRequest{SessionId: "sess-1"})
	require.NoError(t, err)
	assert.Empty(t, got.GetData(), "the blob must be gone after Delete")

	// Deleting a session that has no blob is a no-op, not an error.
	_, err = s.DeleteSessionContext(ctx, &harnesspb.DeleteSessionContextRequest{SessionId: "sess-1"})
	require.NoError(t, err)

	// After delete, an empty-if_match create must succeed again.
	_, err = s.PutSessionContext(ctx, &harnesspb.PutSessionContextRequest{
		SessionId: "sess-1", Data: []byte("recreated"),
	})
	require.NoError(t, err, "Delete must clear the CAS state so a fresh create succeeds")
}

// TestPutSessionContext_PeerPolicyAllowsCallbackPeers is the policy
// complement of the handler tests: with handlers landed, the callback peers'
// method policy must admit the three store RPCs (the reconciliation test in
// callback_method_policy_test.go pins the same from the other direction).
func TestPutSessionContext_PeerPolicyAllowsCallbackPeers(t *testing.T) {
	logger, _ := newBufferLogger()
	for _, method := range []string{
		harnesspb.HarnessCallbackService_PutSessionContext_FullMethodName,
		harnesspb.HarnessCallbackService_GetSessionContext_FullMethodName,
		harnesspb.HarnessCallbackService_DeleteSessionContext_FullMethodName,
	} {
		err := checkCallbackPeerAuthz(
			context.Background(),
			callbackEnvoySVID, true,
			method,
			callbackPeerMethodPolicies(), logger,
		)
		assert.NoError(t, err, "%s is served here; the envoy callback peer must reach it", method)
	}
}

// errSessionContextStore returns a scripted error from every method.
type errSessionContextStore struct{ err error }

func (e *errSessionContextStore) Put(context.Context, string, string, []byte, string) (string, error) {
	return "", e.err
}
func (e *errSessionContextStore) Get(context.Context, string, string) ([]byte, string, error) {
	return nil, "", e.err
}
func (e *errSessionContextStore) Delete(context.Context, string, string) error { return e.err }

func TestPutSessionContext_StoreErrorClassification(t *testing.T) {
	ctx := sessionCallerCtx(t, "acme")
	req := &harnesspb.PutSessionContextRequest{SessionId: "sess-1", Data: []byte("x")}

	// The store's own size-cap refusal surfaces as RESOURCE_EXHAUSTED
	// (second line of defense behind the handler's cap).
	s := newSessionContextTestService(t, &errSessionContextStore{err: fmt.Errorf("cap: %w", ErrSessionContextTooLarge)})
	_, err := s.PutSessionContext(ctx, req)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	// Any other store failure is INTERNAL — never leaked verbatim.
	s = newSessionContextTestService(t, &errSessionContextStore{err: fmt.Errorf("pg down")})
	_, err = s.PutSessionContext(ctx, req)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestGetSessionContext_StoreErrorIsInternal(t *testing.T) {
	s := newSessionContextTestService(t, &errSessionContextStore{err: fmt.Errorf("pg down")})
	_, err := s.GetSessionContext(sessionCallerCtx(t, "acme"),
		&harnesspb.GetSessionContextRequest{SessionId: "sess-1"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestGetSessionContext_UnavailableWithoutStoreAndValidates(t *testing.T) {
	// nil store → Unavailable.
	s := newSessionContextTestService(t, nil)
	_, err := s.GetSessionContext(sessionCallerCtx(t, "acme"),
		&harnesspb.GetSessionContextRequest{SessionId: "sess-1"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))

	// empty session_id → InvalidArgument.
	s = newSessionContextTestService(t, newMemSessionContextStore())
	_, err = s.GetSessionContext(sessionCallerCtx(t, "acme"), &harnesspb.GetSessionContextRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestPutSessionContext_SessionIDLengthBounded(t *testing.T) {
	s := newSessionContextTestService(t, newMemSessionContextStore())
	long := strings.Repeat("s", maxSessionIDBytes+1)
	_, err := s.PutSessionContext(sessionCallerCtx(t, "acme"),
		&harnesspb.PutSessionContextRequest{SessionId: long, Data: []byte("x")})
	require.Error(t, err, "a session_id is a storage key; an unbounded one must be refused")
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestDeleteSessionContext_FailClosedBranches(t *testing.T) {
	// nil store → Unavailable.
	s := newSessionContextTestService(t, nil)
	_, err := s.DeleteSessionContext(sessionCallerCtx(t, "acme"),
		&harnesspb.DeleteSessionContextRequest{SessionId: "sess-1"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))

	// no identity → PermissionDenied.
	s = newSessionContextTestService(t, newMemSessionContextStore())
	_, err = s.DeleteSessionContext(context.Background(),
		&harnesspb.DeleteSessionContextRequest{SessionId: "sess-1"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// empty session_id → InvalidArgument.
	_, err = s.DeleteSessionContext(sessionCallerCtx(t, "acme"), &harnesspb.DeleteSessionContextRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// store error → Internal.
	s = newSessionContextTestService(t, &errSessionContextStore{err: fmt.Errorf("pg down")})
	_, err = s.DeleteSessionContext(sessionCallerCtx(t, "acme"),
		&harnesspb.DeleteSessionContextRequest{SessionId: "sess-1"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// TestPutSessionContext_SetterWiresService covers the CallbackServer and
// CallbackManager wiring path the daemon uses (SetSessionContextStore).
func TestPutSessionContext_SetterWiresService(t *testing.T) {
	logger, _ := newBufferLogger()
	store := newMemSessionContextStore()

	m := NewCallbackManager(CallbackConfig{Enabled: false}, logger)
	m.SetSessionContextStore(store)
	require.NotNil(t, m.server, "manager must construct its server eagerly")
	assert.Same(t, store, m.server.service.sessionContextStore.(*memSessionContextStore),
		"SetSessionContextStore must reach the service the gRPC server registers")
}
