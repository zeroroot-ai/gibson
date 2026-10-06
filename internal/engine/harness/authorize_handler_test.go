// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

// authorize_handler_test.go: coverage for the
// HarnessCallbackService.Authorize RPC handler with an in-memory tuple set.
//
// Prior to this file the Authorize handler had zero tests; this is the first
// vertical slice through all four observable outcomes:
//
//  1. Happy path — active run, FGA allows → AuthorizeResponse{Allowed:true}.
//  2. FGA denied — active run, FGA denies → AuthorizeResponse{Allowed:false}.
//  3. Run not found — authzStore returns ErrRunNotFound → gRPC NotFound.
//  4. Mission inactive — run has status "completed" → gRPC FailedPrecondition.
//
// The fake authorizer keeps its tuples in a map in this file. It used the
// FakeStore of the testfixtures module, which had no other consumer, so the
// store moved here and the module left go.mod (D78).
//
// Slice 5.6 of the production-readiness epic (gibson#183).

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// fgaBackedAuthorizer: minimal authz.Authorizer backed by an in-memory tuple set.
//
// Only Check, Write, and the no-op stubs are needed by Authorize tests.
// ---------------------------------------------------------------------------

// fgaTuple is the (user, relation, object) key of the tuple set.
type fgaTuple struct {
	user, relation, object string
}

type fgaBackedAuthorizer struct {
	mu     sync.Mutex
	tuples map[fgaTuple]struct{}
}

func newFGABackedAuthorizer() *fgaBackedAuthorizer {
	return &fgaBackedAuthorizer{tuples: make(map[fgaTuple]struct{})}
}

func (a *fgaBackedAuthorizer) has(t fgaTuple) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.tuples[t]
	return ok
}

func (a *fgaBackedAuthorizer) put(t fgaTuple) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tuples[t] = struct{}{}
}

func (a *fgaBackedAuthorizer) drop(t fgaTuple) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tuples, t)
}

// Seed writes a tuple into the underlying FakeStore so Check returns true.
func (a *fgaBackedAuthorizer) Seed(user, relation, object string) {
	a.put(fgaTuple{user: user, relation: relation, object: object})
}

func (a *fgaBackedAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	return a.has(fgaTuple{user: user, relation: relation, object: object}), nil
}

func (a *fgaBackedAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		out[i] = a.has(fgaTuple{user: c.User, relation: c.Relation, object: c.Object})
	}
	return out, nil
}

func (a *fgaBackedAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	for _, t := range tuples {
		a.put(fgaTuple{user: t.User, relation: t.Relation, object: t.Object})
	}
	return nil
}

func (a *fgaBackedAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	for _, t := range tuples {
		a.drop(fgaTuple{user: t.User, relation: t.Relation, object: t.Object})
	}
	return nil
}

func (a *fgaBackedAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (a *fgaBackedAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (a *fgaBackedAuthorizer) StoreID() string { return "fake" }
func (a *fgaBackedAuthorizer) ModelID() string { return "fake" }
func (a *fgaBackedAuthorizer) Close() error    { return nil }

// ---------------------------------------------------------------------------
// stubRunAuthzLookup: minimal RunAuthzLookup for Authorize tests.
// ---------------------------------------------------------------------------

type stubRunAuthzLookup struct {
	state *RunAuthzState
	err   error
}

func (s *stubRunAuthzLookup) Get(_ context.Context, _ string) (*RunAuthzState, error) {
	return s.state, s.err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newAuthorizeService builds a HarnessCallbackService wired with the given
// authzStore and componentAuthorizer — the two dependencies exercised by
// the Authorize handler.
func newAuthorizeService(
	store RunAuthzLookup,
	authorizer authz.Authorizer,
) *HarnessCallbackService {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	return NewHarnessCallbackService(
		logger,
		WithAuthzStore(store),
		WithComponentAuthorizer(authorizer),
	)
}

// grpcCode extracts the gRPC status code from an error or returns codes.OK.
func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	if st, ok := status.FromError(err); ok {
		return st.Code()
	}
	return codes.Unknown
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// TestAuthorize_HappyPath verifies that an Authorize call succeeds when:
//   - the authzStore knows the run_id with status "active"
//   - the FGA fake has the relevant tuple seeded (allow)
//
// Expected result: AuthorizeResponse{Allowed:true, Reason:"fga_allow"}.
func TestAuthorize_HappyPath(t *testing.T) {
	// Seed the tuple the Authorize handler will check.
	// run belongs to user "u-1"; action is "execute"; resource is "tool:nmap".
	// Authorize canonicalizes the kind-qualified resource to the tenant-less,
	// kind-less component object (gibson#694): user="user:u-1",
	// relation="can_execute", object="component:tool/nmap" — the form tuples are
	// seeded under in the real store.
	az := newFGABackedAuthorizer()
	az.Seed("user:u-1", "can_execute", "component:tool/nmap")

	store := &stubRunAuthzLookup{
		state: &RunAuthzState{
			RunID:    "run-1",
			UserID:   "u-1",
			TenantID: "tenant-alpha",
			Status:   "active",
		},
	}

	svc := newAuthorizeService(store, az)

	resp, err := svc.Authorize(context.Background(), &harnesspb.AuthorizeRequest{
		RunId:    "run-1",
		Action:   "execute",
		Resource: "tool:nmap",
	})

	require.NoError(t, err)
	assert.True(t, resp.GetAllowed(), "expected allowed=true")
	assert.Equal(t, "fga_allow", resp.GetReason())
}

// TestAuthorize_FGADenied verifies that an Authorize call returns Allowed=false
// when the FGA store does NOT hold the relevant tuple (no seed → deny).
//
// Expected result: AuthorizeResponse{Allowed:false, Reason:"not_authorized"}.
func TestAuthorize_FGADenied(t *testing.T) {
	az := newFGABackedAuthorizer()
	// Do NOT seed any tuple → Check returns false → denied.

	store := &stubRunAuthzLookup{
		state: &RunAuthzState{
			RunID:    "run-2",
			UserID:   "u-2",
			TenantID: "tenant-beta",
			Status:   "active",
		},
	}

	svc := newAuthorizeService(store, az)

	resp, err := svc.Authorize(context.Background(), &harnesspb.AuthorizeRequest{
		RunId:    "run-2",
		Action:   "read",
		Resource: "tool:sqlmap",
	})

	require.NoError(t, err)
	assert.False(t, resp.GetAllowed(), "expected allowed=false when FGA tuple absent")
	assert.Equal(t, "not_authorized", resp.GetReason())
}

// TestAuthorize_RunNotFound verifies that when the authzStore returns
// ErrRunNotFound, the handler returns a gRPC NotFound error.
func TestAuthorize_RunNotFound(t *testing.T) {
	az := newFGABackedAuthorizer()
	store := &stubRunAuthzLookup{
		state: nil,
		err:   ErrRunNotFound,
	}

	svc := newAuthorizeService(store, az)

	_, err := svc.Authorize(context.Background(), &harnesspb.AuthorizeRequest{
		RunId:    "unknown-run",
		Action:   "execute",
		Resource: "tool:nmap",
	})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, grpcCode(err),
		"expected gRPC NotFound when run_id not in authz store")
}

// TestAuthorize_MissionInactive verifies that when the mission run has a
// non-"active" status (e.g., "completed"), the handler returns gRPC
// FailedPrecondition without calling FGA at all.
func TestAuthorize_MissionInactive(t *testing.T) {
	az := newFGABackedAuthorizer()
	// Seed the tuple so that if FGA IS called it would return allow.
	// The handler must short-circuit before reaching FGA.
	az.Seed("user:u-3", "can_execute", "component:tool/nmap")

	store := &stubRunAuthzLookup{
		state: &RunAuthzState{
			RunID:    "run-3",
			UserID:   "u-3",
			TenantID: "tenant-gamma",
			Status:   "completed", // not active
		},
	}

	svc := newAuthorizeService(store, az)

	_, err := svc.Authorize(context.Background(), &harnesspb.AuthorizeRequest{
		RunId:    "run-3",
		Action:   "execute",
		Resource: "tool:nmap",
	})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err),
		"expected gRPC FailedPrecondition when mission run is not active")
}

// TestAuthorize_InvalidArguments verifies that missing required fields
// produce gRPC InvalidArgument without consulting the store or FGA.
func TestAuthorize_InvalidArguments(t *testing.T) {
	t.Run("missing run_id", func(t *testing.T) {
		svc := newAuthorizeService(&stubRunAuthzLookup{}, newFGABackedAuthorizer())
		_, err := svc.Authorize(context.Background(), &harnesspb.AuthorizeRequest{
			Action: "execute", Resource: "tool:nmap",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	})

	t.Run("missing action", func(t *testing.T) {
		svc := newAuthorizeService(&stubRunAuthzLookup{}, newFGABackedAuthorizer())
		_, err := svc.Authorize(context.Background(), &harnesspb.AuthorizeRequest{
			RunId: "run-x", Resource: "tool:nmap",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	})

	t.Run("missing resource", func(t *testing.T) {
		svc := newAuthorizeService(&stubRunAuthzLookup{}, newFGABackedAuthorizer())
		_, err := svc.Authorize(context.Background(), &harnesspb.AuthorizeRequest{
			RunId: "run-x", Action: "execute",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	})
}

// TestAuthorize_AuthzStoreError verifies that a generic (non-NotFound) error
// from the authzStore produces gRPC Unavailable.
func TestAuthorize_AuthzStoreError(t *testing.T) {
	az := newFGABackedAuthorizer()
	store := &stubRunAuthzLookup{
		err: errors.New("postgres: connection refused"),
	}

	svc := newAuthorizeService(store, az)

	_, err := svc.Authorize(context.Background(), &harnesspb.AuthorizeRequest{
		RunId:    "run-z",
		Action:   "execute",
		Resource: "tool:nmap",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, grpcCode(err),
		"expected gRPC Unavailable on generic authz store error")
}

// ListUsersOfType is unused by this package's tests. It exists because the
// method is on authz.Authorizer — a gate reached by type assertion was
// silently skipped by every double that did not implement it.
func (a *fgaBackedAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, nil
}
