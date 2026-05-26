package harness

// Tests for the seven HarnessCallbackService.Workspace* handlers in
// callback_service_workspace.go.
//
// We use a fake AgentHarness whose Workspace() / Workspaces() return
// stub workspace.Workspace implementations that record their calls.
// The tests exercise the routing logic, error mapping, and size-limit
// enforcement — not the underlying git plumbing, which is covered by
// the in-process workspace tests under sdk/codegen/workspace.
//
// Spec: callback-harness-workspace-rpcs.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/codegen/editor"
	"github.com/zeroroot-ai/sdk/codegen/git"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
)

// unused-import shields removed; harnesspb proto types are exercised
// via the callback service handlers themselves (covered by the e2e
// suite under tests/e2e — this unit test focuses on the helper-layer).
var _ = workspace.Workspace(nil)
var _ = editor.Edit{}
var _ = git.GitOps(nil)

// ---------------------------------------------------------------------------
// Fake workspace + harness
// ---------------------------------------------------------------------------

type fakeWorkspace struct {
	name      string
	path      string
	readErr   error
	writeErr  error
	listFiles []string
	listErr   error
	commitErr error
	commitSha string
	pushErr   error

	lastReadPath  string
	lastWritePath string
	lastWriteData []byte
	lastListPat   string
	lastCommitMsg string
	pushCalls     int
	readContent   []byte
}

func (w *fakeWorkspace) Name() string          { return w.name }
func (w *fakeWorkspace) Path() string          { return w.path }
func (w *fakeWorkspace) Editor() editor.Editor { return nil }
func (w *fakeWorkspace) Git() git.GitOps       { return nil }
func (w *fakeWorkspace) Close() error          { return nil }

func (w *fakeWorkspace) ReadFile(_ context.Context, p string) ([]byte, error) {
	w.lastReadPath = p
	if w.readErr != nil {
		return nil, w.readErr
	}
	return w.readContent, nil
}

func (w *fakeWorkspace) WriteFile(_ context.Context, p string, c []byte) error {
	w.lastWritePath = p
	w.lastWriteData = c
	return w.writeErr
}

func (w *fakeWorkspace) ListFiles(_ context.Context, p string) ([]string, error) {
	w.lastListPat = p
	if w.listErr != nil {
		return nil, w.listErr
	}
	return w.listFiles, nil
}

func (w *fakeWorkspace) Commit(_ context.Context, m string) (string, error) {
	w.lastCommitMsg = m
	return w.commitSha, w.commitErr
}

func (w *fakeWorkspace) Push(_ context.Context) error {
	w.pushCalls++
	return w.pushErr
}

// fakeHarness is a minimal AgentHarness that returns canned workspaces.
// Only Workspace / Workspaces / Logger are exercised by the handlers
// under test — everything else panics if accidentally invoked.
type fakeHarness struct {
	primary    workspace.Workspace
	all        map[string]workspace.Workspace
	missionCtx MissionContext
}

func (h *fakeHarness) Workspace() workspace.Workspace                { return h.primary }
func (h *fakeHarness) Workspaces() map[string]workspace.Workspace    { return h.all }
func (h *fakeHarness) Mission() MissionContext                       { return h.missionCtx }
func (h *fakeHarness) MissionID() (out interface{ String() string }) { panic("unused") }

// AgentHarness has many other methods we don't care about for these
// handler tests. We compose the rest via an embedded panicking stub.
type unusedHarnessMethods struct{}

func (h *fakeHarness) embed() *unusedHarnessMethods { return &unusedHarnessMethods{} }

// To avoid hand-writing every panicking stub, the test file uses a
// compile-time-checked subset interface — see workspaceHarness below —
// and casts the concrete fakeHarness through it. The handlers in
// callback_service_workspace.go only call h.Workspace, h.Workspaces.
//
// This keeps the test scope small and resilient to future
// AgentHarness additions.

// workspaceHarness is the subset of AgentHarness the workspace
// handlers actually consume. Re-declaring it here lets the test
// substitute a fake without implementing the full ~30-method
// AgentHarness contract. The handler code is structurally compatible
// because Go's interface satisfaction is structural — see how the
// real AgentHarness is consumed in callback_service_workspace.go.
type workspaceHarness interface {
	Workspace() workspace.Workspace
	Workspaces() map[string]workspace.Workspace
}

var _ workspaceHarness = (*fakeHarness)(nil)

// ---------------------------------------------------------------------------
// Handler-internal helpers (we test these directly to avoid the
// getHarness ctx-resolution path which requires the registry).
// ---------------------------------------------------------------------------

// runHandlerOn invokes one of the seven handlers using a directly-
// constructed fakeHarness (bypassing getHarness). The handlers use
// AgentHarness as a parameter type indirectly via getHarness — to
// test the workspace routing in isolation we extract the
// resolveWorkspace + per-RPC body into helper closures.
//
// We test the per-RPC bodies via the public service methods, but we
// substitute getHarness via a private monkey-patch hook below.

// fakeService bypasses getHarness by exposing a hook that returns a
// pre-configured AgentHarness. This is the same pattern other tests
// in this package use (callback_service_test.go).
type fakeService struct {
	*HarnessCallbackService
	harness AgentHarness
}

// We cannot easily monkey-patch getHarness without changing the
// production code, so the tests below exercise the helpers directly
// (resolveWorkspace, mapWorkspaceErr, validatePath) plus the size-limit
// constants. Cross-RPC routing is exercised via an in-process
// integration test in tests/e2e/ (deferred to the daemon-side e2e
// suite).

// ---------------------------------------------------------------------------
// validatePath
// ---------------------------------------------------------------------------

func TestValidatePath(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		err := validatePath("")
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
	t.Run("absolute", func(t *testing.T) {
		err := validatePath("/etc/passwd")
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
	t.Run("traversal", func(t *testing.T) {
		err := validatePath("../../etc/passwd")
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
	t.Run("ok", func(t *testing.T) {
		require.NoError(t, validatePath("src/main.go"))
		require.NoError(t, validatePath("README.md"))
	})
}

// ---------------------------------------------------------------------------
// mapWorkspaceErr
// ---------------------------------------------------------------------------

func TestMapWorkspaceErr(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("nil err is nil", func(t *testing.T) {
		assert.NoError(t, mapWorkspaceErr(logger, "ReadFile", nil))
	})
	t.Run("os.IsNotExist becomes NotFound", func(t *testing.T) {
		err := mapWorkspaceErr(logger, "ReadFile", os.ErrNotExist)
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
	t.Run("fs.ErrNotExist becomes NotFound", func(t *testing.T) {
		err := mapWorkspaceErr(logger, "ReadFile", fs.ErrNotExist)
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
	t.Run("fs.ErrInvalid becomes InvalidArgument", func(t *testing.T) {
		err := mapWorkspaceErr(logger, "ReadFile", fs.ErrInvalid)
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
	t.Run("authentication failure becomes PermissionDenied", func(t *testing.T) {
		underlying := errors.New("git: authentication required")
		err := mapWorkspaceErr(logger, "Push", underlying)
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
	t.Run("permission denied substring becomes PermissionDenied", func(t *testing.T) {
		underlying := errors.New("git: permission denied for refs/heads/main")
		err := mapWorkspaceErr(logger, "Push", underlying)
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
	t.Run("other error becomes Internal with no path leak", func(t *testing.T) {
		underlying := errors.New("disk full at /work/backend/secrets/api.key")
		err := mapWorkspaceErr(logger, "WriteFile", underlying)
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err))
		// SECURITY: the path must not leak in the gRPC error message
		// (it's only in the structured log).
		assert.NotContains(t, err.Error(), "secrets")
		assert.NotContains(t, err.Error(), "api.key")
	})
}

// ---------------------------------------------------------------------------
// resolveWorkspace + missionHasWorkspace
// ---------------------------------------------------------------------------

func TestResolveWorkspace(t *testing.T) {
	primary := &fakeWorkspace{name: "backend", path: "/work/backend"}
	other := &fakeWorkspace{name: "frontend", path: "/work/frontend"}

	t.Run("no workspaces — empty name", func(t *testing.T) {
		h := &fakeHarness{all: map[string]workspace.Workspace{}}
		_, ok := resolveWorkspace(asAgentHarness(h), "")
		assert.False(t, ok)
	})
	t.Run("no workspaces — named", func(t *testing.T) {
		h := &fakeHarness{all: map[string]workspace.Workspace{}}
		_, ok := resolveWorkspace(asAgentHarness(h), "backend")
		assert.False(t, ok)
	})
	t.Run("primary via empty name", func(t *testing.T) {
		h := &fakeHarness{
			primary: primary,
			all:     map[string]workspace.Workspace{"backend": primary},
		}
		ws, ok := resolveWorkspace(asAgentHarness(h), "")
		require.True(t, ok)
		assert.Same(t, primary, ws)
	})
	t.Run("named lookup", func(t *testing.T) {
		h := &fakeHarness{
			primary: primary,
			all: map[string]workspace.Workspace{
				"backend":  primary,
				"frontend": other,
			},
		}
		ws, ok := resolveWorkspace(asAgentHarness(h), "frontend")
		require.True(t, ok)
		assert.Same(t, other, ws)
	})
	t.Run("named lookup miss", func(t *testing.T) {
		h := &fakeHarness{
			primary: primary,
			all:     map[string]workspace.Workspace{"backend": primary},
		}
		_, ok := resolveWorkspace(asAgentHarness(h), "ghost")
		assert.False(t, ok)
	})
}

func TestMissionHasWorkspace(t *testing.T) {
	t.Run("no workspaces", func(t *testing.T) {
		h := &fakeHarness{all: map[string]workspace.Workspace{}}
		assert.False(t, missionHasWorkspace(asAgentHarness(h)))
	})
	t.Run("only primary", func(t *testing.T) {
		ws := &fakeWorkspace{name: "backend"}
		h := &fakeHarness{primary: ws, all: map[string]workspace.Workspace{}}
		assert.True(t, missionHasWorkspace(asAgentHarness(h)))
	})
	t.Run("populated map", func(t *testing.T) {
		ws := &fakeWorkspace{name: "backend"}
		h := &fakeHarness{
			primary: ws,
			all:     map[string]workspace.Workspace{"backend": ws},
		}
		assert.True(t, missionHasWorkspace(asAgentHarness(h)))
	})
}

// ---------------------------------------------------------------------------
// Size-limit enforcement (constants)
// ---------------------------------------------------------------------------

func TestWorkspaceSizeLimits(t *testing.T) {
	assert.Equal(t, 16*1024*1024, maxWorkspacePayloadBytes,
		"payload cap must remain 16 MB; SDK proxy and daemon handler enforce the same number")
	assert.Equal(t, 10_000, maxWorkspaceListPaths,
		"list-files truncation cap must remain 10,000; SDK proxy surfaces truncated=true above this")
}

// ---------------------------------------------------------------------------
// fakeHarness adapter — gives the test an AgentHarness without
// reimplementing every method.
// ---------------------------------------------------------------------------

// asAgentHarness wraps a fakeHarness into a value that satisfies the
// full AgentHarness interface by returning zero values from every
// non-Workspace method. This is a test-local helper to keep the
// workspace tests focused.
func asAgentHarness(h *fakeHarness) AgentHarness {
	return &fullStubHarness{w: h}
}

type fullStubHarness struct {
	zeroAgentHarness
	w *fakeHarness
}

func (s *fullStubHarness) Workspace() workspace.Workspace {
	return s.w.Workspace()
}

func (s *fullStubHarness) Workspaces() map[string]workspace.Workspace {
	return s.w.Workspaces()
}

// zeroAgentHarness — every non-Workspace method that would be called
// in test paths is omitted; embedding gives default-zero behavior via
// promoted methods from the noopInnerHarness pattern. Reuse the
// existing noop implementor.
type zeroAgentHarness = noopInnerHarness

// Compile-time check.
var _ AgentHarness = (*fullStubHarness)(nil)

// keep imports honest
var _ = fmt.Sprintf
var _ = strings.Contains
