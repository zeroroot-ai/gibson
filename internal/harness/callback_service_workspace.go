// Package harness — callback_service_workspace.go implements the seven
// HarnessCallbackService.Workspace* RPCs. Each handler resolves the
// calling component's harness via getHarness(), then routes to the
// in-process workspace.Workspace methods that DefaultAgentHarness
// already exposes (implementation.go:2076-2117).
//
// v1 surface limits (matched to the SDK proxy):
//   - WorkspaceReadFile / WorkspaceWriteFile cap at 16 MB per call.
//     Larger files require a future streaming variant.
//   - WorkspaceListFiles caps at 10,000 paths and sets truncated=true
//     when the underlying glob result was larger.
//
// Spec: callback-harness-workspace-rpcs.

package harness

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zero-day-ai/sdk/codegen/workspace"
)

// Per-call payload limits. Aligned with gRPC's default 16 MB max
// message size; 10k paths is a pragmatic cap for the unary
// WorkspaceListFiles surface.
const (
	maxWorkspacePayloadBytes = 16 * 1024 * 1024
	maxWorkspaceListPaths    = 10_000
)

// resolveWorkspace returns the workspace named in `name`, or the
// mission's primary workspace when `name` is empty. Returns
// (nil, nil) on either "no workspace configured" or "no such name"
// — the caller maps to FailedPrecondition / NotFound respectively
// based on whether any workspaces exist on the harness.
func resolveWorkspace(h AgentHarness, name string) (workspace.Workspace, bool) {
	all := h.Workspaces()
	if len(all) == 0 {
		return nil, false
	}
	if name == "" {
		ws := h.Workspace()
		return ws, ws != nil
	}
	ws, ok := all[name]
	return ws, ok
}

// missionHasWorkspace reports whether the mission has any workspace
// at all. Used to distinguish FailedPrecondition (no workspace
// configured for this mission) from NotFound (workspace name unknown).
func missionHasWorkspace(h AgentHarness) bool {
	return len(h.Workspaces()) > 0 || h.Workspace() != nil
}

// mapWorkspaceErr translates an error from a workspace.Workspace
// method call into a gRPC status error. Recognized cases:
//   - file not found (os.IsNotExist) → NotFound
//   - path traversal / invalid path → InvalidArgument
//   - push auth failure (string match on "authentication") → PermissionDenied
//   - everything else → Internal with a generic message
//
// Operator-facing detail (path, file content) is logged at slog.Error
// but NEVER included in the gRPC error message returned to the
// callback agent.
func mapWorkspaceErr(logger *slog.Logger, op string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, fs.ErrNotExist) || os.IsNotExist(err):
		return status.Error(codes.NotFound, "file not found")
	case errors.Is(err, fs.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid path")
	case strings.Contains(err.Error(), "authentication") ||
		strings.Contains(err.Error(), "permission denied"):
		// Push auth failures bubble up as errors containing these
		// substrings; the underlying git client doesn't yet wrap a
		// typed sentinel.
		logger.Error("workspace push: auth failure", slog.String("op", op), slog.String("err", err.Error()))
		return status.Error(codes.PermissionDenied, "remote authentication failed")
	default:
		// Log the full error for operator debugging; return a generic
		// gRPC error so we don't leak workspace paths or content.
		logger.Error("workspace operation failed", slog.String("op", op), slog.String("err", err.Error()))
		return status.Errorf(codes.Internal, "workspace %s failed", op)
	}
}

// validatePath rejects empty or path-traversal-suspicious inputs
// before invoking the underlying workspace method.
func validatePath(p string) error {
	if p == "" {
		return status.Error(codes.InvalidArgument, "path is required")
	}
	if strings.Contains(p, "..") || strings.HasPrefix(p, "/") {
		return status.Error(codes.InvalidArgument, "path must be relative and may not contain '..'")
	}
	return nil
}

// ============================================================================
// Handlers
// ============================================================================

// WorkspaceList returns metadata for every workspace configured for
// the calling component's mission.
func (s *HarnessCallbackService) WorkspaceList(ctx context.Context, req *harnesspb.WorkspaceListRequest) (*harnesspb.WorkspaceListResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}

	all := h.Workspaces()
	out := make([]*harnesspb.WorkspaceInfo, 0, len(all))
	for _, ws := range all {
		if ws == nil {
			continue
		}
		out = append(out, &harnesspb.WorkspaceInfo{
			Name: ws.Name(),
			Path: ws.Path(),
		})
	}
	return &harnesspb.WorkspaceListResponse{Workspaces: out}, nil
}

// WorkspaceGetInfo returns name + path for a single workspace. An
// empty name resolves to the mission's primary workspace.
func (s *HarnessCallbackService) WorkspaceGetInfo(ctx context.Context, req *harnesspb.WorkspaceGetInfoRequest) (*harnesspb.WorkspaceGetInfoResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if !missionHasWorkspace(h) {
		return nil, status.Error(codes.FailedPrecondition, "this mission has no workspace configured")
	}
	ws, ok := resolveWorkspace(h, req.GetName())
	if !ok || ws == nil {
		return nil, status.Errorf(codes.NotFound, "workspace %q not found", req.GetName())
	}
	return &harnesspb.WorkspaceGetInfoResponse{
		Workspace: &harnesspb.WorkspaceInfo{
			Name: ws.Name(),
			Path: ws.Path(),
		},
	}, nil
}

// WorkspaceReadFile reads a file from the named workspace.
func (s *HarnessCallbackService) WorkspaceReadFile(ctx context.Context, req *harnesspb.WorkspaceReadFileRequest) (*harnesspb.WorkspaceReadFileResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if !missionHasWorkspace(h) {
		return nil, status.Error(codes.FailedPrecondition, "this mission has no workspace configured")
	}
	ws, ok := resolveWorkspace(h, req.GetWorkspaceName())
	if !ok || ws == nil {
		return nil, status.Errorf(codes.NotFound, "workspace %q not found", req.GetWorkspaceName())
	}
	if err := validatePath(req.GetPath()); err != nil {
		return nil, err
	}
	content, err := ws.ReadFile(ctx, req.GetPath())
	if err != nil {
		return nil, mapWorkspaceErr(s.logger, "ReadFile", err)
	}
	if len(content) > maxWorkspacePayloadBytes {
		return nil, status.Errorf(codes.ResourceExhausted,
			"file exceeds the %d-byte per-file limit", maxWorkspacePayloadBytes)
	}
	return &harnesspb.WorkspaceReadFileResponse{Content: content}, nil
}

// WorkspaceWriteFile writes content to a file in the named workspace.
// The size cap is enforced BEFORE invoking the underlying WriteFile.
func (s *HarnessCallbackService) WorkspaceWriteFile(ctx context.Context, req *harnesspb.WorkspaceWriteFileRequest) (*harnesspb.WorkspaceWriteFileResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if !missionHasWorkspace(h) {
		return nil, status.Error(codes.FailedPrecondition, "this mission has no workspace configured")
	}
	ws, ok := resolveWorkspace(h, req.GetWorkspaceName())
	if !ok || ws == nil {
		return nil, status.Errorf(codes.NotFound, "workspace %q not found", req.GetWorkspaceName())
	}
	if err := validatePath(req.GetPath()); err != nil {
		return nil, err
	}
	if len(req.GetContent()) > maxWorkspacePayloadBytes {
		return nil, status.Errorf(codes.ResourceExhausted,
			"content exceeds the %d-byte per-file limit", maxWorkspacePayloadBytes)
	}
	if err := ws.WriteFile(ctx, req.GetPath(), req.GetContent()); err != nil {
		return nil, mapWorkspaceErr(s.logger, "WriteFile", err)
	}
	return &harnesspb.WorkspaceWriteFileResponse{}, nil
}

// WorkspaceListFiles enumerates paths matching the given glob.
// Truncates to maxWorkspaceListPaths and sets truncated=true when
// the underlying result was larger.
func (s *HarnessCallbackService) WorkspaceListFiles(ctx context.Context, req *harnesspb.WorkspaceListFilesRequest) (*harnesspb.WorkspaceListFilesResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if !missionHasWorkspace(h) {
		return nil, status.Error(codes.FailedPrecondition, "this mission has no workspace configured")
	}
	ws, ok := resolveWorkspace(h, req.GetWorkspaceName())
	if !ok || ws == nil {
		return nil, status.Errorf(codes.NotFound, "workspace %q not found", req.GetWorkspaceName())
	}
	pattern := req.GetPattern()
	if pattern == "" {
		return nil, status.Error(codes.InvalidArgument, "pattern is required")
	}
	paths, err := ws.ListFiles(ctx, pattern)
	if err != nil {
		return nil, mapWorkspaceErr(s.logger, "ListFiles", err)
	}
	resp := &harnesspb.WorkspaceListFilesResponse{}
	if len(paths) > maxWorkspaceListPaths {
		resp.Paths = paths[:maxWorkspaceListPaths]
		resp.Truncated = true
	} else {
		resp.Paths = paths
	}
	return resp, nil
}

// WorkspaceCommit stages all changes and creates a commit.
func (s *HarnessCallbackService) WorkspaceCommit(ctx context.Context, req *harnesspb.WorkspaceCommitRequest) (*harnesspb.WorkspaceCommitResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if !missionHasWorkspace(h) {
		return nil, status.Error(codes.FailedPrecondition, "this mission has no workspace configured")
	}
	ws, ok := resolveWorkspace(h, req.GetWorkspaceName())
	if !ok || ws == nil {
		return nil, status.Errorf(codes.NotFound, "workspace %q not found", req.GetWorkspaceName())
	}
	if strings.TrimSpace(req.GetMessage()) == "" {
		return nil, status.Error(codes.InvalidArgument, "commit message is required")
	}
	sha, err := ws.Commit(ctx, req.GetMessage())
	if err != nil {
		return nil, mapWorkspaceErr(s.logger, "Commit", err)
	}
	return &harnesspb.WorkspaceCommitResponse{CommitSha: sha}, nil
}

// WorkspacePush pushes committed changes to the workspace's remote.
func (s *HarnessCallbackService) WorkspacePush(ctx context.Context, req *harnesspb.WorkspacePushRequest) (*harnesspb.WorkspacePushResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if !missionHasWorkspace(h) {
		return nil, status.Error(codes.FailedPrecondition, "this mission has no workspace configured")
	}
	ws, ok := resolveWorkspace(h, req.GetWorkspaceName())
	if !ok || ws == nil {
		return nil, status.Errorf(codes.NotFound, "workspace %q not found", req.GetWorkspaceName())
	}
	if err := ws.Push(ctx); err != nil {
		return nil, mapWorkspaceErr(s.logger, "Push", err)
	}
	return &harnesspb.WorkspacePushResponse{}, nil
}

// Compile-time interface check is implicit via the proto-generated
// HarnessCallbackServiceServer interface. The seven new methods are
// mandatory members of that interface; this file would fail to
// compile if any were missing.
var _ = fmt.Sprintf // keep "fmt" usable if future error-formatting is added
