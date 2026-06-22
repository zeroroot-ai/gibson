// Package api — admin_server.go
//
// DaemonService CUE language-service RPCs: ValidateMissionCUE,
// CompleteMissionCUE, HoverMissionCUE.
//
// These methods were previously on DaemonAdminService (platform-sdk). ADR-0037
// moves them onto DaemonService (OSS SDK) so customers can use the CUE editor
// without needing internal admin credentials. The DaemonAdminServer wrapper
// is deleted; the business logic is wired directly onto DaemonServer.
//
// Refs: sdk#205, platform-sdk#31, gibson#342.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/cueruntime"
)

// ValidateMissionCUE compiles the CUE source via cueruntime.Validate and
// returns structured diagnostics. A nil or empty Diagnostics slice means the
// source is valid against the mission schema. On success, CompiledDefinition
// is populated so callers can pass it directly to CreateMissionDefinition.
func (s *DaemonServer) ValidateMissionCUE(ctx context.Context, req *daemonpb.ValidateMissionCUERequest) (*daemonpb.ValidateMissionCUEResponse, error) {
	diags, err := cueruntime.Validate(ctx, req.GetCueSource())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "ValidateMissionCUE: engine error: %v", err)
	}
	resp := &daemonpb.ValidateMissionCUEResponse{}
	for _, d := range diags {
		resp.Diagnostics = append(resp.Diagnostics, &daemonpb.CUEDiagnostic{
			Line:     d.Line,
			Col:      d.Col,
			Message:  d.Message,
			Severity: d.Severity,
		})
	}
	if len(resp.Diagnostics) == 0 {
		def, exportErr := cueruntime.Export(ctx, req.GetCueSource())
		if exportErr != nil {
			resp.Diagnostics = append(resp.Diagnostics, &daemonpb.CUEDiagnostic{
				Line:     1,
				Col:      1,
				Message:  exportErr.Error(),
				Severity: "error",
			})
		} else {
			resp.CompiledDefinition = def
		}
	}
	return resp, nil
}

// CompleteMissionCUE returns completion items at the given cursor position by
// delegating to cueruntime.Complete. Line and col are 1-based.
func (s *DaemonServer) CompleteMissionCUE(ctx context.Context, req *daemonpb.CompleteMissionCUERequest) (*daemonpb.CompleteMissionCUEResponse, error) {
	items, err := cueruntime.Complete(ctx, req.GetCueSource(), req.GetLine(), req.GetCol())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "CompleteMissionCUE: engine error: %v", err)
	}
	resp := &daemonpb.CompleteMissionCUEResponse{}
	for _, item := range items {
		resp.Items = append(resp.Items, &daemonpb.CUECompletionItem{
			Label:         item.Label,
			Detail:        item.Detail,
			Documentation: item.Documentation,
			Kind:          item.Kind,
		})
	}
	return resp, nil
}

// HoverMissionCUE returns Markdown hover documentation for the symbol at the
// given cursor position by delegating to cueruntime.Hover. Line and col are
// 1-based. Returns an empty Markdown string when no documentation exists at
// the cursor position.
func (s *DaemonServer) HoverMissionCUE(ctx context.Context, req *daemonpb.HoverMissionCUERequest) (*daemonpb.HoverMissionCUEResponse, error) {
	markdown, err := cueruntime.Hover(ctx, req.GetCueSource(), req.GetLine(), req.GetCol())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "HoverMissionCUE: engine error: %v", err)
	}
	return &daemonpb.HoverMissionCUEResponse{
		Markdown: markdown,
	}, nil
}
