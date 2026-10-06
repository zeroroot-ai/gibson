// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/cueruntime"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// checkCueSourceCompilesTo refuses a CUE source that does not compile to the
// definition of the same request (ADR-0035). The daemon stores both, and the
// editor shows the source again. A source that compiles to a different
// definition would show a reader one mission while the platform runs
// another, so a review of the source would not be a review of what runs.
//
// An empty source is accepted: the request then stores no source.
func checkCueSourceCompilesTo(ctx context.Context, cueSource string, def *missionpb.MissionDefinition) error {
	if cueSource == "" {
		return nil
	}
	compiled, err := cueruntime.Export(ctx, cueSource)
	if err != nil {
		return status_grpc.Errorf(codes.InvalidArgument, "cue_source does not compile: %v", err)
	}
	if !proto.Equal(compiled, def) {
		return status_grpc.Error(codes.InvalidArgument,
			"cue_source does not compile to the definition of this request: send the definition that the source compiles to")
	}
	return nil
}
