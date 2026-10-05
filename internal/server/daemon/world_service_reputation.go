// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
)

// GetReputation returns one technique's current track record in one scope
// (ADR-0122, ADR-0129, gibson#267): a read-only projection of the
// technique x environment belief a settled bet updates via
// brain.UpdateReputation. It is built the same way GetCalibration is: a
// WorldBeliefSubstrate bound to this call's own tenant-scoped engine, read
// through brain.ReadReputation rather than aggregated fresh, since a caller
// here only needs one key's current value, not the full tenant-wide
// breakdown GetCalibration gives.
func (s *worldServer) GetReputation(ctx context.Context, req *worldpb.GetReputationRequest) (*worldpb.GetReputationResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	substrate := brain.NewWorldBeliefSubstrate(e)
	// The response carries no measures (gibson#502): no consumer read them.
	// The read stays so a broken substrate is still reported.
	_, _, err = brain.ReadReputation(ctx, e.World.Tenant, req.GetTechnique(), req.GetScopeId(), substrate)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read reputation: %v", err)
	}
	return &worldpb.GetReputationResponse{}, nil
}
