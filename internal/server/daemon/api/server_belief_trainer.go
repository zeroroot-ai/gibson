// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_belief_trainer.go
//
// The two RPCs of the belief trainer (ADR-0106, gibson#788). The trainer pod
// of a tenant reads the training data of its tenant and stores a new artifact
// version through the daemon. It holds no database credential and opens no
// data store.
//
// Each handler reads the TLS peer certificate of the connection and serves
// only the trainer identity of the tenant in the request,
// spiffe://<trust domain>/trainer/<tenant_id>. A trainer of tenant A gets
// PermissionDenied for tenant B, and a call through the edge (TLS peer
// Envoy) is refused.
package api

import (
	"context"
	"errors"
	"sort"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain"
	"github.com/zeroroot-ai/gibson/internal/platform/beliefartifact"
	"github.com/zeroroot-ai/gibson/internal/platform/trainerid"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// BeliefWorlds gives the brain engine of a tenant. *brain.Registry satisfies
// it.
type BeliefWorlds interface {
	For(tenant string) *brain.Engine
}

// WithBeliefTrainer wires the two trainer RPCs: the brain engines and the
// trust domain of the install. Unwired, the RPCs answer Unavailable.
func (s *DaemonServer) WithBeliefTrainer(worlds BeliefWorlds, td spiffeid.TrustDomain) *DaemonServer {
	s.beliefWorlds = worlds
	s.trainerTrustDomain = td
	return s
}

// errNotTheTrainer is the answer to each caller that is not the trainer of
// the tenant in the request. It names no detail of the peer.
var errNotTheTrainer = status.Error(codes.PermissionDenied,
	"the belief trainer RPCs are served to the trainer of the requested tenant only")

// requireTrainerOf refuses each caller that is not the trainer of tenant.
func (s *DaemonServer) requireTrainerOf(ctx context.Context, tenant string) error {
	if s.trainerTrustDomain.IsZero() {
		return status.Error(codes.Unavailable, "the belief trainer RPCs are not configured on this daemon")
	}
	if tenant == "" {
		return status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	got, ok := trainerid.TenantOfString(peerSPIFFEID(ctx), s.trainerTrustDomain)
	if !ok || got != tenant {
		return errNotTheTrainer
	}
	return nil
}

// GetBeliefTrainingData returns the training rows and the edge outcome
// counts of the World of one tenant.
//
// gibsoncheck:allow tenant-from-request — the TLS peer must be the trainer of
// exactly this tenant, checked in requireTrainerOf (gibson#788).
func (s *DaemonServer) GetBeliefTrainingData(
	ctx context.Context, req *daemonoperatorv1.GetBeliefTrainingDataRequest,
) (*daemonoperatorv1.GetBeliefTrainingDataResponse, error) {
	if err := s.requireTrainerOf(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	if s.beliefWorlds == nil {
		return nil, status.Error(codes.Unavailable, "the brain is not configured on this daemon")
	}
	engine := s.beliefWorlds.For(req.GetTenantId())
	if err := engine.Err(); err != nil {
		return nil, status.Errorf(codes.Unavailable, "the World of the tenant is not available: %v", err)
	}
	var (
		rows  []braintrain.Row
		edges map[string]brain.EdgeOutcomeCount
	)
	engine.ReadWorld(func(w *brain.World) {
		// The trainer restricts the rows to the variables of its base model.
		rows = braintrain.RowsFromWorld(w, nil)
		edges = w.EdgeOutcomeCounts()
	})
	resp := &daemonoperatorv1.GetBeliefTrainingDataResponse{
		Rows:         make([]*daemonoperatorv1.BeliefTrainingRow, 0, len(rows)),
		EdgeOutcomes: make([]*daemonoperatorv1.EdgeOutcomeCount, 0, len(edges)),
	}
	for _, r := range rows {
		resp.Rows = append(resp.Rows, &daemonoperatorv1.BeliefTrainingRow{Vars: r})
	}
	types := make([]string, 0, len(edges))
	for t := range edges {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		resp.EdgeOutcomes = append(resp.EdgeOutcomes, &daemonoperatorv1.EdgeOutcomeCount{
			EdgeType: t, Alpha: edges[t].Alpha, Beta: edges[t].Beta,
		})
	}
	return resp, nil
}

// StoreBeliefArtifact stores the two artifacts of one fit as the next version
// of one tenant, with the state candidate.
//
// gibsoncheck:allow tenant-from-request — the TLS peer must be the trainer of
// exactly this tenant, checked in requireTrainerOf (gibson#788).
func (s *DaemonServer) StoreBeliefArtifact(
	ctx context.Context, req *daemonoperatorv1.StoreBeliefArtifactRequest,
) (*daemonoperatorv1.StoreBeliefArtifactResponse, error) {
	if err := s.requireTrainerOf(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if len(req.GetBeliefModel()) == 0 || len(req.GetEdgePosteriors()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "belief_model and edge_posteriors are required")
	}
	version, err := beliefartifact.NewStore(db).Put(ctx, req.GetTenantId(), req.GetBeliefModel(), req.GetEdgePosteriors())
	switch {
	case errors.Is(err, beliefartifact.ErrNotJSONObject):
		return nil, status.Errorf(codes.InvalidArgument, "store belief artifact: %v", err)
	case err != nil:
		return nil, status.Errorf(codes.Internal, "store belief artifact: %v", err)
	}
	return &daemonoperatorv1.StoreBeliefArtifactResponse{Version: version}, nil
}
