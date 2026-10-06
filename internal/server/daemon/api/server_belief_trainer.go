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
	"fmt"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain/fit"
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
		rows  []fit.Row
		edges map[string]brain.EdgeOutcomeCount
	)
	engine.ReadWorld(func(w *brain.World) {
		// The trainer fits only the variables of its base model.
		rows = braintrain.RowsFromWorld(w)
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

// beliefVersionsTotal counts the versions that the quality gate accepted and
// rejected, for each tenant (gibson#789).
var beliefVersionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gibson_belief_artifact_versions_total",
		Help: "Belief artifact versions that the quality gate decided, labeled by tenant and verdict (accepted or rejected).",
	},
	[]string{"tenant", "verdict"},
)

// betScoreTolerance absorbs the rounding of two equal scores, so a candidate
// that scores the same as the current version counts as not worse.
const betScoreTolerance = 1e-12

// StoreBeliefArtifact stores the two artifacts of one fit as the next version
// of one tenant, and the quality gate decides it (ADR-0106, gibson#789). The
// gate scores the new version and the current version on the settled bets of
// the tenant (brain.BrierOnBets). The new version becomes current only when
// its score is not worse. Otherwise it stays, marked rejected. A tenant with
// no current version compares with the embedded base model, which the
// runtime uses then.
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
	if s.beliefWorlds == nil {
		return nil, status.Error(codes.Unavailable, "the brain is not configured on this daemon")
	}
	if len(req.GetBeliefModel()) == 0 || len(req.GetEdgePosteriors()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "belief_model and edge_posteriors are required")
	}
	candidate, err := parseBeliefModel(req.GetBeliefModel())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "belief_model: %v", err)
	}
	if _, err := fit.ParseEdgePosteriorArtifact(req.GetEdgePosteriors()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "edge_posteriors: %v", err)
	}
	engine := s.beliefWorlds.For(req.GetTenantId())
	if err := engine.Err(); err != nil {
		return nil, status.Errorf(codes.Unavailable, "the World of the tenant is not available: %v", err)
	}
	var cases []brain.BetCase
	engine.ReadWorld(func(w *brain.World) { cases = w.SettledBetCases() })

	store := beliefartifact.NewStore(db)
	version, err := store.Put(ctx, req.GetTenantId(), req.GetBeliefModel(), req.GetEdgePosteriors())
	switch {
	case errors.Is(err, beliefartifact.ErrNotJSONObject):
		return nil, status.Errorf(codes.InvalidArgument, "store belief artifact: %v", err)
	case err != nil:
		return nil, status.Errorf(codes.Internal, "store belief artifact: %v", err)
	}

	current, err := currentBeliefModel(ctx, store, req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the current belief version: %v", err)
	}
	verdict := judgeBeliefVersion(candidate, current, cases)
	if err := store.Decide(ctx, req.GetTenantId(), version, verdict); err != nil {
		return nil, status.Errorf(codes.Internal, "record the quality gate verdict: %v", err)
	}
	label := "rejected"
	if verdict.Accepted {
		label = "accepted"
	}
	beliefVersionsTotal.WithLabelValues(req.GetTenantId(), label).Inc()
	return &daemonoperatorv1.StoreBeliefArtifactResponse{Version: version}, nil
}

// judgeBeliefVersion scores both models on the settled bets. The candidate is
// accepted when its score is not worse than the score of the current model.
func judgeBeliefVersion(candidate, current *beliefvi.BeliefModel, cases []brain.BetCase) beliefartifact.Verdict {
	cand, n := brain.BrierOnBets(candidate, cases)
	cur, _ := brain.BrierOnBets(current, cases)
	return beliefartifact.Verdict{
		Accepted:       cand <= cur+betScoreTolerance,
		BrierCandidate: cand,
		BrierCurrent:   cur,
		ScoredBets:     n,
	}
}

// currentBeliefModel returns the model of the current version of the tenant,
// or the embedded base model when the tenant has no current version.
func currentBeliefModel(ctx context.Context, store *beliefartifact.Store, tenant string) (*beliefvi.BeliefModel, error) {
	raw, _, found, err := store.Current(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("read the current version: %w", err)
	}
	if !found {
		base, err := beliefvi.DefaultArtifact()
		if err != nil {
			return nil, fmt.Errorf("load the base model: %w", err)
		}
		m, err := beliefvi.NewBeliefModel(base)
		if err != nil {
			return nil, fmt.Errorf("build the base model: %w", err)
		}
		return m, nil
	}
	return parseBeliefModel(raw)
}

// parseBeliefModel parses a belief model artifact and builds its model.
func parseBeliefModel(raw []byte) (*beliefvi.BeliefModel, error) {
	art, err := beliefvi.ParseModelArtifact(raw)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	m, err := beliefvi.NewBeliefModel(art)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	return m, nil
}
