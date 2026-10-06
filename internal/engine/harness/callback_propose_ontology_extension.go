// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

// callback_propose_ontology_extension.go implements ProposeOntologyExtension
// (ADR-0124, ADR-0133, gibson#391, epic #376): an agent
// proposes a new Taxonomy node label or relationship type discovered at
// runtime. The agent proposes; it never promotes. Promotion into a live
// tenant extension is a separate, later, explicit tenant-owner decision
// (gibson#392, not built here), and submitting a promoted extension upstream
// as a catalog contribution is a further step still (gibson#393, not built
// here either).
//
// This is the agent-facing wire-up gibson#417 (ontology_extension.go)
// deliberately stopped short of: that slice built the per-tenant
// OntologyExtensionProposed event, its fold (ValidIdentifier fail-closed
// before Submit, PromotionGate.Observe counting recurrence on apply), and
// the OntologyDiscoveryEngine tenant-routing seam a "future RPC handler"
// wires against — mirroring ProofSettlementEngine's seam pattern for
// gibson#389's SubmitProof. This file IS that future handler: a thin
// translation from the wire request onto Engine.ProposeOntologyExtension,
// no further engine-layer work needed, exactly as gibson#417's PR predicted.
//
// Structural field checks (nil request, empty label/proposer/claim, an
// unspecified or unrecognized kind) are refused as gRPC errors — the same
// split every other callback in this package uses (mirrors SubmitProof's
// hypothesis_id/technique/predicate_name checks, defense in depth
// independent of protovalidate). The ValidIdentifier safety gate itself is
// a DOMAIN decision, not a malformed-request one: an invalid identifier is
// reported in-band via ProposeOntologyExtensionResponse.Accepted=false and
// RejectionReason, the same way SubmitProof reports an unresolvable
// predicate in-band rather than as a gRPC error — the RPC itself succeeded,
// the proposal did not.

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// ProposeOntologyExtension implements
// harnesspb.HarnessCallbackServiceServer.ProposeOntologyExtension (ADR-0124,
// ADR-0133, gibson#391): an agent proposes a new Taxonomy node
// label or relationship type discovered at runtime. The daemon checks the
// identifier against taxonomy.ValidIdentifier (through
// Engine.ProposeOntologyExtension) before recording it as a per-tenant
// sighting, and PromotionGate.Observe counts recurrence toward a later,
// explicit tenant-owner approval (gibson#392) — this call never promotes and
// never blocks on that approval.
func (s *HarnessCallbackService) ProposeOntologyExtension(
	ctx context.Context, req *harnesspb.ProposeOntologyExtensionRequest,
) (*harnesspb.ProposeOntologyExtensionResponse, error) {
	if s.ontologyDiscovery == nil {
		return nil, status.Error(codes.Unavailable, "ProposeOntologyExtension: ontology discovery is not wired on this daemon")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing propose ontology extension request")
	}

	label := req.GetLabel()
	proposer := req.GetProposer()
	claim := req.GetClaim()
	if label == "" {
		return nil, status.Error(codes.InvalidArgument, "label must not be empty")
	}
	if proposer == "" {
		return nil, status.Error(codes.InvalidArgument, "proposer must not be empty")
	}
	if claim == "" {
		return nil, status.Error(codes.InvalidArgument, "claim must not be empty")
	}

	kind, kindErr := proposeOntologyExtensionKind(req.GetKind())
	if kindErr != nil {
		return nil, status.Error(codes.InvalidArgument, kindErr.Error())
	}

	if _, err := s.getHarness(ctx, req.GetContext()); err != nil {
		return nil, err
	}

	if err := s.ontologyDiscovery.ProposeOntologyExtension(ctx, kind, label, proposer, claim); err != nil {
		var invalid *taxonomy.InvalidProposalError
		if errors.As(err, &invalid) {
			return &harnesspb.ProposeOntologyExtensionResponse{Accepted: false}, nil
		}
		return nil, status.Errorf(codes.Internal, "ProposeOntologyExtension: %v", err)
	}

	return &harnesspb.ProposeOntologyExtensionResponse{Accepted: true}, nil
}

// proposeOntologyExtensionKind converts the wire OntologyExtensionKind to the
// taxonomy vocabulary Engine.ProposeOntologyExtension folds against. Unlike
// an evidence-type conversion (which can degrade an
// unrecognized value, because the predicate, not the conversion, decides
// relevance), kind SELECTS one of Taxonomy's two vocabularies (node label vs
// relationship type): an unspecified or unrecognized kind names neither, so
// it is refused as a malformed request rather than silently defaulting to
// one.
func proposeOntologyExtensionKind(k harnesspb.OntologyExtensionKind) (taxonomy.ProposalKind, error) {
	switch k {
	case harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL:
		return taxonomy.ProposedNodeLabel, nil
	case harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_RELATIONSHIP_TYPE:
		return taxonomy.ProposedRelationshipType, nil
	case harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_UNSPECIFIED:
		return 0, errors.New("kind must be specified: a node label or a relationship type")
	default:
		return 0, errors.New("kind is not a recognized ontology extension kind")
	}
}
