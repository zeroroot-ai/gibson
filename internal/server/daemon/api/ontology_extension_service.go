// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// OntologyExtensionService is the daemon API backing the tenant OWNER's
// review of agent-proposed Taxonomy extensions (ADR-0024 §2, ADR-0033
// decisions 2-3, gibson#392) and, once a proposal is live, the owner's
// "submit upstream" contribution action (ADR-0033 decision 2, gibson#393).
// An agent proposes a new Taxonomy node label or relationship type via
// ProposeOntologyExtension (gibson#391, the agent-facing
// HarnessCallbackService RPC); this service is the other end of that
// pipeline: the tenant owner lists every proposal
// (ListOntologyExtensionProposals), explicitly approves or rejects one, and
// may render an already-live extension as an SDK pack contribution
// (SubmitOntologyExtensionUpstream).
//
// Approval submits an OntologyExtensionApproved event onto the caller's
// tenant brain.Engine — the HITL half of taxonomy.PromotionGate's settlement
// rule (internal/engine/brain/ontology_extension.go). Once a proposal has
// BOTH recurred enough independent times AND been approved, the single-writer
// fold promotes it into live, per-tenant, replayable Cypher structure —
// exactly the tenant extension ADR-0033 describes. Rejection submits an
// OntologyExtensionRejected event, a terminal audit decision that never
// mutates the Taxonomy. SubmitOntologyExtensionUpstream submits no event at
// all — it is a pure render over already-live state
// (internal/engine/brain/ontology_extension_upstream.go).
//
// Mirrors DomainPackService's shape exactly: daemon-local, tenant-scoped,
// backed by the per-tenant brain registry directly — no separate
// tenant-routing adapter/interface needed, because this service (unlike
// HarnessCallbackService) is already per-request tenant-resolving.
type OntologyExtensionService struct {
	tenantv1.UnimplementedOntologyExtensionServiceServer

	registry *brain.Registry
}

// NewOntologyExtensionService constructs the service over the given tenant
// brain registry.
func NewOntologyExtensionService(registry *brain.Registry) *OntologyExtensionService {
	return &OntologyExtensionService{registry: registry}
}

// engine resolves the caller's tenant from the ext-authz context and returns
// its brain engine (created on first use). Cross-tenant access is
// structurally impossible — a caller only ever reaches its own tenant's
// engine (mirrors DomainPackService.engine).
func (s *OntologyExtensionService) engine(ctx context.Context, rpc string) (*brain.Engine, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, status_grpc.Errorf(codes.PermissionDenied, "%s: missing tenant in context", rpc)
	}
	return s.registry.For(tenantID.String()), nil
}

// ontologyProposalKind converts the wire OntologyProposalKind to the
// taxonomy vocabulary Engine.ApproveOntologyExtension/RejectOntologyExtension
// fold against. Mirrors harness's proposeOntologyExtensionKind
// (callback_propose_ontology_extension.go) exactly: an unspecified or
// unrecognized kind names neither of taxonomy's two vocabularies, so it is
// refused as a malformed request rather than silently defaulting to one.
func ontologyProposalKind(k tenantv1.OntologyProposalKind) (taxonomy.ProposalKind, error) {
	switch k {
	case tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL:
		return taxonomy.ProposedNodeLabel, nil
	case tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE:
		return taxonomy.ProposedRelationshipType, nil
	case tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_UNSPECIFIED:
		return 0, errors.New("kind must be specified: a node label or a relationship type")
	default:
		return 0, errors.New("kind is not a recognized ontology proposal kind")
	}
}

// ontologyProposalKindPB converts the taxonomy vocabulary back to its wire
// enum for ListOntologyExtensionProposals' response view.
func ontologyProposalKindPB(k taxonomy.ProposalKind) tenantv1.OntologyProposalKind {
	switch k {
	case taxonomy.ProposedNodeLabel:
		return tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL
	case taxonomy.ProposedRelationshipType:
		return tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE
	default:
		return tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_UNSPECIFIED
	}
}

// ontologyProposalStatusPB converts brain.OntologyProposalStatus to its wire
// enum.
func ontologyProposalStatusPB(s brain.OntologyProposalStatus) tenantv1.OntologyProposalStatus {
	switch s {
	case brain.OntologyProposalPending:
		return tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_PENDING
	case brain.OntologyProposalApproved:
		return tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_APPROVED
	case brain.OntologyProposalRejected:
		return tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_REJECTED
	default:
		return tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_UNSPECIFIED
	}
}

// ListOntologyExtensionProposals returns every ontology/taxonomy extension
// proposal this tenant's agents have made, pending and decided alike, so the
// tenant owner has full visibility into what agents are proposing
// (ADR-0033's "the tenant owner seeing every proposal").
func (s *OntologyExtensionService) ListOntologyExtensionProposals(
	ctx context.Context, _ *tenantv1.ListOntologyExtensionProposalsRequest,
) (*tenantv1.ListOntologyExtensionProposalsResponse, error) {
	e, err := s.engine(ctx, "ListOntologyExtensionProposals")
	if err != nil {
		return nil, err
	}
	snapshot := e.OntologyProposals()
	out := make([]*tenantv1.OntologyExtensionProposal, 0, len(snapshot))
	for _, p := range snapshot {
		out = append(out, &tenantv1.OntologyExtensionProposal{
			Kind:                    ontologyProposalKindPB(p.ProposalKind),
			Label:                   p.Label,
			Recurrence:              int32Count(p.Recurrence),
			LastProposer:            p.LastProposer,
			LastClaim:               p.LastClaim,
			Status:                  ontologyProposalStatusPB(p.Status),
			Reviewer:                p.Reviewer,
			RejectReason:            p.RejectReason,
			Promoted:                p.Promoted,
			PromotedTaxonomyVersion: int32Count(p.PromotedVersion),
		})
	}
	return &tenantv1.ListOntologyExtensionProposalsResponse{Proposals: out}, nil
}

// ApproveOntologyExtensionProposal is the tenant owner's explicit approval of
// a pending proposal (ADR-0033 decision 3). See the .proto's doc for why the
// response is deliberately empty: whether this approval also completed
// settlement is decided by the tenant's single-writer fold, asynchronously —
// call ListOntologyExtensionProposals afterward for the resulting state.
func (s *OntologyExtensionService) ApproveOntologyExtensionProposal(
	ctx context.Context, req *tenantv1.ApproveOntologyExtensionProposalRequest,
) (*tenantv1.ApproveOntologyExtensionProposalResponse, error) {
	e, err := s.engine(ctx, "ApproveOntologyExtensionProposal")
	if err != nil {
		return nil, err
	}
	kind, kindErr := ontologyProposalKind(req.GetKind())
	if kindErr != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, kindErr.Error())
	}
	label := req.GetLabel()
	if label == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "label must not be empty")
	}
	reviewer, ok := auth.ActingUserFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "no acting user in context")
	}
	if err := e.ApproveOntologyExtension(ctx, kind, label, reviewer); err != nil {
		return nil, ontologyDecisionError("ApproveOntologyExtensionProposal", err)
	}
	return &tenantv1.ApproveOntologyExtensionProposalResponse{}, nil
}

// RejectOntologyExtensionProposal is the tenant owner's explicit rejection of
// a pending proposal. Same refusal rules as ApproveOntologyExtensionProposal.
func (s *OntologyExtensionService) RejectOntologyExtensionProposal(
	ctx context.Context, req *tenantv1.RejectOntologyExtensionProposalRequest,
) (*tenantv1.RejectOntologyExtensionProposalResponse, error) {
	e, err := s.engine(ctx, "RejectOntologyExtensionProposal")
	if err != nil {
		return nil, err
	}
	kind, kindErr := ontologyProposalKind(req.GetKind())
	if kindErr != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, kindErr.Error())
	}
	label := req.GetLabel()
	if label == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "label must not be empty")
	}
	reviewer, ok := auth.ActingUserFromContext(ctx)
	if !ok {
		return nil, status_grpc.Error(codes.Unauthenticated, "no acting user in context")
	}
	if err := e.RejectOntologyExtension(ctx, kind, label, reviewer, req.GetReason()); err != nil {
		return nil, ontologyDecisionError("RejectOntologyExtensionProposal", err)
	}
	return &tenantv1.RejectOntologyExtensionProposalResponse{}, nil
}

// SubmitOntologyExtensionUpstream renders a live tenant extension as an SDK
// Domain Pack contribution artifact (ADR-0033 decision 2, gibson#393). See
// the .proto's doc for why opening the resulting PR is a deliberate
// owner/credential hand-off this handler never performs: it returns the
// rendered file content plus ready-to-paste PR text, nothing more.
func (s *OntologyExtensionService) SubmitOntologyExtensionUpstream(
	ctx context.Context, req *tenantv1.SubmitOntologyExtensionUpstreamRequest,
) (*tenantv1.SubmitOntologyExtensionUpstreamResponse, error) {
	e, err := s.engine(ctx, "SubmitOntologyExtensionUpstream")
	if err != nil {
		return nil, err
	}
	kind, kindErr := ontologyProposalKind(req.GetKind())
	if kindErr != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, kindErr.Error())
	}
	label := req.GetLabel()
	if label == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "label must not be empty")
	}
	pack, err := e.SubmitOntologyExtensionUpstream(ctx, kind, label)
	if err != nil {
		return nil, ontologyDecisionError("SubmitOntologyExtensionUpstream", err)
	}
	packJSON, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "SubmitOntologyExtensionUpstream: encode pack fragment: %v", err)
	}
	return &tenantv1.SubmitOntologyExtensionUpstreamResponse{
		PackJson:          packJSON,
		SuggestedFilePath: fmt.Sprintf("packs/%s.json", pack.Name),
		SuggestedPrTitle:  fmt.Sprintf("Add domain pack contribution: %s", pack.Name),
		SuggestedPrBody: fmt.Sprintf(
			"Contributed by tenant %q via submit-upstream (gibson#393, ADR-0033).\n\n"+
				"This adds %s %q as a candidate Domain Pack fragment for platform-owner review. "+
				"See packs/%s.json for the rendered content.",
			pack.Author, kind, label, pack.Name,
		),
	}, nil
}

// ontologyDecisionError maps Engine.ApproveOntologyExtension/RejectOntologyExtension's
// error taxonomy onto gRPC status codes: NotFound for no such proposal,
// FailedPrecondition for an already-decided one, InvalidArgument for an
// identifier that somehow fails ValidIdentifier (defense in depth — see the
// Engine methods' own doc, this should not be reachable via this handler
// since label is already known to have passed the gate at proposal time),
// and Internal for anything else.
func ontologyDecisionError(rpc string, err error) error {
	var notFound *brain.OntologyProposalNotFoundError
	if errors.As(err, &notFound) {
		return status_grpc.Errorf(codes.NotFound, "%s: %v", rpc, err)
	}
	var decided *brain.OntologyProposalAlreadyDecidedError
	if errors.As(err, &decided) {
		return status_grpc.Errorf(codes.FailedPrecondition, "%s: %v", rpc, err)
	}
	var notPromoted *brain.OntologyProposalNotPromotedError
	if errors.As(err, &notPromoted) {
		return status_grpc.Errorf(codes.FailedPrecondition, "%s: %v", rpc, err)
	}
	var invalid *taxonomy.InvalidProposalError
	if errors.As(err, &invalid) {
		return status_grpc.Errorf(codes.InvalidArgument, "%s: %v", rpc, err)
	}
	return status_grpc.Errorf(codes.Internal, "%s: %v", rpc, err)
}
