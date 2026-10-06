// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeOntologyDiscoveryEngine is a brain.OntologyDiscoveryEngine test double
// that returns a fixed, non-*taxonomy.InvalidProposalError error, so the
// handler's generic codes.Internal branch (an engine failure OTHER than the
// identifier safety gate) can be exercised independent of a real *brain.Engine,
// which never returns anything else.
type fakeOntologyDiscoveryEngine struct {
	err error
}

func (f *fakeOntologyDiscoveryEngine) ProposeOntologyExtension(context.Context, taxonomy.ProposalKind, string, string, string) error {
	return f.err
}

var _ brain.OntologyDiscoveryEngine = (*fakeOntologyDiscoveryEngine)(nil)

// proposeOntologyExtensionMockHarness is an AgentHarness stub carrying the
// one server-side fact ProposeOntologyExtension reads besides tenant: the
// mission id, mirroring submitProofMockHarness (callback_submit_proof_test.go).
type proposeOntologyExtensionMockHarness struct {
	DefaultAgentHarness
	missionID types.ID
	tenantID  string
}

func (m *proposeOntologyExtensionMockHarness) Mission() MissionContext {
	return MissionContext{ID: m.missionID, TenantID: m.tenantID}
}

func (m *proposeOntologyExtensionMockHarness) Workspace() workspace.Workspace { return nil }
func (m *proposeOntologyExtensionMockHarness) Workspaces() map[string]workspace.Workspace {
	return map[string]workspace.Workspace{}
}

// newProposeOntologyExtensionService wires a HarnessCallbackService for
// ProposeOntologyExtension tests, mirroring newSubmitProofService. engine may
// be nil to exercise the not-wired path.
func newProposeOntologyExtensionService(
	t *testing.T, h *proposeOntologyExtensionMockHarness, agentName string, engine brain.OntologyDiscoveryEngine,
) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	registry.Register(h.missionID.String(), agentName, h)
	var opts []CallbackServiceOption
	if engine != nil {
		opts = append(opts, WithOntologyDiscovery(engine))
	}
	return NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, opts...)
}

func proposeOntologyExtensionRequest(missionID, agentName string, kind harnesspb.OntologyExtensionKind, label, proposer, claim string) *harnesspb.ProposeOntologyExtensionRequest {
	return &harnesspb.ProposeOntologyExtensionRequest{
		Context:  &harnesspb.ContextInfo{MissionId: missionID, AgentName: agentName},
		Kind:     kind,
		Label:    label,
		Proposer: proposer,
		Claim:    claim,
	}
}

// awaitOntologyProposalRecurrence polls e's OntologyProposals for (kind,
// label) until it reaches wantRecurrence, or fails the test —
// Engine.ProposeOntologyExtension folds OntologyExtensionProposed
// asynchronously through the normal single-writer Submit path (ADR-0101),
// mirroring awaitProofSettlements.
func awaitOntologyProposalRecurrence(t *testing.T, e *brain.Engine, label string, wantRecurrence int) []brain.OntologyProposalSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snaps := e.OntologyProposals()
		for _, s := range snaps {
			if s.Label == label && s.Recurrence == wantRecurrence {
				return snaps
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("proposal %q never reached recurrence %d within the deadline", label, wantRecurrence)
	return nil
}

// TestProposeOntologyExtension_NotWired_Unavailable proves
// ProposeOntologyExtension degrades the same way SubmitProof/PlaceBet do when
// its dependency was never wired (staged-wiring default, ADR-0003).
func TestProposeOntologyExtension_NotWired_Unavailable(t *testing.T) {
	h := &proposeOntologyExtensionMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newProposeOntologyExtensionService(t, h, "recon-agent", nil)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.ProposeOntologyExtension(ctx, proposeOntologyExtensionRequest(
		"mission-A", "recon-agent", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, "CustomHost", "recon-agent", "seen it"))
	require.Nil(t, resp)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestProposeOntologyExtension_MissingFields_InvalidArgument proves each
// required field is checked independently of protovalidate (defense in
// depth, mirroring SubmitProof's required-field checks).
func TestProposeOntologyExtension_MissingFields_InvalidArgument(t *testing.T) {
	ctx0, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := brain.NewRegistry(ctx0).For("acme")
	h := &proposeOntologyExtensionMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newProposeOntologyExtensionService(t, h, "recon-agent", engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	tests := []struct {
		name     string
		kind     harnesspb.OntologyExtensionKind
		label    string
		proposer string
		claim    string
	}{
		{"empty label", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, "", "recon-agent", "claim"},
		{"empty proposer", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, "CustomHost", "", "claim"},
		{"empty claim", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, "CustomHost", "recon-agent", ""},
		{"unspecified kind", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_UNSPECIFIED, "CustomHost", "recon-agent", "claim"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.ProposeOntologyExtension(ctx, proposeOntologyExtensionRequest(
				"mission-A", "recon-agent", tt.kind, tt.label, tt.proposer, tt.claim))
			require.Nil(t, resp)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// TestProposeOntologyExtension_InvalidIdentifier_RejectedInBand proves an
// identifier failing taxonomy.ValidIdentifier is refused in-band (Accepted =
// false, RejectionReason set), never as a gRPC error — the RPC itself
// succeeded, the proposal did not, mirroring SubmitProof's
// UnknownPredicate_FailsClosed style.
func TestProposeOntologyExtension_InvalidIdentifier_RejectedInBand(t *testing.T) {
	ctx0, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := brain.NewRegistry(ctx0).For("acme")
	h := &proposeOntologyExtensionMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newProposeOntologyExtensionService(t, h, "recon-agent", engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.ProposeOntologyExtension(ctx, proposeOntologyExtensionRequest(
		"mission-A", "recon-agent", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, "not valid!", "recon-agent", "claim"))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.GetAccepted())
	assert.Empty(t, engine.OntologyProposals(), "an invalid identifier must never be recorded as a sighting")
}

// TestProposeOntologyExtension_ValidProposal_AcceptedAndRecurs proves the
// full accept path: a valid identifier is accepted, folded through the real
// Engine (not a mock), and recorded with recurrence 1 on the first sighting
// and 2 on the second — the ADR-0124 recurrence counting a later
// promotion (gibson#392) will read.
func TestProposeOntologyExtension_ValidProposal_AcceptedAndRecurs(t *testing.T) {
	ctx0, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := brain.NewRegistry(ctx0).For("acme")
	h := &proposeOntologyExtensionMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newProposeOntologyExtensionService(t, h, "recon-agent", engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	req := proposeOntologyExtensionRequest(
		"mission-A", "recon-agent", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, "CustomHost", "recon-agent", "seen it")

	resp, err := svc.ProposeOntologyExtension(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.GetAccepted())
	awaitOntologyProposalRecurrence(t, engine, "CustomHost", 1)

	resp, err = svc.ProposeOntologyExtension(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.GetAccepted())
	awaitOntologyProposalRecurrence(t, engine, "CustomHost", 2)
}

// TestProposeOntologyExtension_RelationshipType_UsesRelationshipVocabulary
// proves a proposed relationship type is folded under Taxonomy's
// relationship-type vocabulary, distinct from node labels (gibson#417's
// applyOntologyExtensionProposed keys recurrence by (kind, label)).
func TestProposeOntologyExtension_RelationshipType_UsesRelationshipVocabulary(t *testing.T) {
	ctx0, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := brain.NewRegistry(ctx0).For("acme")
	h := &proposeOntologyExtensionMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newProposeOntologyExtensionService(t, h, "recon-agent", engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.ProposeOntologyExtension(ctx, proposeOntologyExtensionRequest(
		"mission-A", "recon-agent", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_RELATIONSHIP_TYPE, "EXPOSES", "recon-agent", "seen it"))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.GetAccepted())

	snaps := awaitOntologyProposalRecurrence(t, engine, "EXPOSES", 1)
	require.Len(t, snaps, 1)
	assert.Equal(t, "EXPOSES", snaps[0].Label)
}

// TestProposeOntologyExtension_NilRequest_InvalidArgument proves a nil
// request is refused as a gRPC error, the same nil-request guard every other
// callback in this package uses (mirrors SubmitProof/PlaceBet).
func TestProposeOntologyExtension_NilRequest_InvalidArgument(t *testing.T) {
	ctx0, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := brain.NewRegistry(ctx0).For("acme")
	h := &proposeOntologyExtensionMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newProposeOntologyExtensionService(t, h, "recon-agent", engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.ProposeOntologyExtension(ctx, nil)
	require.Nil(t, resp)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestProposeOntologyExtension_UnregisteredHarness_PropagatesLookupError
// proves a well-formed request for a mission/agent pair with no active
// harness registration fails the same way SubmitProof/PlaceBet do: getHarness
// itself returns the gRPC error, propagated unchanged.
func TestProposeOntologyExtension_UnregisteredHarness_PropagatesLookupError(t *testing.T) {
	ctx0, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := brain.NewRegistry(ctx0).For("acme")
	h := &proposeOntologyExtensionMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newProposeOntologyExtensionService(t, h, "recon-agent", engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.ProposeOntologyExtension(ctx, proposeOntologyExtensionRequest(
		"mission-UNREGISTERED", "recon-agent", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, "CustomHost", "recon-agent", "claim"))
	require.Nil(t, resp)
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestProposeOntologyExtension_EngineFailure_Internal proves an engine error
// OTHER than *taxonomy.InvalidProposalError (the identifier safety gate) is
// reported as codes.Internal, never silently swallowed or mistaken for an
// in-band rejection.
func TestProposeOntologyExtension_EngineFailure_Internal(t *testing.T) {
	h := &proposeOntologyExtensionMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := &fakeOntologyDiscoveryEngine{err: errors.New("boom")}
	svc := newProposeOntologyExtensionService(t, h, "recon-agent", engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.ProposeOntologyExtension(ctx, proposeOntologyExtensionRequest(
		"mission-A", "recon-agent", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, "CustomHost", "recon-agent", "claim"))
	require.Nil(t, resp)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// TestProposeOntologyExtensionKind proves the wire-to-taxonomy kind
// conversion: the two valid kinds map to their taxonomy vocabulary, and both
// the unspecified and an out-of-range value are refused rather than silently
// defaulting to either vocabulary.
func TestProposeOntologyExtensionKind(t *testing.T) {
	tests := []struct {
		name    string
		kind    harnesspb.OntologyExtensionKind
		want    taxonomy.ProposalKind
		wantErr bool
	}{
		{"node label", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_NODE_LABEL, taxonomy.ProposedNodeLabel, false},
		{"relationship type", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_RELATIONSHIP_TYPE, taxonomy.ProposedRelationshipType, false},
		{"unspecified", harnesspb.OntologyExtensionKind_ONTOLOGY_EXTENSION_KIND_UNSPECIFIED, 0, true},
		{"out of range", harnesspb.OntologyExtensionKind(99), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := proposeOntologyExtensionKind(tt.kind)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
