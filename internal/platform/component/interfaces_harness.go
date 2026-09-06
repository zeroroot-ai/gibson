// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// interfaces_harness.go defines narrow dependency interfaces for the harness
// proxy RPCs added to ComponentServiceServer. Each interface is injected via
// a With*() method on ComponentServiceServer and is nil-safe: handlers check
// for nil and return codes.Unimplemented when the dependency is not wired.

import (
	"context"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// OntologyReasoner is the narrow interface of ontology.Reasoner that the
// ComponentService needs. It matches sdk/graphrag.Reasoner so the concrete
// ontology.Reasoner can be injected directly without an adapter.
//
// The full sdk/graphrag.Reasoner interface is used rather than a subset because
// callers (RegisterComponent, future ontology-extension RPCs) may eventually
// call any of the expansion methods. Keeping the interface identical to the SDK
// type avoids drift and makes mock generation straightforward.
type OntologyReasoner interface {
	// RegisterExtension adds ontology triples contributed by an enrolling
	// component. Called during RegisterComponent when the request carries an
	// OntologyExtension payload.
	RegisterExtension(name string, ext sdkgraphrag.OntologyExtension) error

	// UnregisterExtension removes the extension previously registered under name.
	// Called when the component is deregistered or the daemon shuts down.
	UnregisterExtension(name string) error
}

// GraphRAGQuerier reads the knowledge graph for remote agents. It is read-only:
// ADR-0012 makes the projector the sole writer, and sdk#451 took the write RPC
// off the wire, so there is no StoreNode here (gibson#1322).
// May be nil on ComponentServiceServer; GraphRAG RPCs return Unimplemented when nil.
type GraphRAGQuerier interface {
	// QueryNodes searches the knowledge graph.
	QueryNodes(ctx context.Context, tenant string, query *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error)
	// FindSimilarAttacks returns JSON-encoded []graphrag.AttackPattern.
	FindSimilarAttacks(ctx context.Context, tenant, content string, topK int) ([]byte, error)
	// GetAttackChains returns JSON-encoded []graphrag.AttackChain.
	GetAttackChains(ctx context.Context, tenant, techniqueID string, maxDepth int) ([]byte, error)
	// FindSimilarFindings returns JSON-encoded []graphrag.FindingNode.
	FindSimilarFindings(ctx context.Context, tenant, findingID string, topK int) ([]byte, error)
	// GetRelatedFindings returns JSON-encoded []graphrag.FindingNode.
	GetRelatedFindings(ctx context.Context, tenant, findingID string) ([]byte, error)

	// ApplicationFindings returns JSON-encoded []ApplicationFinding: the
	// Findings of one Application with, per Finding, whether the code it
	// affects is inside an Image a Deployment of that Application runs, and
	// whether that Deployment exposes a Host.
	//
	// It is a traversal, not a search, which is why the hybrid QueryNodes
	// surface could not answer it (gibson#1669). statuses filters by lifecycle
	// status; empty means every status.
	ApplicationFindings(ctx context.Context, tenant, application string, statuses []string, limit int) ([]byte, error)
}

// FindingQuerier reads findings for remote agents. Write operations are handled
// by the existing FindingSubmitter interface.
// May be nil; finding query RPCs return Unimplemented when nil.
type FindingQuerier interface {
	// GetFindings returns JSON-encoded []*finding.Finding matching the filter.
	GetFindings(ctx context.Context, tenant string, filterJSON []byte) ([]byte, error)
	// GetRunFindings returns JSON-encoded []*finding.Finding scoped to mission runs.
	// scope is "previous" or "all".
	GetRunFindings(ctx context.Context, tenant, workID, scope string, filterJSON []byte) ([]byte, error)
}

// OriginateMissionRequest carries everything the daemon needs to originate a
// mission for an off-cluster component. It is a struct, not an argument
// list, because half of these fields are authority-bearing and must be
// filled from VERIFIED request state rather than the payload — a struct
// makes an unfilled one visible at the call site instead of hiding it in
// argument order.
//
// There is deliberately NO tenant field. The daemon-side implementation
// reads the tenant from the request context and nowhere else, so this struct
// cannot carry a wrong one — gibsoncheck's tenantfromcontext analyzer flags a
// `req.Tenant` read in handler code precisely because a tenant that travels
// in a struct eventually travels from a payload.
type OriginateMissionRequest struct {
	// ParentMissionID is the mission the caller's current work item belongs
	// to, resolved server-side. Empty means "no resolvable parent", which
	// origination refuses — a component cannot start a mission out of
	// nothing (see internal/engine/mission's originate.go).
	ParentMissionID string

	// ParentWorkID is the caller's work item. Lineage only; it has already
	// been used, and validated, to produce ParentMissionID.
	ParentWorkID string

	// Principal is the caller's verified FGA principal ref.
	Principal string

	// GrantID is the ACTIVE capability grant that carried
	// capname.MissionOriginate for this call.
	GrantID string

	// DefinitionJSON, TargetID and OptsJSON are the caller's own request
	// payload: what mission it wants, against which target, with which
	// options. These are the only fields a caller controls, and each is
	// bounded by the parent (budget by the reservation ledger, target by
	// the subset check).
	DefinitionJSON []byte
	TargetID       string
	OptsJSON       []byte
}

// MissionManager handles mission lifecycle for off-cluster components.
// May be nil; mission RPCs return Unavailable when nil (the gate cannot be
// evaluated, which is never the same as the gate being open).
type MissionManager interface {
	// OriginateMission creates a mission under the caller's parent mission,
	// clamping and reserving its budget and enforcing target scope, and
	// returns the JSON-encoded mission record.
	OriginateMission(ctx context.Context, req OriginateMissionRequest) ([]byte, error)
	// RunMission queues a mission for execution.
	RunMission(ctx context.Context, tenant, missionID string, optsJSON []byte) error
	// GetMissionStatus returns JSON-encoded mission.MissionStatusInfo.
	GetMissionStatus(ctx context.Context, tenant, missionID string) ([]byte, error)
	// WaitForMission blocks until mission completes or timeout; returns JSON-encoded mission.MissionResult.
	WaitForMission(ctx context.Context, tenant, missionID string, timeoutMs int64) ([]byte, error)
	// ListMissions returns JSON-encoded []*mission.MissionInfo.
	ListMissions(ctx context.Context, tenant string, filterJSON []byte) ([]byte, error)
	// CancelMission requests cancellation of a running mission.
	CancelMission(ctx context.Context, tenant, missionID string) error
	// GetMissionResults returns JSON-encoded mission.MissionResult.
	GetMissionResults(ctx context.Context, tenant, missionID string) ([]byte, error)
	// GetMissionRunHistory returns the JSON-encoded run history of
	// missionID. It takes a mission id, not a work id: both callers already
	// hold one that the daemon resolved (PollWork from the work item it
	// enqueued, the RPC handler from the tenant-hardened work-context
	// lookup), so re-deriving it here would only add a place to get it
	// wrong.
	GetMissionRunHistory(ctx context.Context, tenant, missionID string) ([]byte, error)
}

// CapabilityChecker verifies whether a calling component's capability grant
// carries a given session capability (gibson#1186 slice C — capname.
// MissionDelegate, capname.MissionOriginate). Unlike the FGA-derived
// "execute:tool:x" style capabilities, these two are never FGA relations:
// they exist only as a row on the specific Grant the check resolves, minted
// there by capabilitygrant.RegisterCapabilityGrant when the enrolling
// credential's own ceiling named them. Revoking the agent removes the grant
// (and so the capability) with it — there is no standing tuple anywhere else
// that a revocation would need to also find.
//
// May be nil on ComponentServiceServer; every capability-gated RPC DENIES
// rather than allows when nil. A nil checker means "the gate is not wired",
// never "the gate is open".
type CapabilityChecker interface {
	// ActiveGrantID returns the id of the ACTIVE grant named capabilityName
	// held by principal (the FGA principal ref of the calling component,
	// e.g. "agent_principal:<id>" — the request's verified identity Subject)
	// within tenant, or "" when the principal does not hold it.
	//
	// One method rather than a bool check plus a separate id lookup: mission
	// origination must record WHICH grant authorized it (gibson#1358), and
	// asking twice would let a revocation land between the two calls and
	// leave a mission attributed to a grant that no longer allowed it. An
	// empty id is the denial.
	ActiveGrantID(ctx context.Context, tenant, principal, capabilityName string) (string, error)
}

// CredentialStore retrieves tenant-scoped credentials for remote agents.
// May be nil; GetCredential returns Unimplemented when nil.
type CredentialStore interface {
	// GetCredential returns JSON-encoded types.Credential.
	GetCredential(ctx context.Context, tenant, name string) ([]byte, error)
}

// TaxonomyProvider returns the current taxonomy schema for remote agents.
// May be nil; GetTaxonomySchema returns Unimplemented when nil.
type TaxonomyProvider interface {
	// GetTaxonomySchema returns JSON-encoded taxonomy definition.
	GetTaxonomySchema(ctx context.Context) ([]byte, error)
}

// StepHintsReporter accepts planning step hints from remote agents.
// May be nil; ReportStepHints returns Unimplemented when nil.
type StepHintsReporter interface {
	// ReportStepHints forwards hints to the orchestrator.
	ReportStepHints(ctx context.Context, tenant, workID string, hintsJSON []byte) error
}
