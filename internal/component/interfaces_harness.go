package component

// interfaces_harness.go defines narrow dependency interfaces for the harness
// proxy RPCs added to ComponentServiceServer. Each interface is injected via
// a With*() method on ComponentServiceServer and is nil-safe: handlers check
// for nil and return codes.Unimplemented when the dependency is not wired.

import (
	"context"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
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

// GraphRAGQuerier handles knowledge graph operations for remote agents.
// May be nil on ComponentServiceServer; GraphRAG RPCs return Unimplemented when nil.
type GraphRAGQuerier interface {
	// QueryNodes searches the knowledge graph.
	QueryNodes(ctx context.Context, tenant string, query *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error)
	// StoreNode persists a node and returns its assigned ID.
	StoreNode(ctx context.Context, tenant string, node *graphragpb.GraphNode) (string, error)
	// FindSimilarAttacks returns JSON-encoded []graphrag.AttackPattern.
	FindSimilarAttacks(ctx context.Context, tenant, content string, topK int) ([]byte, error)
	// GetAttackChains returns JSON-encoded []graphrag.AttackChain.
	GetAttackChains(ctx context.Context, tenant, techniqueID string, maxDepth int) ([]byte, error)
	// FindSimilarFindings returns JSON-encoded []graphrag.FindingNode.
	FindSimilarFindings(ctx context.Context, tenant, findingID string, topK int) ([]byte, error)
	// GetRelatedFindings returns JSON-encoded []graphrag.FindingNode.
	GetRelatedFindings(ctx context.Context, tenant, findingID string) ([]byte, error)
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

// MissionManager handles sub-mission lifecycle for remote agents.
// May be nil; mission management RPCs return Unimplemented when nil.
type MissionManager interface {
	// CreateMission creates a sub-mission and returns JSON-encoded mission.MissionInfo.
	CreateMission(ctx context.Context, tenant string, missionDefinitionJSON []byte, targetID string, optsJSON []byte) ([]byte, error)
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
	// GetMissionRunHistory returns JSON-encoded []types.MissionRunSummary.
	GetMissionRunHistory(ctx context.Context, tenant, workID string) ([]byte, error)
}

// AgentDelegator dispatches sub-agent execution for remote agents.
// May be nil; delegation RPCs return Unimplemented when nil.
type AgentDelegator interface {
	// DelegateToAgent dispatches a task to another agent and returns JSON-encoded agent.Result.
	DelegateToAgent(ctx context.Context, tenant, agentName string, taskJSON []byte) ([]byte, error)
}

// ComponentLister provides component discovery for remote agents.
// May be nil; list RPCs return Unimplemented when nil.
type ComponentLister interface {
	// ListTools returns tool descriptors visible to the tenant.
	ListTools(ctx context.Context, tenant string) ([]ToolDescriptor, error)
	// ListAgents returns agent descriptors visible to the tenant.
	ListAgents(ctx context.Context, tenant string) ([]AgentDescriptor, error)
}

// ToolDescriptor contains metadata about a registered tool.
type ToolDescriptor struct {
	Name              string
	Version           string
	Description       string
	Tags              []string
	InputMessageType  string
	OutputMessageType string
}

// AgentDescriptor contains metadata about a registered agent.
type AgentDescriptor struct {
	Name         string
	Version      string
	Description  string
	Capabilities []string
	TargetTypes  []string
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
