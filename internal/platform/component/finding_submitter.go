// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// finding_submitter.go provides GraphRAGFindingSubmitter, which routes
// findings from remote agents to both the per-tenant finding store (via the
// data-plane Pool) and the Neo4j knowledge graph (via an async bridge).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkfinding "github.com/zeroroot-ai/sdk/finding"
)

// WorldFindingSink routes a submitted finding into the per-tenant ECS brain World
// (ADR-0107): the daemon wires this to fold the finding as a Timeline event so the
// graph projector — the sole writer of finding nodes — materializes it. Kept as a
// plain callback so component stays decoupled from the brain package.
//
// The sink receives the same record the per-tenant store keeps: the
// EnhancedFinding carries the mission whose work produced the finding, the
// mission-evidence edge (gibson#1075/#1078), and the verified submitter
// (gibson#208). The submitter resolves the mission from the work-item context
// (PollWork → Redis) before invoking the sink, so the brain FindingRaised can be
// stamped and the finding attaches to its mission's frame. The mission is empty
// when the finding was submitted outside a formal mission (the context expired
// or never existed), in which case the finding stays tenant-ambient.
//
// missionRunID is the run of the mission that the work item belongs to, as the
// daemon bound it when it enqueued the work. It is empty when the finding has
// no mission or the binding is gone. The World drops a finding of a run that is
// not the current run of the mission (gibson#1217).
type WorldFindingSink func(ctx context.Context, tenant string, finding finding.EnhancedFinding, missionRunID string)

// ErrNoSubmitterIdentity reports a SubmitFinding call whose context carries no
// verified caller identity. Every request reaches the daemon through ext-authz
// and the SDK identity interceptor, so a missing identity is a wiring fault,
// and a finding with no submitter is not recorded.
var ErrNoSubmitterIdentity = errors.New("finding submitter: no verified caller identity in context")

// ErrFindingNotStored reports a finding that the per-tenant store did not
// write. The error chain holds the cause, for the log. A caller never sends the
// cause to the agent.
var ErrFindingNotStored = errors.New("finding submitter: the finding was not stored")

// FindingRecordStore writes the one record of a finding to the per-tenant
// store. pgstore.Store satisfies it.
type FindingRecordStore interface {
	Store(ctx context.Context, tenant string, f finding.EnhancedFinding) error
}

// GraphRAGFindingSubmitter implements FindingSubmitter. It writes a finding to
// the per-tenant finding store first, and then routes it into the tenant World.
// Postgres is the one home of the fields and the evidence of a finding, so a
// finding that the store did not write fails the submit and never reaches the
// World.
type GraphRAGFindingSubmitter struct {
	worldSink   WorldFindingSink
	store       FindingRecordStore
	stateClient *state.StateClient
	logger      *slog.Logger

	// enrolledAgents turns the verified principal into the registered agent
	// name and the enrolling subject (gibson#208). Nil when the daemon has no
	// capability-grant service, in which case a finding carries the principal
	// and no name.
	enrolledAgents EnrolledAgentLookup

	// records reads the tool calls that the daemon recorded. Nil when the daemon
	// has no brain, and a finding that names a tool call then fails.
	records brain.ToolCallRecord
}

// WithEnrolledAgentLookup wires the registry that names the enrolled agent
// behind a verified component principal.
func (s *GraphRAGFindingSubmitter) WithEnrolledAgentLookup(l EnrolledAgentLookup) *GraphRAGFindingSubmitter {
	s.enrolledAgents = l
	return s
}

// NewGraphRAGFindingSubmitter constructs a GraphRAGFindingSubmitter.
//
// Parameters:
//   - bridge:      FindingGraphBridge for async Neo4j storage (must not be nil).
//   - store:       The per-tenant finding store (required). The daemon passes a
//     pgstore.Store over its data pool. A daemon with no pool has a store that
//     refuses each write, so each submit fails.
//   - stateClient: StateClient used to resolve workID → missionID from Redis.
//   - logger:      Structured logger; if nil, slog.Default() is used.
func NewGraphRAGFindingSubmitter(
	worldSink WorldFindingSink,
	store FindingRecordStore,
	stateClient *state.StateClient,
	logger *slog.Logger,
) *GraphRAGFindingSubmitter {
	if store == nil {
		panic("component.NewGraphRAGFindingSubmitter: the finding store must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &GraphRAGFindingSubmitter{
		worldSink:   worldSink,
		store:       store,
		stateClient: stateClient,
		logger:      logger.With("component", "graphrag_finding_submitter"),
	}
}

// findingPayload is the JSON that an SDK agent sends. Its evidence has the shape
// of the SDK. The field shadows the evidence of the embedded agent.Finding, so
// the decoder reads the SDK shape.
type findingPayload struct {
	agent.Finding
	Evidence    []sdkfinding.Evidence `json:"evidence,omitempty"`
	ToolCallIDs []string              `json:"tool_call_ids,omitempty"`
}

// decodeFindingPayload decodes the JSON of an SDK finding. The agent typed all
// of its evidence, so each item is tier 2. The payload cannot set a tier or a
// tool call ID on an item. It returns the tool call IDs that the agent named.
// The daemon builds tier 1 evidence from the record of those tool calls.
func decodeFindingPayload(raw []byte) (agent.Finding, []string, error) {
	var payload findingPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return agent.Finding{}, nil, fmt.Errorf("decode finding payload: %w", err)
	}
	out := payload.Finding
	out.Evidence = nil
	for _, e := range payload.Evidence {
		metadata := make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			metadata[k] = fmt.Sprint(v)
		}
		out.Evidence = append(out.Evidence, &typespb.Evidence{
			Title:    e.Title,
			Type:     finding.EvidenceTypeFromName(e.Type),
			Content:  e.Content,
			Metadata: metadata,
			Tier:     typespb.EvidenceTier_EVIDENCE_TIER_TYPED,
		})
	}
	return out, payload.ToolCallIDs, nil
}

// Errors of the tool call record. The service maps each one to a gRPC code.
var (
	// ErrToolCallNotRecorded reports a tool call ID that names no record of the
	// mission of the work item in the tenant of the caller.
	ErrToolCallNotRecorded = errors.New("finding submitter: no record of the named tool call")

	// ErrToolCallRecordUnavailable reports that the daemon has no record of tool
	// calls to read.
	ErrToolCallRecordUnavailable = errors.New("finding submitter: the record of tool calls is not wired")
)

// WithToolCallRecord wires the record of tool calls. The submitter builds tier 1
// evidence from it with brain.ReadRecordedEvidence, the function that a proof
// and a harness finding also use.
func (s *GraphRAGFindingSubmitter) WithToolCallRecord(r brain.ToolCallRecord) *GraphRAGFindingSubmitter {
	s.records = r
	return s
}

// recordedEvidence builds the tier 1 evidence of a finding from the tool calls
// that it names, with brain.ReadRecordedEvidence. A finding with no mission
// cannot name a tool call, because a record belongs to a mission.
func (s *GraphRAGFindingSubmitter) recordedEvidence(
	ctx context.Context, missionID types.ID, toolCallIDs []string,
) ([]*typespb.Evidence, error) {
	if len(toolCallIDs) == 0 {
		return nil, nil
	}
	if s.records == nil {
		return nil, ErrToolCallRecordUnavailable
	}
	if missionID == "" {
		return nil, fmt.Errorf("%w: %q (the finding has no mission)", ErrToolCallNotRecorded, toolCallIDs[0])
	}
	recorded, missing, err := brain.ReadRecordedEvidence(ctx, s.records, missionID.String(), toolCallIDs)
	if err != nil {
		return nil, fmt.Errorf("finding submitter: %w", err)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %q", ErrToolCallNotRecorded, missing[0])
	}
	return recorded, nil
}

// Submit stores a JSON-encoded agent.Finding in the per-tenant finding store
// (via the data-plane Pool) and routes it into the tenant World, from which the
// graph projector materializes it.
//
// The method:
//  1. Reads the verified caller identity from the context. No identity, no
//     finding (ErrNoSubmitterIdentity).
//  2. Parses the finding JSON into an agent.Finding.
//  3. Assigns a new finding ID and stamps the submitter, overwriting whatever
//     the client supplied for either. The client's own agent_name is not
//     attribution and is never read.
//  4. Resolves the missionID from the work-item context stored in Redis.
//  5. Builds the one EnhancedFinding the store keeps and the World sink folds.
//  6. Writes it to the per-tenant store. A failed write fails the submit
//     (ErrFindingNotStored), and the World never gets the finding.
//  7. Hands it to the World sink.
//
// Returns the generated finding ID and nil on success. A parse error and a
// store failure each return an error.
func (s *GraphRAGFindingSubmitter) Submit(
	ctx context.Context,
	tenant, workID, findingJSON, severity, title, idempotencyKey string,
) (string, error) {
	// Step 1: the verified caller. ext-authz asserted it and the SDK
	// interceptor put it on the context; the client payload has no say.
	submitter, err := s.resolveSubmitter(ctx, tenant)
	if err != nil {
		return "", err
	}

	// Step 2: Parse the finding JSON.
	baseFinding, toolCallIDs, err := decodeFindingPayload([]byte(findingJSON))
	if err != nil {
		s.logger.WarnContext(ctx, "finding submitter: failed to parse finding JSON; generating stub finding",
			slog.String("tenant", tenant),
			slog.String("work_id", workID),
			slog.String("error", err.Error()),
		)
		// Build a minimal stub so the call never completely drops a finding.
		baseFinding = agent.Finding{
			Title:       title,
			Description: findingJSON, // preserve raw payload in description
			Severity:    agent.FindingSeverity(severity),
			CreatedAt:   time.Now(),
		}
	}

	// Step 3: Assign a canonical finding ID and stamp the verified submitter.
	// Both overwrite the client payload.
	findingID := types.NewID()
	if idempotencyKey != "" {
		// One result of a tool names one finding of this submitter (review R6).
		findingID = finding.ResultID(tenant, submitter.principal, idempotencyKey)
	}
	baseFinding.ID = findingID
	baseFinding.TenantID = tenant
	baseFinding.SubmittedBy = submitter.principal
	baseFinding.EnrolledBy = submitter.enrolledBy

	// Step 4: Resolve missionID from the work-item context stored by PollWork.
	// This is best-effort; findings submitted outside a formal mission — and
	// findings naming a work item this tenant does not own — use an empty
	// missionID and stay tenant-ambient.
	missionID := s.resolveMissionID(ctx, tenant, workID)

	// Step 4b: tier 1 evidence. Each tool call that the payload names must have a
	// record of this mission in this tenant. An ID with no record fails the whole
	// submit, before the daemon stores anything.
	recorded, err := s.recordedEvidence(ctx, missionID, toolCallIDs)
	if err != nil {
		return "", err
	}
	baseFinding.Evidence = append(recorded, baseFinding.Evidence...)

	// Step 5: the one record. The store keeps it and the World folds it, so
	// the two never disagree about who submitted what under which mission.
	enhanced := finding.NewEnhancedFinding(baseFinding, missionID, submitter.agentName)
	// An agent that submits a finding raised it in a mission run, and a rerun of
	// that mission is the check that verifies the fix (ADR-0178). The daemon has
	// no attack proof for this path, so it never records a predicate here.
	enhanced.Check = finding.ScanCheck(missionID)

	// Step 6: Acquire a per-tenant Conn and persist the finding. Postgres is the
	// one home of the fields and the evidence of the finding. A failed write
	// fails the submit before the World hears of the finding.
	if err := s.persistFinding(ctx, tenant, enhanced); err != nil {
		s.logger.ErrorContext(ctx, "finding submitter: failed to store finding",
			slog.String("tenant", tenant),
			slog.String("work_id", workID),
			slog.String("finding_id", findingID.String()),
			slog.String("error", err.Error()),
		)
		return "", err
	}

	// Step 7: route the finding into the World; the graph projector (sole writer)
	// materializes the :Finding node from it (ADR-0107, gibson#837). The mission id
	// resolved in step 4 is carried so the brain can stamp FindingRaised.MissionID
	// and the finding attaches to its mission's frame (gibson#1078); empty when the
	// finding was submitted outside a formal mission (tenant-ambient).
	if s.worldSink != nil {
		s.worldSink(ctx, tenant, enhanced, s.resolveMissionRunID(ctx, workID, missionID))
	}

	s.logger.InfoContext(ctx, "finding submitter: finding queued for GraphRAG storage",
		slog.String("tenant", tenant),
		slog.String("work_id", workID),
		slog.String("finding_id", findingID.String()),
		slog.String("mission_id", missionID.String()),
		slog.String("severity", string(baseFinding.Severity)),
		slog.String("submitted_by", submitter.principal),
		slog.String("agent_name", submitter.agentName),
	)

	return findingID.String(), nil
}

// findingSubmitter is the verified identity a finding is stamped with.
type findingSubmitter struct {
	principal  string // the FGA user ref ext-authz asserted, e.g. "agent_principal:<id>"
	agentName  string // the name the agent registered under, from the capability-grant registry
	enrolledBy string // the subject of the person who enrolled the agent
}

// resolveSubmitter reads the verified caller from ctx and names the enrolled
// agent behind it. The principal is the request identity's Subject in its FGA
// user form: a typed component principal as is, a human subject as
// "user:<sub>". The registry answers the name and the enroller; when it has no
// active agent for the principal, or the daemon has no registry, the finding
// carries the principal alone.
func (s *GraphRAGFindingSubmitter) resolveSubmitter(ctx context.Context, tenant string) (findingSubmitter, error) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return findingSubmitter{}, ErrNoSubmitterIdentity
	}
	sub := findingSubmitter{principal: componentFGAUser(id.Subject)}
	if s.enrolledAgents == nil {
		return sub, nil
	}
	name, enrolledBy, lookupErr := s.enrolledAgents.LookupEnrolledAgent(ctx, tenant, sub.principal)
	if lookupErr != nil {
		return findingSubmitter{}, fmt.Errorf("finding submitter: name the enrolled agent for %s: %w", sub.principal, lookupErr)
	}
	if name == "" {
		s.logger.WarnContext(ctx, "finding submitter: principal has no active enrolled agent; finding carries the principal only",
			slog.String("tenant", tenant),
			slog.String("submitted_by", sub.principal),
		)
	}
	sub.agentName = name
	sub.enrolledBy = enrolledBy
	return sub, nil
}

// persistFinding writes the finding to the findings table of the database of
// the tenant. Any write error, including a tenant that is not provisioned and a
// daemon with no data pool, is returned.
func (s *GraphRAGFindingSubmitter) persistFinding(
	ctx context.Context,
	tenant string,
	enhanced finding.EnhancedFinding,
) error {
	if err := s.store.Store(ctx, tenant, enhanced); err != nil {
		return fmt.Errorf("%w: %w", ErrFindingNotStored, err)
	}
	s.logger.DebugContext(ctx, "finding submitter: finding stored in per-tenant store",
		slog.String("tenant", tenant),
		slog.String("finding_id", enhanced.ID.String()),
		slog.String("mission_id", enhanced.MissionID.String()),
	)
	return nil
}

// resolveMissionID looks up the missionID associated with a work item from the
// Redis work-context hash written by PollWork (key: gibson:work:ctx:{work_id}).
//
// The hash is global — the work id is its only qualifier — so the tenant it was
// registered under is compared against the submitting tenant before the mission
// is handed back. Without that comparison a work id is enough on its own to
// stamp a finding with another tenant's mission.
//
// Returns an empty types.ID when:
//   - workID is empty.
//   - The mapping has expired or was never written.
//   - The stateClient is unavailable.
//   - The mapping belongs to a different tenant than the submitter.
//
// An empty mission ID leaves the finding tenant-ambient under the submitter's
// own tenant, which is the safe outcome: the finding is still recorded, it just
// cannot attach itself to a mission it has no claim on.
func (s *GraphRAGFindingSubmitter) resolveMissionID(ctx context.Context, tenant, workID string) types.ID {
	if workID == "" || s.stateClient == nil {
		return types.ID("")
	}

	key := workContextKeyPrefix + workID
	fields, err := s.stateClient.Client().HGetAll(ctx, key).Result()
	if err != nil || len(fields) == 0 {
		s.logger.DebugContext(ctx, "finding submitter: no work context found (finding not in a mission or context expired)",
			slog.String("work_id", workID),
		)
		return types.ID("")
	}

	if !tenantMayActOnWork(tenant, fields[workContextTenantField]) {
		s.logger.WarnContext(ctx, "finding submitter: work context belongs to another tenant; finding left unattached to a mission",
			slog.String("tenant", tenant),
			slog.String("work_id", workID),
		)
		return types.ID("")
	}

	return types.ID(fields[workContextMissionField])
}

// resolveMissionRunID returns the run of the mission that workID belongs to. The
// daemon bound it to the work id when it enqueued the work, so it does not come
// from the component. A finding with no mission has no run.
func (s *GraphRAGFindingSubmitter) resolveMissionRunID(ctx context.Context, workID string, missionID types.ID) string {
	if missionID.IsZero() || s.stateClient == nil {
		return ""
	}
	run, err := lookupWorkRun(ctx, s.stateClient.Client(), workID)
	if err != nil {
		if errors.Is(err, ErrWorkRunUnknown) {
			s.logger.DebugContext(ctx, "finding submitter: no mission run bound to the work item",
				slog.String("work_id", workID),
			)
		} else {
			// The finding is kept without a run. A Redis fault must not pass
			// without a sign.
			s.logger.WarnContext(ctx, "finding submitter: could not read the mission run of the work item",
				slog.String("work_id", workID),
				slog.String("error", err.Error()),
			)
		}
		return ""
	}
	return run
}

// Compile-time check: GraphRAGFindingSubmitter must satisfy FindingSubmitter.
var _ FindingSubmitter = (*GraphRAGFindingSubmitter)(nil)
