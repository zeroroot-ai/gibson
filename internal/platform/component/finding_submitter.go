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
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// WorldFindingSink routes a submitted finding into the per-tenant ECS brain World
// (ADR-0007): the daemon wires this to fold the finding as a Timeline event so the
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
type WorldFindingSink func(ctx context.Context, tenant string, finding finding.EnhancedFinding)

// ErrNoSubmitterIdentity reports a SubmitFinding call whose context carries no
// verified caller identity. Every request reaches the daemon through ext-authz
// and the SDK identity interceptor, so a missing identity is a wiring fault,
// and a finding with no submitter is not recorded.
var ErrNoSubmitterIdentity = errors.New("finding submitter: no verified caller identity in context")

// GraphRAGFindingSubmitter implements FindingSubmitter by routing findings to:
//  1. The per-tenant finding store (via the data-plane Pool), for tenant-scoped writes.
//  2. The GraphRAG knowledge graph via FindingGraphBridge.StoreAsync (fire-and-forget).
//
// Each Submit call acquires a per-tenant Conn from the pool using the tenant extracted
// from the request context. Pool errors are mapped to gRPC status errors via
// datapool.MapPoolError; the finding_id is still returned to the caller so the agent
// can continue processing.
//
// GraphRAG storage is fully async: StoreAsync returns immediately and the actual
// write happens in a background goroutine managed by the bridge.
type GraphRAGFindingSubmitter struct {
	worldSink   WorldFindingSink
	pool        datapool.Pool
	stateClient *state.StateClient
	logger      *slog.Logger

	// enrolledAgents turns the verified principal into the registered agent
	// name and the enrolling subject (gibson#208). Nil when the daemon has no
	// capability-grant service, in which case a finding carries the principal
	// and no name.
	enrolledAgents EnrolledAgentLookup
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
//   - pool:        Per-tenant data-plane Pool used to acquire Conn for finding writes.
//     May be nil; when nil, finding persistence is skipped (Neo4j storage still runs).
//   - stateClient: StateClient used to resolve workID → missionID from Redis.
//   - logger:      Structured logger; if nil, slog.Default() is used.
func NewGraphRAGFindingSubmitter(
	worldSink WorldFindingSink,
	pool datapool.Pool,
	stateClient *state.StateClient,
	logger *slog.Logger,
) *GraphRAGFindingSubmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &GraphRAGFindingSubmitter{
		worldSink:   worldSink,
		pool:        pool,
		stateClient: stateClient,
		logger:      logger.With("component", "graphrag_finding_submitter"),
	}
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
//  6. Acquires a per-tenant Conn and stores it (warn on failure).
//  7. Hands it to the World sink.
//
// Returns the generated finding ID and nil on success. JSON parse errors return
// an error; store failures are non-fatal.
func (s *GraphRAGFindingSubmitter) Submit(
	ctx context.Context,
	tenant, workID, findingJSON, severity, title string,
) (string, error) {
	// Step 1: the verified caller. ext-authz asserted it and the SDK
	// interceptor put it on the context; the client payload has no say.
	submitter, err := s.resolveSubmitter(ctx, tenant)
	if err != nil {
		return "", err
	}

	// Step 2: Parse the finding JSON.
	var baseFinding agent.Finding
	if err := json.Unmarshal([]byte(findingJSON), &baseFinding); err != nil {
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
	baseFinding.ID = findingID
	baseFinding.TenantID = tenant
	baseFinding.SubmittedBy = submitter.principal
	baseFinding.EnrolledBy = submitter.enrolledBy

	// Step 4: Resolve missionID from the work-item context stored by PollWork.
	// This is best-effort; findings submitted outside a formal mission — and
	// findings naming a work item this tenant does not own — use an empty
	// missionID and stay tenant-ambient.
	missionID := s.resolveMissionID(ctx, tenant, workID)

	// Step 5: the one record. The store keeps it and the World folds it, so
	// the two never disagree about who submitted what under which mission.
	enhanced := finding.NewEnhancedFinding(baseFinding, missionID, submitter.agentName)

	// Step 6: Acquire a per-tenant Conn and persist the finding.
	s.persistFinding(ctx, tenant, workID, enhanced)

	// Step 7: route the finding into the World; the graph projector (sole writer)
	// materializes the :Finding node from it (ADR-0007, gibson#837). The mission id
	// resolved in step 4 is carried so the brain can stamp FindingRaised.MissionID
	// and the finding attaches to its mission's frame (gibson#1078); empty when the
	// finding was submitted outside a formal mission (tenant-ambient).
	if s.worldSink != nil {
		s.worldSink(ctx, tenant, enhanced)
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

// persistFinding acquires a per-tenant Conn from the pool and stores the finding.
// Errors are logged as warnings; the finding ID is still returned to the caller.
func (s *GraphRAGFindingSubmitter) persistFinding(
	ctx context.Context,
	tenant, workID string,
	enhanced finding.EnhancedFinding,
) {
	findingID := enhanced.ID
	missionID := enhanced.MissionID
	if s.pool == nil {
		s.logger.WarnContext(ctx, "finding submitter: pool not configured; finding not persisted to store",
			slog.String("tenant", tenant),
			slog.String("finding_id", findingID.String()),
		)
		return
	}

	tenantID, tenantParseErr := auth.NewTenantID(tenant)
	if tenantParseErr != nil {
		s.logger.WarnContext(ctx, "finding submitter: invalid tenant ID; finding not persisted",
			slog.String("tenant", tenant),
			slog.String("finding_id", findingID.String()),
			slog.String("error", tenantParseErr.Error()),
		)
		return
	}

	conn, err := s.pool.For(ctx, tenantID)
	if err != nil {
		var npErr *datapool.NotProvisionedError
		if errors.As(err, &npErr) {
			s.logger.WarnContext(ctx, "finding submitter: tenant not provisioned; finding not persisted",
				slog.String("tenant", tenant),
				slog.String("finding_id", findingID.String()),
			)
		} else {
			s.logger.WarnContext(ctx, "finding submitter: failed to acquire conn; finding not persisted",
				slog.String("tenant", tenant),
				slog.String("finding_id", findingID.String()),
				slog.String("error", err.Error()),
			)
		}
		return
	}
	defer conn.Release()

	store := finding.NewConnBoundFindingStore(conn.Redis)
	if storeErr := store.Store(ctx, enhanced); storeErr != nil {
		s.logger.WarnContext(ctx, "finding submitter: failed to store finding; continuing",
			slog.String("tenant", tenant),
			slog.String("work_id", workID),
			slog.String("finding_id", findingID.String()),
			slog.String("error", storeErr.Error()),
		)
	} else {
		s.logger.DebugContext(ctx, "finding submitter: finding stored in per-tenant store",
			slog.String("tenant", tenant),
			slog.String("finding_id", findingID.String()),
			slog.String("mission_id", missionID.String()),
		)
	}
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

// Compile-time check: GraphRAGFindingSubmitter must satisfy FindingSubmitter.
var _ FindingSubmitter = (*GraphRAGFindingSubmitter)(nil)
