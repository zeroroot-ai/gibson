package component

// finding_submitter.go provides GraphRAGFindingSubmitter, which routes
// findings from remote agents to both the per-tenant finding store (via the
// data-plane Pool) and the Neo4j knowledge graph (via an async bridge).

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/auth"
)

// FindingGraphBridge is a narrow interface over harness.GraphRAGBridge used by
// GraphRAGFindingSubmitter. It declares only the StoreAsync method to avoid
// a circular import (harness imports component, so component cannot import harness).
//
// harness.GraphRAGBridge satisfies this interface at the call site in daemon/grpc.go.
type FindingGraphBridge interface {
	StoreAsync(ctx context.Context, finding agent.Finding, missionID types.ID, targetID *types.ID)
}

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
	bridge      FindingGraphBridge
	pool        datapool.Pool
	stateClient *state.StateClient
	logger      *slog.Logger
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
	bridge FindingGraphBridge,
	pool datapool.Pool,
	stateClient *state.StateClient,
	logger *slog.Logger,
) *GraphRAGFindingSubmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &GraphRAGFindingSubmitter{
		bridge:      bridge,
		pool:        pool,
		stateClient: stateClient,
		logger:      logger.With("component", "graphrag_finding_submitter"),
	}
}

// Submit stores a JSON-encoded agent.Finding in the per-tenant finding store
// (via the data-plane Pool) and queues it for asynchronous storage in the Neo4j
// knowledge graph.
//
// The method:
//  1. Parses the finding JSON into an agent.Finding.
//  2. Assigns a new finding ID (overwriting any client-supplied ID for consistency).
//  3. Sets the tenant from the auth context.
//  4. Resolves the missionID from the work-item context stored in Redis.
//  5. Acquires a per-tenant Conn and stores an EnhancedFinding (warn on failure).
//  6. Calls FindingGraphBridge.StoreAsync with the base finding (fire-and-forget).
//
// Returns the generated finding ID and nil on success. Pool errors are mapped to
// gRPC status codes; JSON parse errors return an error; GraphRAG failures are non-fatal.
func (s *GraphRAGFindingSubmitter) Submit(
	ctx context.Context,
	tenant, workID, findingJSON, severity, title string,
) (string, error) {
	// Step 1: Parse the finding JSON.
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

	// Step 2: Assign a canonical finding ID.
	findingID := types.NewID()
	baseFinding.ID = findingID
	baseFinding.TenantID = tenant

	// Step 3: Resolve missionID from the work-item context stored by PollWork.
	// This is best-effort; findings submitted outside a formal mission will use
	// an empty missionID.
	missionID := s.resolveMissionID(ctx, workID)

	// Step 4: Acquire a per-tenant Conn and persist the finding.
	s.persistFinding(ctx, tenant, workID, findingID, baseFinding, missionID)

	// Step 5: Queue async storage to Neo4j via the bridge.
	// StoreAsync is fire-and-forget; the bridge manages its own goroutines.
	var targetID *types.ID
	if baseFinding.TargetID != nil {
		targetID = baseFinding.TargetID
	}
	s.bridge.StoreAsync(ctx, baseFinding, missionID, targetID)

	s.logger.InfoContext(ctx, "finding submitter: finding queued for GraphRAG storage",
		slog.String("tenant", tenant),
		slog.String("work_id", workID),
		slog.String("finding_id", findingID.String()),
		slog.String("mission_id", missionID.String()),
		slog.String("severity", string(baseFinding.Severity)),
	)

	return findingID.String(), nil
}

// persistFinding acquires a per-tenant Conn from the pool and stores the finding.
// Errors are logged as warnings; the finding ID is still returned to the caller.
func (s *GraphRAGFindingSubmitter) persistFinding(
	ctx context.Context,
	tenant, workID string,
	findingID types.ID,
	baseFinding agent.Finding,
	missionID types.ID,
) {
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

	enhanced := finding.NewEnhancedFinding(baseFinding, missionID, "")
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
// Returns an empty types.ID when:
//   - workID is empty.
//   - The mapping has expired or was never written.
//   - The stateClient is unavailable.
//
// Failures are logged at debug level and do not propagate as errors.
func (s *GraphRAGFindingSubmitter) resolveMissionID(ctx context.Context, workID string) types.ID {
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

	return types.ID(fields[workContextMissionField])
}

// Compile-time check: GraphRAGFindingSubmitter must satisfy FindingSubmitter.
var _ FindingSubmitter = (*GraphRAGFindingSubmitter)(nil)
