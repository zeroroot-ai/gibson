// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// component_mission_manager.go implements component.MissionManager — the
// mission surface an off-cluster component reaches through ComponentService
// (gibson#1358).
//
// It is daemon-local on purpose. The mission-origination design brief looked
// for a seam that does not fight the ecs-brain rewrite, and this is it: the
// per-tenant mission store plus the existing missionManager, reached the same
// way missionHarnessAdapter already reaches them for the in-cluster harness.
// Whatever engine eventually consumes a mission.Mission row, the row is
// created the same way.
//
// Two things it does that the harness adapter does not, both required
// because the caller here is a COMPONENT rather than a dispatched work item:
//
//   - Origination policy. Budget clamp + atomic reservation against the
//     parent's envelope, target-scope subset check, and immutable lineage —
//     all of it in internal/engine/mission's Originator, which this type
//     constructs per call over the caller's own tenant Conn.
//   - An explicit wire shape. The proto fields are opaque `bytes *_json`, so
//     the daemon owns what goes in them; componentMissionRecord below is that
//     shape, and it is deliberately NOT a marshalled mission.Mission — that
//     struct is mid-rewrite and carries fields (checkpoints, agent
//     assignments, memory continuity) an off-cluster caller has no business
//     reading.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// componentMissionManager implements component.MissionManager.
type componentMissionManager struct {
	daemon  *daemonImpl
	adapter *missionHarnessAdapter
	// storeFactory builds the per-tenant store + reservation ledger from an
	// acquired Conn. Defaults to the RedisJSON-backed implementations; tests
	// override it to inject in-memory fakes, since RedisJSON (JSON.SET/GET) has
	// no in-process server (miniredis does not implement it).
	storeFactory func(conn *datapool.Conn) (mission.MissionStore, mission.ReservationLedger)
	// runStoreFactory builds the per-tenant run store from an acquired Conn.
	// Same RedisJSON-injection reason as storeFactory.
	runStoreFactory func(conn *datapool.Conn) mission.MissionRunStore
}

// newComponentMissionManager constructs the manager. d must not be nil.
func newComponentMissionManager(d *daemonImpl) *componentMissionManager {
	if d == nil {
		panic("daemon: newComponentMissionManager: daemon must not be nil")
	}
	return &componentMissionManager{
		daemon:          d,
		adapter:         newMissionHarnessAdapter(d),
		storeFactory:    defaultMissionStoreFactory,
		runStoreFactory: defaultMissionRunStoreFactory,
	}
}

// defaultMissionStoreFactory is the production store+ledger constructor: both
// bound to the acquired tenant Conn's Redis client.
func defaultMissionStoreFactory(conn *datapool.Conn) (mission.MissionStore, mission.ReservationLedger) {
	return mission.NewConnBoundMissionStore(conn.Redis), mission.NewRedisReservationLedger(conn.Redis)
}

// defaultMissionRunStoreFactory is the production run-store constructor.
func defaultMissionRunStoreFactory(conn *datapool.Conn) mission.MissionRunStore {
	return mission.NewConnBoundRunStore(conn.Redis)
}

var _ component.MissionManager = (*componentMissionManager)(nil)

// componentMissionRecord is the JSON body ComponentService returns for a
// mission, on create, status, results and list alike. One shape for all four
// so a client parses missions once.
//
// Money is reported in whole USD (the unit mission.Constraints/Metrics use)
// rather than the cents the reservation ledger counts in, because that is
// what every other mission surface reports and a second unit on one wire
// would be read wrong exactly once.
type componentMissionRecord struct {
	ID              string     `json:"id"`
	Name            string     `json:"name,omitempty"`
	Description     string     `json:"description,omitempty"`
	Status          string     `json:"status"`
	Progress        float64    `json:"progress"`
	Depth           int        `json:"depth"`
	ParentMissionID string     `json:"parent_mission_id,omitempty"`
	TargetIDs       []string   `json:"target_ids,omitempty"`
	MaxCostUSD      float64    `json:"max_cost_usd,omitempty"`
	MaxTokens       int64      `json:"max_tokens,omitempty"`
	TotalCostUSD    float64    `json:"total_cost_usd,omitempty"`
	TotalTokens     int64      `json:"total_tokens,omitempty"`
	FindingsCount   int        `json:"findings_count"`
	Error           string     `json:"error,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	// Lineage echoes the four origination keys back to the caller so a
	// component can see the attribution the daemon recorded for it — and so
	// a support conversation about "which grant let this run" has an answer
	// on the same surface that started it.
	Lineage map[string]string `json:"lineage,omitempty"`
}

// componentMissionRunRecord is one entry of GetMissionRunHistory.
type componentMissionRunRecord struct {
	ID            string     `json:"id"`
	MissionID     string     `json:"mission_id"`
	RunNumber     int        `json:"run_number"`
	Status        string     `json:"status"`
	Progress      float64    `json:"progress"`
	FindingsCount int        `json:"findings_count"`
	Error         string     `json:"error,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

// tenantConn acquires the caller's tenant Conn.
//
// The tenant argument arrives from the handler, which read it from the
// verified identity — but this cross-checks it against the context anyway.
// Not paranoia: "the tenant came from the payload" is the defect class that
// has produced repeated advisories in this repo, and a seam that accepts a
// tenant string is one careless call site away from becoming one. If the two
// ever disagree, the context wins and the request fails.
func (m *componentMissionManager) tenantConn(ctx context.Context, tenant string) (mission.MissionStore, mission.ReservationLedger, func(), error) {
	if m.daemon.pool == nil {
		return nil, nil, func() {}, status.Error(codes.Unavailable, "mission store not available (pool not configured)")
	}
	ctxTenant, err := tenantFromCtx(ctx)
	if err != nil {
		return nil, nil, func() {}, err
	}
	if tenant != "" && tenant != ctxTenant.String() {
		m.daemon.logger.Error(ctx, "component mission manager: tenant argument does not match the request identity; refusing",
			"argument_tenant", tenant, "identity_tenant", ctxTenant)
		return nil, nil, func() {}, status.Error(codes.Internal, "tenant mismatch")
	}

	conn, connErr := m.daemon.pool.For(ctx, ctxTenant)
	if connErr != nil {
		return nil, nil, func() {}, status.Errorf(codes.Unavailable, "mission store: acquire conn: %v", connErr)
	}
	store, ledger := m.storeFactory(conn)
	return store, ledger, func() { conn.Release() }, nil
}

// OriginateMission implements component.MissionManager.
func (m *componentMissionManager) OriginateMission(ctx context.Context, req component.OriginateMissionRequest) ([]byte, error) {
	// No tenant argument: OriginateMissionRequest deliberately carries none,
	// so the tenant here can only be the request context's.
	store, ledger, release, err := m.tenantConn(ctx, "")
	if err != nil {
		return nil, err
	}
	defer release()

	if req.ParentMissionID == "" {
		// Permanent, not a not-yet. A component originates a mission only
		// from inside one it was dispatched to (ADR-0063, gibson#1398,
		// 2026-08-16). Phrase it as a caller mistake to correct rather than
		// a feature to wait for, so nobody builds against it landing.
		return nil, status.Errorf(codes.FailedPrecondition,
			"%v: this call carries no work item whose mission could be the parent. "+
				"A component originates a mission only from INSIDE one it was dispatched to, "+
				"so that its budget and target scope are bounded by a mission a human already "+
				"approved. Dispatch the component work first, then originate from there.",
			mission.ErrNoParentMission)
	}
	parentID, parseErr := types.ParseID(req.ParentMissionID)
	if parseErr != nil {
		return nil, status.Errorf(codes.Internal, "resolved parent mission id is not a valid id: %v", parseErr)
	}
	parent, getErr := store.Get(ctx, parentID)
	if getErr != nil {
		return nil, status.Errorf(codes.NotFound, "parent mission %s not found: %v", parentID, getErr)
	}

	targets, targetErr := parseTargetIDs(req.TargetID)
	if targetErr != nil {
		return nil, targetErr
	}

	originator := mission.NewOriginator(store, ledger, m.daemon.logger.WithComponent("mission-originator").Slog())
	child, origErr := originator.Originate(ctx, mission.OriginateRequest{
		Parent:         parent,
		ParentWorkID:   req.ParentWorkID,
		Principal:      req.Principal,
		GrantID:        req.GrantID,
		DefinitionJSON: req.DefinitionJSON,
		TargetIDs:      targets,
	})
	if origErr != nil {
		return nil, originationStatus(origErr)
	}
	return json.Marshal(missionRecord(child)) //nolint:wrapcheck // marshalling our own struct
}

// parseTargetIDs turns the request's single target field into the child's
// target set. Empty means "no targets", which is always a valid subset.
// Nothing here resolves names — a target is a UUID or it is nothing
// (workspace convention).
func parseTargetIDs(targetID string) ([]types.ID, error) {
	if targetID == "" {
		return nil, nil
	}
	id, err := types.ParseID(targetID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "target_id must be a target UUID: %v", err)
	}
	return []types.ID{id}, nil
}

// originationStatus maps the policy's sentinel errors onto gRPC codes. Each
// refusal gets the code that tells a caller what to do about it: fix the
// request (InvalidArgument), stop asking (FailedPrecondition /
// PermissionDenied), or wait for room (ResourceExhausted).
func originationStatus(err error) error {
	switch {
	case errors.Is(err, mission.ErrNoParentMission):
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	case errors.Is(err, mission.ErrScopeWiden):
		return status.Errorf(codes.PermissionDenied,
			"%v — a child mission may only test targets the originating mission already holds, and widening needs a human", err)
	case errors.Is(err, mission.ErrDepthExceeded):
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	case errors.Is(err, mission.ErrLineageSupplied):
		return status.Errorf(codes.InvalidArgument, "%v", err)
	case errors.Is(err, mission.ErrMissingAttribution):
		return status.Errorf(codes.Unauthenticated, "%v", err)
	default:
		// The ledger reports an exhausted parent envelope as a plain error
		// from Redis's script; there is nothing left to grant, so the caller
		// should back off rather than retry immediately.
		return status.Errorf(codes.ResourceExhausted, "mission origination refused: %v", err)
	}
}

// RunMission implements component.MissionManager.
func (m *componentMissionManager) RunMission(ctx context.Context, tenant, missionID string, _ []byte) error {
	// Acquired and released purely for the tenant cross-check: the adapter
	// below resolves the tenant from the context itself, and this is what
	// refuses a seam caller that passed a different one.
	_, _, release, err := m.tenantConn(ctx, tenant)
	if err != nil {
		return err
	}
	release()
	//nolint:wrapcheck // the adapter already returns gRPC statuses
	return m.adapter.Run(ctx, missionID)
}

// CancelMission implements component.MissionManager.
func (m *componentMissionManager) CancelMission(ctx context.Context, tenant, missionID string) error {
	_, _, release, err := m.tenantConn(ctx, tenant)
	if err != nil {
		return err
	}
	release()
	id, parseErr := types.ParseID(missionID)
	if parseErr != nil {
		return status.Errorf(codes.InvalidArgument, "invalid mission ID: %v", parseErr)
	}
	//nolint:wrapcheck // the adapter already returns gRPC statuses
	return m.adapter.Cancel(ctx, id)
}

// GetMissionStatus implements component.MissionManager.
func (m *componentMissionManager) GetMissionStatus(ctx context.Context, tenant, missionID string) ([]byte, error) {
	return m.oneMission(ctx, tenant, missionID)
}

// GetMissionResults implements component.MissionManager.
//
// Same record as GetMissionStatus: a mission's "result" is its terminal
// state plus its metrics, and inventing a second shape for the same row
// would only make a client parse twice.
func (m *componentMissionManager) GetMissionResults(ctx context.Context, tenant, missionID string) ([]byte, error) {
	return m.oneMission(ctx, tenant, missionID)
}

func (m *componentMissionManager) oneMission(ctx context.Context, tenant, missionID string) ([]byte, error) {
	store, _, release, err := m.tenantConn(ctx, tenant)
	if err != nil {
		return nil, err
	}
	defer release()

	id, parseErr := types.ParseID(missionID)
	if parseErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid mission ID: %v", parseErr)
	}
	found, getErr := store.Get(ctx, id)
	if getErr != nil {
		return nil, status.Errorf(codes.NotFound, "mission %s not found", missionID)
	}
	return json.Marshal(missionRecord(found)) //nolint:wrapcheck // marshalling our own struct
}

// WaitForMission implements component.MissionManager.
//
// A caller that disconnects does NOT cancel the mission: the poll loop
// returns when ctx is done and nothing else happens. The mission keeps
// running, which is the only defensible default — the caller already paid
// for it out of the parent's reserved envelope, and a dropped TCP connection
// is not a decision to stop work.
func (m *componentMissionManager) WaitForMission(ctx context.Context, tenant, missionID string, timeoutMs int64) ([]byte, error) {
	store, _, release, err := m.tenantConn(ctx, tenant)
	if err != nil {
		return nil, err
	}
	defer release()

	id, parseErr := types.ParseID(missionID)
	if parseErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid mission ID: %v", parseErr)
	}

	if timeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
	}

	const pollInterval = 2 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		found, getErr := store.Get(ctx, id)
		if getErr != nil {
			return nil, status.Errorf(codes.NotFound, "mission %s not found", missionID)
		}
		if found.Status.IsTerminal() {
			return json.Marshal(missionRecord(found)) //nolint:wrapcheck // marshalling our own struct
		}
		select {
		case <-ctx.Done():
			return nil, status.Errorf(codes.DeadlineExceeded,
				"mission %s did not finish before the wait ended; it is still running", missionID)
		case <-ticker.C:
		}
	}
}

// ListMissions implements component.MissionManager.
func (m *componentMissionManager) ListMissions(ctx context.Context, tenant string, filterJSON []byte) ([]byte, error) {
	store, _, release, err := m.tenantConn(ctx, tenant)
	if err != nil {
		return nil, err
	}
	defer release()

	filter := &mission.MissionFilter{Limit: defaultComponentMissionListLimit}
	if len(filterJSON) > 0 {
		if unmarshalErr := json.Unmarshal(filterJSON, filter); unmarshalErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "filter_json is not a mission filter: %v", unmarshalErr)
		}
	}
	if filter.Limit <= 0 || filter.Limit > defaultComponentMissionListLimit {
		filter.Limit = defaultComponentMissionListLimit
	}

	missions, listErr := store.List(ctx, filter)
	if listErr != nil {
		return nil, status.Errorf(codes.Internal, "list missions: %v", listErr)
	}
	records := make([]componentMissionRecord, 0, len(missions))
	for _, found := range missions {
		records = append(records, missionRecord(found))
	}
	return json.Marshal(records) //nolint:wrapcheck // marshalling our own struct
}

// defaultComponentMissionListLimit bounds ListMissions. A component asking
// "what missions are there" gets a page, not the tenant's whole history —
// the response is a single unstreamed blob, so an unbounded list is a memory
// decision made by the caller.
const defaultComponentMissionListLimit = 100

// GetMissionRunHistory implements component.MissionManager.
func (m *componentMissionManager) GetMissionRunHistory(ctx context.Context, tenant, missionID string) ([]byte, error) {
	if m.daemon.pool == nil {
		return nil, status.Error(codes.Unavailable, "mission store not available (pool not configured)")
	}
	ctxTenant, err := tenantFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	if tenant != "" && tenant != ctxTenant.String() {
		return nil, status.Error(codes.Internal, "tenant mismatch")
	}
	conn, connErr := m.daemon.pool.For(ctx, ctxTenant)
	if connErr != nil {
		return nil, status.Errorf(codes.Unavailable, "run store: acquire conn: %v", connErr)
	}
	defer conn.Release()

	id, parseErr := types.ParseID(missionID)
	if parseErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid mission ID: %v", parseErr)
	}
	runs, listErr := m.runStoreFactory(conn).ListByMission(ctx, id)
	if listErr != nil {
		return nil, status.Errorf(codes.Internal, "list mission runs: %v", listErr)
	}
	records := make([]componentMissionRunRecord, 0, len(runs))
	for _, r := range runs {
		records = append(records, componentMissionRunRecord{
			ID:            r.ID.String(),
			MissionID:     r.MissionID.String(),
			RunNumber:     r.RunNumber,
			Status:        string(r.Status),
			Progress:      r.Progress,
			FindingsCount: r.FindingsCount,
			Error:         r.Error,
			CompletedAt:   r.CompletedAt,
		})
	}
	return json.Marshal(records) //nolint:wrapcheck // marshalling our own struct
}

// missionRecord projects a mission onto the component wire shape.
func missionRecord(m *mission.Mission) componentMissionRecord {
	if m == nil {
		return componentMissionRecord{}
	}
	rec := componentMissionRecord{
		ID:            m.ID.String(),
		Name:          m.Name,
		Description:   m.Description,
		Status:        string(m.Status),
		Progress:      m.Progress,
		Depth:         m.Depth,
		FindingsCount: m.FindingsCount,
		Error:         m.Error,
	}
	if m.ParentMissionID != nil {
		rec.ParentMissionID = m.ParentMissionID.String()
	}
	for _, t := range m.TargetSet() {
		rec.TargetIDs = append(rec.TargetIDs, t.String())
	}
	if m.Constraints != nil {
		rec.MaxCostUSD = m.Constraints.GetMaxCost()
		rec.MaxTokens = m.Constraints.GetMaxTokens()
	}
	if m.Metrics != nil {
		rec.TotalCostUSD = m.Metrics.TotalCost
		rec.TotalTokens = m.Metrics.TotalTokens
	}
	if !m.CompletedAt.IsNil() {
		rec.CompletedAt = m.CompletedAt.Time
	}
	if lineage := lineageOf(m); len(lineage) > 0 {
		rec.Lineage = lineage
	}
	return rec
}

// lineageOf extracts the four origination keys from a mission's metadata.
// Only those four: Metadata is a free-form map, and echoing all of it back
// would turn an internal scratch area into a wire contract by accident.
func lineageOf(m *mission.Mission) map[string]string {
	out := map[string]string{}
	for _, k := range []string{
		mission.LineageOriginatingComponent,
		mission.LineageCapabilityGrantID,
		mission.LineageParentMissionID,
		mission.LineageParentWorkID,
	} {
		if v, ok := m.Metadata[k].(string); ok && v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
