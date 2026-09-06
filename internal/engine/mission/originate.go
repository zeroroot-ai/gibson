// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

// originate.go: the server-side policy for a mission ORIGINATED by an
// off-cluster component (gibson#1358, owner decision recorded on
// gibson#1186 2026-08-09).
//
// Origination is not creation. Every other CreateMission path in the daemon
// is driven by a human or by the orchestrator on a human's behalf, so the
// authority question is already settled before the record is written. A
// component asking for a NEW mission has to answer it here, in one place,
// before anything is persisted:
//
//	budget   the child's envelope is clamped to what the parent has left and
//	         RESERVED against it, so parallel children cannot together
//	         over-commit the same money (reservation.go).
//	scope    the child's target UUID set must be a subset of the parent's
//	         (scope.go's TargetSetSubset). Widening is refused; no code path
//	         here grows it.
//	lineage  {originating component, capability-grant id, parent mission id,
//	         parent work id} is recorded on the child at creation, from the
//	         VERIFIED caller identity — never from the request payload.
//
// The parent is mandatory, permanently. This is an invariant, not a gap.
//
// The 2026-08-09 decision also contemplated a "grant-only" origination — no
// parent at all, clamped by a tenant per-mission cap. **That was reversed by
// the owner on 2026-08-16 — ADR-0063, gibson#1398.** A component may only originate a
// mission from inside one it was dispatched to. There is no plan to add the
// no-parent path, and the two primitives it would have needed — a target
// allow-list on the capability grant, and a per-mission tenant cost cap —
// are not being built for this purpose.
//
// The reason the reversal is the right call is visible in the three clauses
// above: every bound this file enforces is expressed RELATIVE TO A PARENT.
// The budget is a reservation against the parent's remainder; the scope is a
// subset of the parent's targets; the lineage names the parent. Remove the
// parent and all three need a separate, independently-maintained source of
// truth for "how much" and "against what" — a second authority path for the
// same question, which is the thing that goes wrong quietly. Requiring a
// parent means an agent can never widen scope or spend beyond an envelope a
// human already approved, because there is always a human-approved mission
// above it.
//
// Do not re-add the no-parent path without a new ADR superseding ADR-0063. If
// one ever comes, it needs the two primitives first — allowing it without them
// would mean unbounded budget and unbounded target scope.
//
// This lives in internal/engine/mission, next to the Mission type, the
// reservation ledger and the subset check it composes — not in the daemon
// package and not in internal/platform/component — so it is unit-testable
// against a fake store and miniredis, with no gRPC server and no daemon.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// Lineage metadata keys written on a component-originated mission. They are
// plain Mission.Metadata entries rather than new struct fields because the
// durable home for lineage is the Timeline (ADR-0011), and the Timeline's
// Append is documented as callable only from the ECS-brain World engine's
// single tick goroutine — a concurrent gRPC handler cannot write it today
// (gibson#1358 gap 3). Metadata is the interim, explicitly-temporary home;
// the follow-up migrates these four keys into a Timeline event once the
// World engine has a command-intake path a handler may use.
const (
	// LineageOriginatingComponent is the FGA principal ref of the component
	// that asked for the mission ("agent_principal:<id>"), taken from the
	// request's verified identity.
	LineageOriginatingComponent = "originating_component"
	// LineageCapabilityGrantID is the id of the ACTIVE capability grant that
	// carried mission:originate at the moment of the call. Recorded so a
	// later revocation still leaves an answer to "which grant authorized
	// this mission".
	LineageCapabilityGrantID = "capability_grant_id"
	// LineageParentMissionID is the originating mission, resolved server-side
	// from the caller's work item.
	LineageParentMissionID = "parent_mission_id"
	// LineageParentWorkID is the work item the caller was executing.
	LineageParentWorkID = "parent_work_id"
)

// MaxOriginationDepth bounds how deep a chain of component-originated
// missions may go. Mirrors harness.DefaultSpawnLimits().MaxMissionDepth
// (internal/engine/harness/limits.go) rather than importing it — harness
// imports this package, so the dependency cannot point the other way. The
// two must stay in step: an off-cluster caller and an in-cluster harness
// spawning the same chain should hit the same wall.
const MaxOriginationDepth = 3

// Origination errors. Callers map these to gRPC statuses; they are values,
// not strings, so a handler test can assert the reason rather than a
// substring.
var (
	// ErrNoParentMission is returned when the caller has no resolvable
	// parent mission. This is permanent: a component originates a mission
	// only from inside one it was dispatched to (ADR-0063 / gibson#1398,
	// 2026-08-16, reversing the grant-only case contemplated on 2026-08-09).
	// See the file comment for why every bound here is parent-relative.
	ErrNoParentMission = errors.New("mission: origination requires a parent mission")
	// ErrScopeWiden is returned when the requested target set is not a
	// subset of the parent's target set.
	ErrScopeWiden = errors.New("mission: origination target scope exceeds the parent mission's targets")
	// ErrDepthExceeded is returned when the child would sit deeper than
	// MaxOriginationDepth.
	ErrDepthExceeded = errors.New("mission: origination would exceed the maximum mission depth")
	// ErrLineageSupplied is returned when the request's mission definition
	// metadata already carries lineage keys. Lineage is asserted by the
	// daemon from the verified identity; a caller that supplies its own is
	// trying to forge attribution, and the request is refused rather than
	// silently overwritten.
	ErrLineageSupplied = errors.New("mission: origination lineage may not be supplied by the caller")
	// ErrMissingAttribution is returned when the caller's principal or grant
	// id is empty. Lineage is mandatory (owner decision 4), so a mission
	// that cannot be attributed is not created.
	ErrMissingAttribution = errors.New("mission: origination requires the caller's principal and capability-grant id")
)

// OriginateRequest is everything Originate needs. Every field is filled by
// the daemon from verified request state: Parent from the work item the
// caller was dispatched, Principal and GrantID from the caller's identity
// and its resolved capability grant. Nothing here may be read from a
// request payload except the definition, the target and the name.
type OriginateRequest struct {
	// Parent is the originating mission, already loaded from the caller's
	// tenant store. Required.
	Parent *Mission

	// ParentWorkID is the work item the caller was executing when it asked.
	// Lineage only.
	ParentWorkID string

	// Principal is the caller's verified FGA principal ref.
	Principal string

	// GrantID is the id of the active capability grant that carried
	// mission:originate.
	GrantID string

	// DefinitionJSON is the caller-supplied mission definition. Its
	// Constraints are treated as the REQUESTED budget and are replaced by
	// what the ledger actually grants.
	DefinitionJSON []byte

	// TargetIDs is the child's requested target set. Must be a subset of
	// Parent.TargetSet(). Empty claims no target scope at all.
	TargetIDs []types.ID
}

// Saver is the sliver of MissionStore that Originate needs. Narrow
// on purpose: origination writes one new record and reads nothing, so the
// policy is testable against four lines of fake instead of the thirty-method
// MissionStore. *ConnBoundMissionStore satisfies it.
type Saver interface {
	Save(ctx context.Context, m *Mission) error
}

// Originator applies the origination policy and persists the child mission.
type Originator struct {
	store  Saver
	ledger ReservationLedger
	logger *slog.Logger
}

// NewOriginator constructs an Originator. store and ledger must both be
// bound to the CALLER'S tenant already (the per-tenant Conn is the isolation
// boundary — there is no tenant argument anywhere below, deliberately, so
// there is nothing for a payload to influence). logger may be nil.
func NewOriginator(store Saver, ledger ReservationLedger, logger *slog.Logger) *Originator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Originator{store: store, ledger: ledger, logger: logger}
}

// Originate validates the request against the parent's budget and scope,
// reserves the child's envelope, and saves the child mission.
//
// Ordering matters and is not arbitrary: everything that can refuse runs
// BEFORE the reservation, so a refused origination never leaves money
// promised to a child that was never created. The one operation that can
// still fail after the reservation is the store Save, which compensates by
// releasing it.
func (o *Originator) Originate(ctx context.Context, req OriginateRequest) (*Mission, error) {
	if req.Parent == nil {
		return nil, ErrNoParentMission
	}
	if req.Principal == "" || req.GrantID == "" {
		return nil, ErrMissingAttribution
	}

	// Depth. Parent.Depth is the parent's own level; the child sits one
	// below it.
	childDepth := req.Parent.Depth + 1
	if childDepth >= MaxOriginationDepth {
		return nil, fmt.Errorf("%w: parent is at depth %d, limit %d",
			ErrDepthExceeded, req.Parent.Depth, MaxOriginationDepth)
	}

	// Scope. The subset check is the whole rules-of-engagement rule: the
	// child may test the parent's targets or fewer, never more.
	if !TargetSetSubset(req.TargetIDs, req.Parent.TargetSet()) {
		return nil, fmt.Errorf("%w: parent mission %s", ErrScopeWiden, req.Parent.ID)
	}

	def, err := parseOriginationDefinition(req.DefinitionJSON)
	if err != nil {
		return nil, err
	}

	// Budget. The definition's own constraints are the REQUEST; what comes
	// back from the ledger is the grant, and it is what the child mission
	// records. A caller that asks for more than the parent has left gets
	// the remainder, not an error — that is the "clamp" half of
	// "clamped and reserved".
	requested := requestedBudget(def.GetConstraints())
	childID := types.NewID()
	granted, reserveErr := o.ledger.Reserve(ctx, req.Parent, childID, requested)
	if reserveErr != nil {
		return nil, fmt.Errorf("mission: originate: reserve against parent %s: %w", req.Parent.ID, reserveErr)
	}

	child, buildErr := o.buildChild(childID, childDepth, def, granted, req)
	if buildErr != nil {
		o.releaseAfterFailure(ctx, req.Parent.ID, childID)
		return nil, buildErr
	}

	if saveErr := o.store.Save(ctx, child); saveErr != nil {
		// The reservation outlives nothing: no child exists to spend it.
		o.releaseAfterFailure(ctx, req.Parent.ID, childID)
		return nil, fmt.Errorf("mission: originate: save child mission: %w", saveErr)
	}

	o.logger.InfoContext(ctx, "component originated a mission",
		slog.String("mission_id", child.ID.String()),
		slog.String("parent_mission_id", req.Parent.ID.String()),
		slog.String("originating_component", req.Principal),
		slog.String("capability_grant_id", req.GrantID),
		slog.Int("depth", child.Depth),
		slog.Int("target_count", len(child.TargetSet())),
	)
	return child, nil
}

// releaseAfterFailure undoes a reservation on a path that is already
// failing. A release error here cannot change the outcome the caller sees —
// the origination failed either way — so it is logged, not returned, and
// deliberately not wrapped into the returned error: the caller needs to know
// why origination was refused, not that the cleanup of the refusal also had
// trouble.
func (o *Originator) releaseAfterFailure(ctx context.Context, parentID, childID types.ID) {
	if err := o.ledger.Release(ctx, parentID, childID); err != nil {
		o.logger.ErrorContext(ctx, "mission: originate: failed to release the reservation of a mission that was never created",
			slog.String("parent_mission_id", parentID.String()),
			slog.String("child_mission_id", childID.String()),
			slog.String("error", err.Error()),
		)
	}
}

// buildChild assembles the child Mission record. Split out from Originate so
// the assembly (and its lineage-forgery refusal) is testable without a
// ledger.
func (o *Originator) buildChild(
	childID types.ID,
	childDepth int,
	def *missionv1.MissionDefinition,
	granted ChildBudget,
	req OriginateRequest,
) (*Mission, error) {
	// Lineage is asserted, never accepted. A definition that already names
	// any lineage key is refused outright rather than overwritten: the
	// caller had no legitimate reason to set it, and silently correcting a
	// forgery attempt hides it.
	for _, k := range []string{
		LineageOriginatingComponent,
		LineageCapabilityGrantID,
		LineageParentMissionID,
		LineageParentWorkID,
	} {
		if _, present := def.GetMetadata()[k]; present {
			return nil, fmt.Errorf("%w: %q", ErrLineageSupplied, k)
		}
	}

	defJSON, marshalErr := MarshalDefinitionJSON(def)
	if marshalErr != nil {
		return nil, fmt.Errorf("mission: originate: marshal definition: %w", marshalErr)
	}

	parentID := req.Parent.ID
	child := &Mission{
		ID:                    childID,
		TenantID:              req.Parent.TenantID,
		Name:                  def.GetName(),
		Description:           def.GetDescription(),
		Status:                MissionStatusPending,
		MissionDefinitionID:   types.ID(def.GetId()),
		MissionDefinitionJSON: string(defJSON),
		Constraints:           grantedConstraints(def.GetConstraints(), granted),
		ParentMissionID:       &parentID,
		Depth:                 childDepth,
		Metadata: map[string]any{
			LineageOriginatingComponent: req.Principal,
			LineageCapabilityGrantID:    req.GrantID,
			LineageParentMissionID:      parentID.String(),
			LineageParentWorkID:         req.ParentWorkID,
		},
	}
	if len(req.TargetIDs) > 0 {
		child.TargetID = req.TargetIDs[0]
		if len(req.TargetIDs) > 1 {
			child.AdditionalTargetIDs = append([]types.ID(nil), req.TargetIDs[1:]...)
		}
	}
	return child, nil
}

// parseOriginationDefinition decodes the caller's mission definition. An
// absent definition is an empty one, matching missionHarnessAdapter's
// CreateMission; a malformed one is an error, because guessing at a
// half-parsed definition would mean creating a mission the caller did not
// describe.
func parseOriginationDefinition(raw []byte) (*missionv1.MissionDefinition, error) {
	if len(raw) == 0 {
		return &missionv1.MissionDefinition{}, nil
	}
	def, err := UnmarshalDefinitionJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("mission: originate: parse definition: %w", err)
	}
	if def == nil {
		return &missionv1.MissionDefinition{}, nil
	}
	return def, nil
}

// requestedBudget reads the caller's asked-for envelope out of the mission
// definition's constraints. The proto's own convention — 0 means "no limit"
// on both max_cost and max_tokens — maps to a nil ChildBudget field, i.e.
// "the caller named no ceiling on this dimension", which lets the ledger
// answer with the parent's remainder instead.
func requestedBudget(c *missionv1.MissionConstraints) ChildBudget {
	out := ChildBudget{}
	if c == nil {
		return out
	}
	if c.GetMaxCost() > 0 {
		cents := CostCentsFromDollars(c.GetMaxCost())
		out.CostUSDCents = &cents
	}
	if c.GetMaxTokens() > 0 {
		tokens := c.GetMaxTokens()
		out.Tokens = &tokens
	}
	return out
}

// grantedConstraints rewrites the child's constraints so the mission record
// carries what was RESERVED, not what was asked for. Every other consumer of
// Mission.Constraints (the budget enforcer, the orchestrator, the run
// report) then sees the clamped envelope without knowing origination
// happened — which is the point: a reservation nobody enforces is a comment.
//
// The rest of the caller's constraints (timeouts, concurrency, whatever the
// proto grows next) is preserved as supplied; only the two budget dimensions
// the ledger arbitrates are overwritten.
func grantedConstraints(requested *missionv1.MissionConstraints, granted ChildBudget) *missionv1.MissionConstraints {
	out := &missionv1.MissionConstraints{}
	if requested != nil {
		cloned, ok := proto.Clone(requested).(*missionv1.MissionConstraints)
		if ok {
			out = cloned
		}
	}
	if granted.CostUSDCents != nil {
		out.MaxCost = DollarsFromCostCents(*granted.CostUSDCents)
	}
	if granted.Tokens != nil {
		out.MaxTokens = *granted.Tokens
	}
	return out
}
