// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// A bank member runs an always-on loop. It has no mission turn, so it has no
// grant of a sender to call a tool with. A tenant admin gives the member a loop
// grant instead (gibson#1612). The grant names tool classes and harness calls, is
// bound to the member and to the tenant, and never reaches another member or
// another tenant.

// LoopGrant is the loop grant of one bank member in one tenant.
type LoopGrant struct {
	// ID names the grant. The audit record of each member call holds it.
	ID string
	// MemberID is the bank member that holds the grant.
	MemberID string
	// AgentName is the catalog agent of the member when the grant was made. A
	// member whose verified grant names another agent does not use the grant.
	AgentName string
	// ToolClasses are tool classes of the catalog, for example ticket.
	ToolClasses []string
	// HarnessCalls are the harness calls besides the tool call.
	HarnessCalls []string
	// Grantor is the subject of the admin who gave the grant.
	Grantor string
}

// ErrNoLoopGrant is what a LoopGrantSource answers for a member with no grant.
var ErrNoLoopGrant = errors.New("harness: the member holds no loop grant")

// LoopGrantSource reads the loop grant of a bank member in a tenant. The daemon
// backs it with the per-tenant store. The tenant and the member are the ones of
// the verified grant of the call, so a source never answers with the grant of
// another tenant or another member.
type LoopGrantSource interface {
	LoopGrantFor(ctx context.Context, tenant, memberID string) (*LoopGrant, error)
}

// WithLoopGrants wires the source of the loop grants of bank members.
func WithLoopGrants(src LoopGrantSource) CallbackServiceOption {
	return func(c *HarnessCallbackService) { c.loopGrants = src }
}

// covers reports whether the grant holds the class.
func (g *LoopGrant) covers(class string) bool {
	return g != nil && class != "" && slices.Contains(g.ToolClasses, class)
}

// memberCall is the identity of a member behind a call, read from the verified
// base grant of the member. It never comes from the body of a request.
type memberCall struct {
	tenant   string
	agent    string
	memberID string
	bankID   string
	runID    string
}

// memberOfCall returns the member behind the call, or false when the call is
// not the call of a member. The grant must be the base grant of the member: its
// subject names an agent, its mission is the bank and its task is the member.
// A turn grant has the sender as its subject and so is no member call. A lookup
// that fails is an error, never "not a member", because that reading would let
// a member act with no loop grant while the bank store is down.
func (s *HarnessCallbackService) memberOfCall(ctx context.Context) (memberCall, bool, error) {
	claims, ok := TaskGrantClaimsFromContext(ctx)
	if !ok {
		return memberCall{}, false, nil
	}
	agent, isAgent := grantAgentName(claims)
	if !isAgent || claims.MissionRunID == "" {
		return memberCall{}, false, nil
	}
	tenant := claims.Tenant.String()
	memberID, bankID, err := s.members.MemberByRun(ctx, tenant, claims.MissionRunID)
	switch {
	case errors.Is(err, ErrNotAMember), errors.Is(err, ErrNoBankSurface):
		return memberCall{}, false, nil
	case err != nil:
		return memberCall{}, false, fmt.Errorf("resolve the calling member: %w", err)
	}
	if claims.MissionID != bankID || claims.TaskID != memberID {
		return memberCall{}, false, nil
	}
	return memberCall{tenant: tenant, agent: agent, memberID: memberID, bankID: bankID, runID: claims.MissionRunID}, true, nil
}

// loopGrant reads the grant of the member. A missing grant is ErrNoLoopGrant. A
// grant that names another agent than the agent of the verified grant of the
// member is no grant of this member.
func (s *HarnessCallbackService) loopGrant(ctx context.Context, m memberCall) (*LoopGrant, error) {
	if s.loopGrants == nil {
		return nil, ErrNoLoopGrant
	}
	g, err := s.loopGrants.LoopGrantFor(ctx, m.tenant, m.memberID)
	if err != nil {
		if errors.Is(err, ErrNoLoopGrant) {
			return nil, ErrNoLoopGrant
		}
		return nil, fmt.Errorf("read the loop grant of member %q: %w", m.memberID, err)
	}
	if g == nil || g.MemberID != m.memberID || g.AgentName != m.agent {
		return nil, ErrNoLoopGrant
	}
	return g, nil
}

// contextInfo is the ContextInfo of a member call. It holds the bank, the run and
// the agent that the verified grant names. The request of the member never
// chooses them: the flight recorder, the merge check and the approval request
// all read this value, so a member cannot act in the mission of another.
func (m memberCall) contextInfo() *harnesspb.ContextInfo {
	return &harnesspb.ContextInfo{MissionId: m.bankID, MissionRunId: m.runID, AgentName: m.agent}
}

// ownsContext reports whether the ContextInfo of a request names only what the
// member owns. An empty field names nothing. A field that names another mission,
// run or agent is a refusal.
func (m memberCall) ownsContext(info *harnesspb.ContextInfo) bool {
	if info == nil {
		return true
	}
	return (info.GetMissionId() == "" || info.GetMissionId() == m.bankID) &&
		(info.GetMissionRunId() == "" || info.GetMissionRunId() == m.runID) &&
		(info.GetAgentName() == "" || info.GetAgentName() == m.agent)
}

// loopCheck is the metatool.LoopCheck of a member call. It reads the grant per
// call, so a revoked grant stops the next call. It reads the class of the
// connector from the catalog manifest at call time (connectorToolClass), so a
// grant of a class covers each connector of the class, now and later. The
// tenant enable of the connector is the can_execute check that runs after it.
func (s *HarnessCallbackService) loopCheck(m memberCall) metatool.LoopCheck {
	return func(ctx context.Context, connector string) (metatool.LoopAllow, error) {
		g, err := s.loopGrant(ctx, m)
		switch {
		case errors.Is(err, ErrNoLoopGrant):
			return metatool.LoopAllow{}, fmt.Errorf("%w: agent %q has no loop grant", metatool.ErrLoopGrantDenied, m.agent)
		case err != nil:
			return metatool.LoopAllow{}, fmt.Errorf("%w: %w", metatool.ErrLoopGrantUnavailable, err)
		}
		allow := metatool.LoopAllow{GrantID: g.ID, Grantor: g.Grantor}
		class := connectorToolClass(connector)
		if !g.covers(class) {
			return allow, fmt.Errorf("%w: the grant does not hold the class %q of connector %q",
				metatool.ErrLoopGrantDenied, class, connector)
		}
		return allow, nil
	}
}
