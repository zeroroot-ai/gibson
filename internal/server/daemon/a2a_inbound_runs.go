// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/inboundmissionstore"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	"github.com/zeroroot-ai/sdk/auth"
)

// inboundTaskInputVariable is the mission variable that holds the text of an
// inbound message. The text is the task input. The daemon never reads a target
// from it.
const inboundTaskInputVariable = "a2a_task_input"

// missionStarter starts a mission for a caller. *api.DaemonServer is the one
// implementation, and the RunMission RPC uses the same function.
type missionStarter interface {
	StartMission(ctx context.Context, req api.RunMissionData) (string, error)
}

// inboundRuns starts the missions of inbound A2A messages (epic gibson#1367). It
// holds the policy that is the entry point's own: the mapping from an agent name
// to a published definition, and from a data part to a narrower target list.
// Everything else is the mission start function that the MCP mission tool uses.
type inboundRuns struct {
	published inboundmissionstore.Store
	// source reads the definition and the targets, to compare them with the pin.
	source   api.InboundMissionSource
	starter  missionStarter
	registry *brain.Registry
	findings missionFindingReader
	// results keeps the results of finished missions, so a repeated read does not
	// load the findings again.
	results resultCache
	// stop ends a running mission of the tenant on the context.
	stop func(ctx context.Context, missionID string) error
}

// inboundReservationGrace is how long a reserved place may wait for its mission. A
// reservation that never got a mission, for example after a crash, gives its place
// back after this time.
const inboundReservationGrace = 2 * time.Minute

// missionFinished returns the function that tells the store whether a mission has
// ended. A mission that the World does not hold yet has not ended.
func (r *inboundRuns) missionFinished(tenant string) func(missionID string) bool {
	return func(missionID string) bool {
		eng, ok := api.TenantEngine(r.registry, tenant)
		if !ok {
			return false
		}
		for _, m := range eng.Missions() {
			if m.ID == missionID {
				return m.Status.IsTerminal()
			}
		}
		return false
	}
}

// missionFindingReader reads the findings of one mission with all of their
// evidence, in the one read function that the Finding evidence epic added.
type missionFindingReader interface {
	// ReadFindings hands each finding of the mission to add, in pages. It keeps no
	// finding after add returns.
	ReadFindings(ctx context.Context, tenant string, missionID types.ID, add func(finding.EnhancedFinding) error) error
}

// findingPager is the part of pgstore.Store that reads a page of findings with
// their evidence.
type findingPager interface {
	FindWithEvidence(ctx context.Context, tenantID string, q pgstore.Query) ([]finding.EnhancedFinding, int, error)
}

// inboundFindingPage is the number of findings that one read holds. A page holds all
// evidence of its findings, so the page is small, and the memory of a read is the
// result plus one page.
const inboundFindingPage = 25

// pgMissionFindings reads every finding of one mission through
// pgstore.Store.FindWithEvidence. It reads page after page, so no finding is left
// out. The result has no size limit.
type pgMissionFindings struct{ store findingPager }

var _ missionFindingReader = pgMissionFindings{}

func (p pgMissionFindings) ReadFindings(
	ctx context.Context, tenant string, missionID types.ID, add func(finding.EnhancedFinding) error,
) error {
	read := 0
	for {
		page, total, err := p.store.FindWithEvidence(ctx, tenant,
			pgstore.Query{MissionID: missionID, Limit: inboundFindingPage, Offset: read})
		if err != nil {
			return fmt.Errorf("read the findings of mission %s: %w", missionID, err)
		}
		for _, f := range page {
			if err := add(f); err != nil {
				return err
			}
		}
		read += len(page)
		if len(page) == 0 || read >= total {
			return nil
		}
	}
}

// The result cache keeps the results of finished missions for a short time, so a
// repeated read does not load the findings again. It is bounded by the number of
// entries and by the total bytes of the results. A result that is larger than the
// byte budget is not cached. A finished mission can get a late finding, so a result
// does not stay for long.
const (
	resultCacheSize  = 128
	resultCacheBytes = 64 << 20
	resultCacheTTL   = 2 * time.Minute
)

// inboundResult is the built result of a finished mission.
type inboundResult struct {
	artifact *a2a.Artifact
	size     int
	at       time.Time
}

// resultCache keeps the results of finished missions, by tenant and mission. The
// oldest result goes first when the count or the bytes pass their bound.
type resultCache struct {
	mu      sync.Mutex
	entries map[string]inboundResult
	order   []string
	bytes   int
	now     func() time.Time
}

func (c *resultCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *resultCache) get(key string) (inboundResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.entries[key]
	if !ok {
		return inboundResult{}, false
	}
	if c.clock().Sub(r.at) > resultCacheTTL {
		c.drop(key)
		return inboundResult{}, false
	}
	return r, true
}

// put keeps a result. A result over the byte budget is not kept.
func (c *resultCache) put(key string, r inboundResult) {
	if r.size > resultCacheBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]inboundResult{}
	}
	if _, ok := c.entries[key]; ok {
		c.drop(key)
	}
	for len(c.order) > 0 && (len(c.order) >= resultCacheSize || c.bytes+r.size > resultCacheBytes) {
		c.drop(c.order[0])
	}
	r.at = c.clock()
	c.entries[key] = r
	c.bytes += r.size
	c.order = append(c.order, key)
}

// drop removes one entry. The caller holds the lock.
func (c *resultCache) drop(key string) {
	if r, ok := c.entries[key]; ok {
		c.bytes -= r.size
	}
	delete(c.entries, key)
	c.order = slices.DeleteFunc(c.order, func(k string) bool { return k == key })
}

// Start starts a new mission from the definition that the tenant published under
// the agent name. The mission has the targets of the publication, or the targets
// of the data part when it names a subset. The targets, the budget and the scope
// come from the publication and the definition, and the message sets nothing
// else. A refused message gets a Task in the state rejected, and no mission
// starts.
func (r *inboundRuns) Start(ctx context.Context, req a2aserver.InboundStart) (*a2a.Task, error) {
	c := req.Caller
	pub, err := r.published.Get(ctx, c.Tenant, req.Agent)
	if errors.Is(err, inboundmissionstore.ErrNotFound) {
		return rejectedInboundTask("the agent is not published for inbound calls"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the publication of agent %s: %w", req.Agent, err)
	}

	targets, err := r.narrowedTargets(pub, req.Message)
	if err != nil {
		var refused refusedTargets
		if errors.As(err, &refused) {
			return rejectedInboundTask(refused.Error()), nil
		}
		return nil, err
	}

	tenant, err := auth.NewTenantID(c.Tenant)
	if err != nil {
		return nil, fmt.Errorf("%w: the tenant of the caller is not valid", a2aserver.ErrRefused)
	}
	ctx = auth.ContextWithTenant(ctx, tenant)
	// The definition and the targets must be what the admin approved at publish. A
	// change after that gives a rejected Task and no mission.
	reason, err := api.InboundStaleReason(ctx, r.source, *pub, targets)
	if err != nil {
		return nil, fmt.Errorf("check the publication of agent %s: %w", req.Agent, err)
	}
	if reason != "" {
		return rejectedInboundTask(reason + ". An admin of the tenant must publish it again"), nil
	}
	ctx = auth.WithIdentity(ctx, auth.Identity{
		Subject: c.Subject, Issuer: auth.IssuerCapabilityGrant, CredentialType: auth.CredentialCapabilityGrant,
		Tenant: tenant,
	})
	// One place of the publication is reserved before the mission record is written.
	// The store counts in the database under a lock, so parallel messages and more
	// than one replica cannot go over the limit.
	slot, err := r.published.Reserve(ctx, c.Tenant, req.Agent, c.Subject, r.missionFinished(c.Tenant), inboundReservationGrace)
	switch {
	case errors.Is(err, inboundmissionstore.ErrLimit):
		return rejectedInboundTask(fmt.Sprintf("the agent already has its most active missions (%d). Wait for one to end", pub.MaxActive)), nil
	case errors.Is(err, inboundmissionstore.ErrNotFound):
		return rejectedInboundTask("the agent is not published for inbound calls"), nil
	case err != nil:
		return nil, fmt.Errorf("reserve a place for agent %s: %w", req.Agent, err)
	}
	missionID, err := r.starter.StartMission(ctx, api.RunMissionData{
		MissionDefinitionID: pub.DefinitionID,
		TargetIDs:           targets,
		Variables:           map[string]string{inboundTaskInputVariable: a2aserver.TextOf(req.Message)},
		// Each message starts a new mission, so each one has a name of its own.
		NameSuffix: " (a2a " + strings.ReplaceAll(uuid.NewString(), "-", "")[:12] + ")",
		CreatedBy:  inboundPrincipal(c.Subject),
	})
	if err != nil {
		rerr := r.published.Release(ctx, c.Tenant, slot)
		// A tenant that is suspended or over its quota is a refusal of policy. The
		// Task is rejected, as for any other refusal of a well formed message.
		if code := status.Code(err); rerr == nil && (code == codes.ResourceExhausted || code == codes.FailedPrecondition) {
			return rejectedInboundTask("the tenant cannot start a mission now: " + status.Convert(err).Message()), nil
		}
		if rerr != nil {
			err = errors.Join(err, rerr)
		}
		return nil, fmt.Errorf("start the mission of agent %s: %w", req.Agent, err)
	}
	if err := r.published.Bind(ctx, c.Tenant, slot, missionID); err != nil {
		// A mission that no task row names has no owner. It ends here.
		if serr := r.stop(ctx, missionID); serr != nil {
			err = errors.Join(err, serr)
		}
		return nil, fmt.Errorf("record the mission %s of agent %s: %w", missionID, req.Agent, err)
	}
	return &a2a.Task{
		ID: a2a.TaskID(missionID), ContextID: missionID,
		Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted},
	}, nil
}

// ownedMission returns the snapshot of a mission that the caller started. The
// task row in the database names the caller, so every replica gives the same
// answer. A mission that another caller started, a mission that no inbound call
// started and a mission that does not exist all give ErrNotFound, so the caller
// learns nothing about them. A mission that the World does not hold yet gives the
// snapshot of a submitted mission.
func (r *inboundRuns) ownedMission(ctx context.Context, c a2aserver.InboundCaller, agent, id string) (brain.MissionSnapshot, error) {
	owner, rowAgent, err := r.published.Owner(ctx, c.Tenant, id)
	// A Task belongs to the endpoint of the agent that it started from. A read or a
	// cancel through the path of another agent finds nothing, so a grant on agent B
	// never reaches a mission of agent A.
	if errors.Is(err, inboundmissionstore.ErrNotFound) || (err == nil && (owner != c.Subject || rowAgent != agent)) {
		return brain.MissionSnapshot{}, a2aserver.ErrNotFound
	}
	if err != nil {
		return brain.MissionSnapshot{}, fmt.Errorf("read the owner of mission %s: %w", id, err)
	}
	if eng, ok := api.TenantEngine(r.registry, c.Tenant); ok {
		for _, m := range eng.Missions() {
			if m.ID == id {
				return m, nil
			}
		}
	}
	return brain.MissionSnapshot{ID: id, Status: brain.MissionSubmitted}, nil
}

// inputRequiredText is the message of a Task that waits for an approval. An
// outside caller cannot answer it.
const inputRequiredText = "the mission waits for a person in the tenant to decide in the dashboard"

// Task returns the Task of a mission that the caller started. The Task state is
// the mission state, and a paused mission shows as working. A mission in a final
// state has the findings of that one mission in its result, with all of their
// evidence. The result has no size limit.
func (r *inboundRuns) Task(ctx context.Context, c a2aserver.InboundCaller, agent string, id a2a.TaskID) (*a2a.Task, error) {
	m, err := r.ownedMission(ctx, c, agent, string(id))
	if err != nil {
		return nil, err
	}
	return r.taskOf(ctx, c, m)
}

func (r *inboundRuns) taskOf(ctx context.Context, c a2aserver.InboundCaller, m brain.MissionSnapshot) (*a2a.Task, error) {
	now := time.Now().UTC()
	t := &a2a.Task{
		ID: a2a.TaskID(m.ID), ContextID: m.ID,
		Status: a2a.TaskStatus{State: brain.TaskStateFromMission(m.Status), Timestamp: &now},
	}
	switch m.Status {
	case brain.MissionInputRequired:
		t.Status.Message = a2a.NewMessageForTask(a2a.MessageRoleAgent, t, a2a.NewTextPart(inputRequiredText))
	case brain.MissionFailed, brain.MissionCanceled:
		if m.Reason != "" {
			t.Status.Message = a2a.NewMessageForTask(a2a.MessageRoleAgent, t, a2a.NewTextPart(m.Reason))
		}
	case brain.MissionSubmitted, brain.MissionWorking, brain.MissionPaused, brain.MissionCompleted:
		// These states have no message.
	}
	if !m.Status.IsTerminal() {
		return t, nil
	}
	missionID, err := types.ParseID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("the mission ID %q is not a UUID: %w", m.ID, err)
	}
	key := c.Tenant + "/" + m.ID
	if res, ok := r.results.get(key); ok {
		return withResult(t, res), nil
	}
	res, err := r.buildResult(ctx, c.Tenant, missionID)
	if err != nil {
		return nil, err
	}
	r.results.put(key, res)
	return withResult(t, res), nil
}

// buildResult reads the findings of a finished mission, page by page, and builds
// the artifact. The result always holds all findings with all of their evidence.
func (r *inboundRuns) buildResult(ctx context.Context, tenant string, missionID types.ID) (inboundResult, error) {
	b, err := a2aserver.NewResultBuilder(missionID.String())
	if err != nil {
		return inboundResult{}, fmt.Errorf("build the result of mission %s: %w", missionID, err)
	}
	if err := r.findings.ReadFindings(ctx, tenant, missionID, b.Add); err != nil {
		return inboundResult{}, fmt.Errorf("read the findings of mission %s: %w", missionID, err)
	}
	artifact, size, err := b.Artifact()
	if err != nil {
		return inboundResult{}, fmt.Errorf("build the result of mission %s: %w", missionID, err)
	}
	return inboundResult{artifact: artifact, size: size}, nil
}

func withResult(t *a2a.Task, res inboundResult) *a2a.Task {
	t.Artifacts = []*a2a.Artifact{res.artifact}
	return t
}

// Cancel ends a mission that the caller started. It ends no other mission: a
// mission of another caller is not found. A mission in a final state cannot be
// canceled.
func (r *inboundRuns) Cancel(ctx context.Context, c a2aserver.InboundCaller, agent string, id a2a.TaskID) (*a2a.Task, error) {
	m, err := r.ownedMission(ctx, c, agent, string(id))
	if err != nil {
		return nil, err
	}
	if m.Status.IsTerminal() {
		return nil, a2aserver.ErrNotCancelable
	}
	tenant, err := auth.NewTenantID(c.Tenant)
	if err != nil {
		return nil, fmt.Errorf("%w: the tenant of the caller is not valid", a2aserver.ErrRefused)
	}
	if err := r.stop(auth.ContextWithTenant(ctx, tenant), m.ID); err != nil {
		return nil, fmt.Errorf("end mission %s: %w", m.ID, err)
	}
	// The stop submitted the end of the mission, so the Task is canceled. The
	// World folds it on its next tick.
	m.Status = brain.MissionCanceled
	m.Reason = "canceled by " + c.Subject
	return r.taskOf(ctx, c, m)
}

// inboundPrincipal is the creator that a mission records for an inbound caller.
// The subject is the typed FGA principal of the enrolled agent identity.
func inboundPrincipal(subject string) principal.Principal {
	return principal.Principal{Kind: principal.Component, ID: subject}
}

// refusedTargets is a target list that the policy refuses.
type refusedTargets string

func (e refusedTargets) Error() string { return string(e) }

// narrowedTargets returns the targets of the mission. With no target list in the
// message, it is the whole published set. With a list, each target must be in the
// published set, and the list is the result. A target outside the set refuses the
// whole message. Only a data part can hold a list (a2aserver.TargetsOf), so no
// target comes from text.
func (r *inboundRuns) narrowedTargets(pub *inboundmissionstore.Entry, msg *a2a.Message) ([]string, error) {
	asked, present, err := a2aserver.TargetsOf(msg)
	if err != nil {
		return nil, fmt.Errorf("read the target list of the message: %w", err)
	}
	if !present {
		return slices.Clone(pub.TargetIDs), nil
	}
	seen := map[string]struct{}{}
	targets := make([]string, 0, len(asked))
	for _, id := range asked {
		if !slices.Contains(pub.TargetIDs, id) {
			return nil, refusedTargets("a target is outside the published definition: " + id)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		targets = append(targets, id)
	}
	return targets, nil
}

// rejectedInboundTask is the Task of a refused message. It holds no mission, so
// no one can read or cancel it later.
func rejectedInboundTask(reason string) *a2a.Task {
	id := uuid.NewString()
	t := &a2a.Task{ID: a2a.TaskID(id), ContextID: id, Status: a2a.TaskStatus{State: a2a.TaskStateRejected}}
	t.Status.Message = a2a.NewMessageForTask(a2a.MessageRoleAgent, t, a2a.NewTextPart(reason))
	return t
}
