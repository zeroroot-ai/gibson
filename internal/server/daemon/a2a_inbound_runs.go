// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
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

// inboundStartBound bounds the claim, the reserve and the start of one message. It
// is far under inboundmissionstore.MessageLease, so a start that is still in work
// when the lease ends cannot happen. A second call then never starts a second mission.
const inboundStartBound = inboundmissionstore.MessageLease / 5

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
	// flight shares one build of a result between parallel reads of a mission.
	flight singleflight.Group
	// gate bounds the results in work for a tenant and for a caller.
	gate *resultGate
	// buildTimeout bounds the build of one result. Zero means the default.
	buildTimeout time.Duration
	// stop ends a running mission of the tenant on the context.
	stop func(ctx context.Context, missionID string) error
	// startBound bounds the claim of the message id, the reserve and the start. Zero
	// means inboundStartBound. A test sets it.
	startBound time.Duration
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
		return a2aserver.RejectedTask(a2aserver.ReasonAgentNotAvailable), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the publication of agent %s: %w", req.Agent, err)
	}

	targets, err := r.narrowedTargets(pub, req.Message)
	if err != nil {
		var refused refusedTargets
		if errors.As(err, &refused) {
			return a2aserver.RejectedTask(refused.Error()), nil
		}
		return nil, err
	}

	// The webhook of the message is data. It goes to the mission as typed task
	// data, never into the task input text and never into an instruction.
	var taskData map[string]any
	if hook, present, werr := a2aserver.WebhookOf(req.Message); werr != nil {
		return nil, fmt.Errorf("read the webhook of the message: %w", werr)
	} else if present {
		taskData = map[string]any{a2aserver.WebhookKey: hook}
	}

	tenant, err := auth.NewTenantID(c.Tenant)
	if err != nil {
		return nil, fmt.Errorf("%w: the tenant of the caller is not valid", a2aserver.ErrRefused)
	}
	ctx = auth.ContextWithTenant(ctx, tenant)
	// The definition and the targets must be what the admin approved at publish. A
	// change after that gives a rejected Task and no mission.
	reason, def, err := api.InboundStaleReason(ctx, r.source, *pub, targets)
	if err != nil {
		return nil, fmt.Errorf("check the publication of agent %s: %w", req.Agent, err)
	}
	if reason != "" {
		return a2aserver.RejectedTask(reason + ". An admin of the tenant must publish it again"), nil
	}
	// A run against more than one target needs a for_each node. Without it the daemon
	// would fail the mission after it started. The message gets the reason at once.
	if len(targets) > 1 && !def.FansOut {
		return a2aserver.RejectedTask("the definition has no for_each node, so one message can use one target only. " +
			"Name one target in a data part"), nil
	}
	ctx = auth.WithIdentity(ctx, auth.Identity{
		Subject: c.Subject, Issuer: auth.IssuerCapabilityGrant, CredentialType: auth.CredentialCapabilityGrant,
		Tenant: tenant,
	})
	// The task row is written before the mission record, and it takes the ID that
	// the mission record will take. A running mission therefore always has its row.
	missionID := types.NewID().String()
	// A message id that this agent of the tenant already started a mission for
	// starts no second mission. The key holds the agent, so one id sent to two
	// agents starts both. It is kept in the database of the tenant, so the same id
	// in another tenant is a new id. The claim is a lease. A start that fails gives
	// it back, and a daemon that stops loses it when the lease ends, so no message
	// is lost for good. The claim is confirmed only after the start succeeded.
	bound := r.startBound
	if bound <= 0 {
		bound = inboundStartBound
	}
	// The detached context still ends the claim, the reserve and the start before the
	// lease of the claim ends. The calls that undo them use a context of their own.
	baseCtx := ctx
	ctx, cancelBound := context.WithTimeout(ctx, bound)
	defer cancelBound()
	msgKey := ""
	if k := a2aserver.WebhookMessageKey(req.Message); k != "" {
		msgKey = req.Agent + "\x00" + k
		claim, cerr := r.published.ClaimMessage(ctx, c.Tenant, msgKey, missionID)
		if cerr != nil {
			return nil, fmt.Errorf("record the message id for agent %s: %w", req.Agent, cerr)
		}
		switch claim {
		case inboundmissionstore.ClaimNew:
			// The caller may start the mission.
		case inboundmissionstore.ClaimDuplicate:
			return a2aserver.RejectedTask("duplicate"), nil
		case inboundmissionstore.ClaimInFlight:
			return nil, fmt.Errorf("%w: agent %s", a2aserver.ErrInFlight, req.Agent)
		}
	}
	forget := func() error {
		if msgKey == "" {
			return nil
		}
		return r.published.ForgetMessage(context.WithoutCancel(baseCtx), c.Tenant, msgKey, missionID)
	}
	slot, err := r.published.Reserve(ctx, c.Tenant, req.Agent, c.Subject, missionID)
	switch {
	case errors.Is(err, inboundmissionstore.ErrNotFound):
		if ferr := forget(); ferr != nil {
			return nil, fmt.Errorf("give back the message id for agent %s: %w", req.Agent, ferr)
		}
		return a2aserver.RejectedTask(a2aserver.ReasonAgentNotAvailable), nil
	case err != nil:
		return nil, fmt.Errorf("record the task for agent %s: %w", req.Agent, errors.Join(err, forget()))
	}
	started, err := r.starter.StartMission(ctx, api.RunMissionData{
		MissionDefinitionID: pub.DefinitionID,
		MissionID:           missionID,
		TargetIDs:           targets,
		Variables:           map[string]string{inboundTaskInputVariable: a2aserver.TextOf(req.Message)},
		TaskData:            taskData,
		// The mission start compares the definition and the targets that it loads with
		// the pin of the publication, so a change after the check above starts nothing.
		PinnedDefinitionHash: pub.DefinitionHash,
		PinnedTargetHashes:   pinsOf(pub, targets),
		// Each message starts a new mission, so each one has a name of its own.
		NameSuffix: " (a2a " + strings.ReplaceAll(uuid.NewString(), "-", "")[:12] + ")",
		CreatedBy:  inboundPrincipal(c.Subject),
	})
	if err != nil {
		// The client may be gone, and the task row must still be deleted.
		rerr := errors.Join(r.published.Release(context.WithoutCancel(baseCtx), c.Tenant, slot), forget())
		// A tenant that is suspended, and a pin that does not match, are refusals
		// of policy. The Task is rejected, as for any other refusal of a well
		// formed message.
		if rerr == nil && status.Code(err) == codes.FailedPrecondition {
			return a2aserver.RejectedTask("the mission cannot start now: " + status.Convert(err).Message()), nil
		}
		if rerr != nil {
			err = errors.Join(err, rerr)
		}
		return nil, fmt.Errorf("start the mission of agent %s: %w", req.Agent, err)
	}
	if started != missionID {
		// The record has an ID that the row does not name. The mission ends, and the
		// task row is deleted.
		serr := r.stop(context.WithoutCancel(baseCtx), started)
		rerr := errors.Join(r.published.Release(context.WithoutCancel(baseCtx), c.Tenant, slot), forget())
		return nil, fmt.Errorf("the mission %s has an ID other than %s: %w", started, missionID, errors.Join(serr, rerr))
	}
	if msgKey != "" {
		// The mission runs. A key that cannot be confirmed stays a lease and is never
		// given back, so the mission is not started twice within the lease.
		cerr := r.published.ConfirmMessage(context.WithoutCancel(baseCtx), c.Tenant, msgKey, missionID)
		if errors.Is(cerr, inboundmissionstore.ErrNotFound) {
			// The claim is gone, so another call may have taken it over and may start a
			// second mission. This mission ends, and its task row is deleted.
			serr := r.stop(context.WithoutCancel(baseCtx), missionID)
			rerr := r.published.Release(context.WithoutCancel(baseCtx), c.Tenant, slot)
			return nil, fmt.Errorf("the claim of the message id of agent %s is gone, so mission %s ended: %w",
				req.Agent, missionID, errors.Join(cerr, serr, rerr))
		}
		if cerr != nil {
			// The row stays pending. The next claim cannot take it over while the task row
			// of this mission exists (inboundmissionstore.ClaimMessage).
			slog.WarnContext(ctx, "the message id of a started mission could not be confirmed",
				"tenant", c.Tenant, "agent", req.Agent, "mission_id", missionID, "error", cerr)
		}
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

// statusTask is the Task of a mission with its state and its message, and no
// result.
func statusTask(m brain.MissionSnapshot) *a2a.Task {
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
	return t
}

// taskOf is the Task of a mission. A mission in a final state also has its result.
// The result cache holds only results of missions in a final state.
func (r *inboundRuns) taskOf(ctx context.Context, c a2aserver.InboundCaller, m brain.MissionSnapshot) (*a2a.Task, error) {
	t := statusTask(m)
	if !m.Status.IsTerminal() {
		return t, nil
	}
	missionID, err := types.ParseID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("the mission ID %q is not a UUID: %w", m.ID, err)
	}
	// A result is held in memory while it is built and while the JSON-RPC layer
	// encodes it. A permit for the tenant and one for the caller bound the results in
	// work, and the permits end after the response is written. When no permit is
	// free the caller gets a retryable error.
	release, ok := r.gate.acquire(c.Tenant, c.Subject)
	if !ok {
		return nil, a2aserver.ErrBusy
	}
	// handedOff is set when this reader leaves while its build runs. The end of its
	// response then frees nothing, and the goroutine below frees the permit after
	// the build.
	var handedOff atomic.Bool
	a2aserver.AfterResponse(ctx, func() {
		if !handedOff.Load() {
			release()
		}
	})
	key := c.Tenant + "/" + m.ID
	if res, ok := r.results.get(key); ok {
		a2aserver.ExtendWriteDeadline(ctx, int64(res.size))
		return withResult(t, res), nil
	}
	// Parallel reads of one mission build the result once and share it. The build
	// does not stop when one reader leaves, because the other readers use it. It stops
	// after the build timeout. Each reader leaves when its own context ends.
	ch := r.flight.DoChan(key, func() (val any, err error) {
		// singleflight re-raises a panic of the function in a new goroutine, and
		// nothing can recover it there. The panic becomes an error here, so one bad
		// finding cannot stop the daemon.
		defer func() {
			if rec := recover(); rec != nil {
				slog.ErrorContext(ctx, "inbound result build panicked",
					"mission", m.ID, "panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				val, err = inboundResult{}, fmt.Errorf("the result of mission %s could not be built", m.ID)
			}
		}()
		if res, ok := r.results.get(key); ok {
			return res, nil
		}
		bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.buildTimeoutOrDefault())
		defer cancel()
		res, err := r.buildResult(bctx, c.Tenant, missionID)
		if err != nil {
			return inboundResult{}, err
		}
		r.results.put(key, res)
		return res, nil
	})
	var v any
	select {
	case <-ctx.Done():
		// The build goes on for the other readers, and it holds memory. The permit
		// of this reader stays until the build ends, so a caller that asks and
		// leaves cannot start more builds than the bounds allow.
		handedOff.Store(true)
		go func() {
			<-ch
			release()
		}()
		return nil, fmt.Errorf("read the result: %w", ctx.Err())
	case out := <-ch:
		if out.Err != nil {
			// A failed build holds no result, so its permit goes back at once.
			release()
			if errors.Is(out.Err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("%w: the result of mission %s is not ready", a2aserver.ErrBusy, m.ID)
			}
			return nil, fmt.Errorf("read the result: %w", out.Err)
		}
		v = out.Val
	}
	res, _ := v.(inboundResult)
	a2aserver.ExtendWriteDeadline(ctx, int64(res.size))
	return withResult(t, res), nil
}

// inboundResultBuildTimeout is the longest time to build one result.
const inboundResultBuildTimeout = 5 * time.Minute

func (r *inboundRuns) buildTimeoutOrDefault() time.Duration {
	if r.buildTimeout > 0 {
		return r.buildTimeout
	}
	return inboundResultBuildTimeout
}

// resultGate bounds the results that are in work for the daemon, for one tenant and
// for one caller. A permit is taken without waiting, so a busy daemon answers at
// once.
type resultGate struct {
	mu                              sync.Mutex
	globalMax, tenantMax, callerMax int
	global                          int
	tenants, callers                map[string]int
}

// newResultGate returns a gate with the three bounds. A bound under 1 is 1.
func newResultGate(globalMax, tenantMax, callerMax int) *resultGate {
	return &resultGate{
		globalMax: max(globalMax, 1), tenantMax: max(tenantMax, 1), callerMax: max(callerMax, 1),
		tenants: map[string]int{}, callers: map[string]int{},
	}
}

// acquire takes one global permit, one for the tenant and one for the caller. It returns the
// function that gives both back, or false when either bound is full. The function
// is safe to call more than one time.
func (g *resultGate) acquire(tenant, caller string) (release func(), ok bool) {
	if g == nil {
		return func() {}, true // a runs value with no gate bounds nothing, as in a unit test
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	ck := tenant + "/" + caller
	if g.global >= g.globalMax || g.tenants[tenant] >= g.tenantMax || g.callers[ck] >= g.callerMax {
		return nil, false
	}
	g.global++
	g.tenants[tenant]++
	g.callers[ck]++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.global--
			g.tenants[tenant]--
			if g.tenants[tenant] == 0 {
				delete(g.tenants, tenant)
			}
			g.callers[ck]--
			if g.callers[ck] == 0 {
				delete(g.callers, ck)
			}
		})
	}, true
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
	// World folds it on its next tick. The answer holds the status and no result:
	// the findings of a mission that is still ending are not final, so they are not
	// built and not cached. A read of the Task after the end gives the result.
	m.Status = brain.MissionCanceled
	m.Reason = "canceled by " + c.Subject
	return statusTask(m), nil
}

// pinsOf returns the pinned hash of each target that the mission uses.
func pinsOf(pub *inboundmissionstore.Entry, targets []string) map[string]string {
	out := make(map[string]string, len(targets))
	for _, id := range targets {
		out[id] = pub.TargetHashes[id]
	}
	return out
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
