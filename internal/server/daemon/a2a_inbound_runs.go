// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"

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
	starter   missionStarter
}

var _ a2aserver.InboundRuns = (*inboundRuns)(nil)

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
	ctx = auth.WithIdentity(ctx, auth.Identity{
		Subject: c.Subject, Issuer: auth.IssuerCapabilityGrant, CredentialType: auth.CredentialCapabilityGrant,
		Tenant: tenant,
	})
	missionID, err := r.starter.StartMission(ctx, api.RunMissionData{
		MissionDefinitionID: pub.DefinitionID,
		TargetIDs:           targets,
		Variables:           map[string]string{inboundTaskInputVariable: a2aserver.TextOf(req.Message)},
		// Each message starts a new mission, so each one has a name of its own.
		NameSuffix: " (a2a " + strings.ReplaceAll(uuid.NewString(), "-", "")[:12] + ")",
		CreatedBy:  inboundPrincipal(c.Subject),
	})
	if err != nil {
		return nil, err
	}
	return &a2a.Task{
		ID: a2a.TaskID(missionID), ContextID: missionID,
		Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted},
	}, nil
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
		return nil, err
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
