// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// WorkTaskContextKey is the key of the work item Context that carries the id
// of the task of agent work. Only the daemon sets it, and Enqueue binds it to
// the work id with the name of the agent. A component request never sets it.
const WorkTaskContextKey = "gibson_task_id"

// workAgentKeyPrefix is the Redis key prefix of the agent that a work item
// belongs to.
const workAgentKeyPrefix = "gibson:work:agent:"

func workAgentKey(workID string) string { return workAgentKeyPrefix + workID }

// ErrWorkAgentUnknown is returned when a work id has no agent bound to it: the
// work is not agent work, or its binding has aged out.
var ErrWorkAgentUnknown = errors.New("work-context registry: no agent recorded for work id")

// WorkAgentRegistry records the agent and the task of agent work. The daemon
// finds the harness of a node, with its network scope, by this pair.
type WorkAgentRegistry interface {
	// WorkAgent returns the agent and the task of workID, or
	// ErrWorkAgentUnknown.
	WorkAgent(ctx context.Context, workID string) (agent, task string, err error)
}

var _ WorkAgentRegistry = (*RedisWorkContextRegistry)(nil)

type workAgentRecord struct {
	Agent string `json:"agent"`
	Task  string `json:"task,omitempty"`
}

// bindWorkAgent binds the agent of agent work to its work id, as Enqueue does for
// the run. Work of another kind binds nothing.
func bindWorkAgent(ctx context.Context, client redis.UniversalClient, kind, name string, item WorkItem) error {
	if kind != "agent" {
		return nil
	}
	raw, err := json.Marshal(workAgentRecord{Agent: name, Task: item.Context[WorkTaskContextKey]})
	if err != nil {
		return fmt.Errorf("work-context registry: encode the agent of work %q: %w", item.WorkID, err)
	}
	if err := client.Set(ctx, workAgentKey(item.WorkID), raw, workOwnerTTL).Err(); err != nil {
		return fmt.Errorf("work-context registry: bind agent of work %q: %w", item.WorkID, err)
	}
	return nil
}

// WorkAgent reads the agent and the task of a work item.
func (r *RedisWorkContextRegistry) WorkAgent(ctx context.Context, workID string) (agent, task string, err error) {
	if workID == "" {
		return "", "", ErrWorkAgentUnknown
	}
	raw, err := r.stateClient.Client().Get(ctx, workAgentKey(workID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", "", ErrWorkAgentUnknown
		}
		return "", "", fmt.Errorf("work-context registry: look up agent of work %q: %w", workID, err)
	}
	var rec workAgentRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil || rec.Agent == "" {
		return "", "", ErrWorkAgentUnknown
	}
	return rec.Agent, rec.Task, nil
}
