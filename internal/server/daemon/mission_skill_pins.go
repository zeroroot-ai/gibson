// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// skillIDsOf returns the Agent Skill ids that a mission definition lists in
// Dependencies.tools. An entry is an Agent Skill when it starts with "skill:".
// Any other entry is a tool and is not touched here. The order of the
// definition stays, and a repeated id counts once. An entry with a bad skill
// name is an error.
func skillIDsOf(def *missionpb.MissionDefinition) ([]string, error) {
	var ids []string
	seen := map[string]struct{}{}
	for _, entry := range def.GetDependencies().GetTools() {
		const prefix = string(toolid.SourceSkill) + ":"
		if len(entry) < len(prefix) || entry[:len(prefix)] != prefix {
			continue
		}
		id, err := toolid.Parse(entry)
		if err != nil {
			return nil, fmt.Errorf("mission dependency %q: %w", entry, err)
		}
		canon := id.Canonical()
		if _, dup := seen[canon]; dup {
			continue
		}
		seen[canon] = struct{}{}
		ids = append(ids, canon)
	}
	return ids, nil
}

// pinMissionSkills pins the digest of each Agent Skill that the definition lists,
// in the pin table of the mission. It runs at mission start, so a publish after
// the start does not change what the mission sees (gibson#1375). It returns the
// ids for the agent work items. A skill that the tenant does not have fails the
// start, because the mission cannot run as written.
func pinMissionSkills(
	ctx context.Context, store agentskillstore.Store, tenant, missionID string, def *missionpb.MissionDefinition,
) ([]string, error) {
	ids, err := skillIDsOf(def)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if store == nil {
		return nil, fmt.Errorf("the mission lists %d Agent Skills, and this daemon has no Agent Skill store", len(ids))
	}
	for _, canon := range ids {
		id, _ := toolid.Parse(canon) // checked by skillIDsOf
		if _, err := store.Resolve(ctx, tenant, missionID, id.Tool); err != nil {
			return nil, fmt.Errorf("pin the Agent Skill %s: %w", canon, err)
		}
	}
	return ids, nil
}
