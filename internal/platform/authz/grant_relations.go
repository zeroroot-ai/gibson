// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import "sort"

// grantTupleRelations maps each action that a grant can name onto the
// relation that holds the tuple of that grant.
//
// can_read, can_configure and can_execute on a component are computed in
// model.fga: each one joins a direct_ relation with the tenant catalog and
// subtracts the deny relations. A computed relation takes no tuple, so the
// grant is a tuple on the direct_ relation. can_invoke on a plugin is a
// direct relation and holds its own tuple.
var grantTupleRelations = map[string]string{
	"can_read":      "direct_read",
	"can_configure": "direct_configure",
	"can_execute":   "direct_execute",
	"can_invoke":    "can_invoke",
}

// GrantTupleRelation returns the relation that holds the tuple for a grant
// of the given action. It reports false for an action that a grant cannot
// name.
//
// A caller checks access on the action (the computed relation), and it
// writes and deletes the tuple on the relation that this function returns.
func GrantTupleRelation(action string) (string, bool) {
	relation, ok := grantTupleRelations[action]
	return relation, ok
}

// GrantActions returns the actions that a grant can name, sorted.
func GrantActions() []string {
	actions := make([]string, 0, len(grantTupleRelations))
	for action := range grantTupleRelations {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return actions
}
