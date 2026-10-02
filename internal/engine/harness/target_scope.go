// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// targetScopedHarness is one harness seen as running against a different target.
//
// It embeds the AgentHarness it views, so every method but Target() is the
// parent's own method on the parent's own state. That is what makes it a view
// and not a second harness: the token tracker, the memory manager, the callback
// manager, the registries and the agent-concurrency bookkeeping are all shared,
// because this is the same mission doing the same turn against another host.
//
// A for_each instance uses it so a finding's scope is the target the instance
// actually assessed (gibson#526).
type targetScopedHarness struct {
	AgentHarness
	target TargetInfo
}

// Target reports the view's target. This is the one method that differs from the
// parent, and it is the whole reason the type exists.
func (v *targetScopedHarness) Target() TargetInfo { return v.target }

// ForTarget re-scopes from the PARENT, never by wrapping this view in another.
// Nesting would build a chain one link longer for every re-scope, and each link
// would be another Target() to get wrong.
//
// The identity cases return THIS view and not the parent. The parent reports a
// different target, so handing it back would silently return the scope to the
// mission's primary — the exact misattribution the view exists to prevent.
func (v *targetScopedHarness) ForTarget(targetID string) AgentHarness {
	if targetID == "" || targetID == v.target.ID.String() {
		return v
	}
	return scopeToTarget(v.AgentHarness, v.target, targetID)
}

// scopeToTarget returns parent scoped to targetID, or parent itself when there is
// nothing to change.
//
// An empty id returns the parent, so a caller dispatching an ordinary node does
// not have to branch. The id the parent already reports returns the parent too: a
// single-target mission's for_each produces one instance whose target IS the
// primary, and allocating a view for it would add an object to reason about and
// change nothing.
//
// `current` is the target the parent reports, passed in rather than read back
// through parent.Target(), because a MiddlewareHarness's Target() may be
// intercepted and the caller already holds the answer it means.
func scopeToTarget(parent AgentHarness, current TargetInfo, targetID string) AgentHarness {
	if targetID == "" || targetID == current.ID.String() {
		return parent
	}
	scoped := current
	scoped.ID = types.ID(targetID)
	return &targetScopedHarness{AgentHarness: parent, target: scoped}
}
