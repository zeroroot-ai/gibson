// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package saga

import (
	"context"
	"errors"
	"strconv"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	psaga "github.com/zeroroot-ai/gibson/pkg/platform/saga"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
)

// ErrNoAudit reports a Runner with no audit emitter. The runner refuses to
// run a step without it, because a step changes state and each change needs
// its audit record first (gibson#583).
var ErrNoAudit = errors.New("saga: the runner has no audit emitter; no step runs without an audit record")

// auditedStep writes the audit record of a step before the step runs, and a
// second record when the step then fails (gibson#583, the order of gibson#676).
// When the first record cannot be written, the step does not run and the
// saga retries it.
type auditedStep struct {
	Step
	emitter    *audit.SagaEmitter
	finalPhase string
}

func (s *auditedStep) Provision(ctx context.Context, obj ConditionedObject, deps *Deps) (bool, error) {
	if stepSettled(obj, s.Step) {
		// The step already holds at this generation. Its Provision is an
		// idempotent re-check, or the wait for a change that already has
		// its record.
		return s.Step.Provision(ctx, obj, deps) //nolint:wrapcheck // the decorator passes the step error through
	}
	ev := audit.ObjectEvent(audit.ActionSagaStep, obj, map[string]string{
		"step":        s.Name(),
		"condition":   s.Condition(),
		"final_phase": s.finalPhase,
		"generation":  strconv.FormatInt(obj.GetGeneration(), 10),
	})
	var done bool
	err := s.emitter.Change(ctx, ev, func() error {
		var perr error
		done, perr = s.Step.Provision(ctx, obj, deps)
		return perr //nolint:wrapcheck // the decorator passes the step error through; the saga classifies it
	})
	return done, err //nolint:wrapcheck // the decorator passes the step error through; the saga classifies it
}

// wrapWithAudit wraps each step in an auditedStep.
func (r *Runner) wrapWithAudit(steps []Step, finalPhase string) []Step {
	out := make([]Step, len(steps))
	for i, st := range steps {
		out[i] = &auditedStep{Step: st, emitter: r.Audit, finalPhase: finalPhase}
	}
	return out
}

// stepSettled reports a step whose condition holds at the current
// generation: done, skipped, or in progress after an earlier pass started
// the change. A step with no condition, a failed step and a step of an
// older generation are not settled: they make a change, so they get a record.
func stepSettled(obj ConditionedObject, step Step) bool {
	var conds []metav1.Condition
	if p := obj.GetConditions(); p != nil {
		conds = *p
	}
	c := meta.FindStatusCondition(conds, step.Condition())
	return c != nil && c.ObservedGeneration == obj.GetGeneration() &&
		(c.Status == metav1.ConditionTrue || c.Reason == psaga.ReasonInProgress)
}
