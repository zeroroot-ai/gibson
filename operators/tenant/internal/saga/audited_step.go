// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package saga

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	psaga "github.com/zeroroot-ai/gibson/pkg/platform/saga"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
)

// ErrNoAudit reports a Runner with no audit emitter. The runner refuses to
// run a step without it, because a step changes state and each change needs
// its audit record first (gibson#583).
var ErrNoAudit = errors.New("saga: the runner has no audit emitter; no step runs without an audit record")

// auditRecordTimeout bounds one audit record, so a daemon that does not
// answer holds the reconcile for a bounded time.
const auditRecordTimeout = 10 * time.Second

// auditedStep writes the audit record of a step before the step runs, and a
// second record when the step then fails (gibson#583, the order of gibson#676).
// When the first record cannot be written, the step does not run and the
// saga retries it.
type auditedStep struct {
	Step
	emitter    *audit.SagaEmitter
	corrID     string
	finalPhase string
}

func (s *auditedStep) Provision(ctx context.Context, obj ConditionedObject, deps *Deps) (bool, error) {
	if stepSettled(obj, s.Step) {
		// The step already holds at this generation. Its Provision is an
		// idempotent re-check, or the wait for a change that already has
		// its record.
		return s.Step.Provision(ctx, obj, deps)
	}
	ev := s.event(obj)
	if err := s.record(ctx, func(rctx context.Context) error { return s.emitter.Record(rctx, ev) }); err != nil {
		return false, fmt.Errorf("saga: step %q did not run: %w", s.Name(), err)
	}
	done, err := s.Step.Provision(ctx, obj, deps)
	if err != nil {
		if ferr := s.record(ctx, func(rctx context.Context) error { return s.emitter.RecordFailure(rctx, ev, err) }); ferr != nil {
			return done, errors.Join(err, ferr)
		}
	}
	return done, err
}

// record runs one audit write under its own deadline.
func (s *auditedStep) record(ctx context.Context, write func(context.Context) error) error {
	rctx, cancel := context.WithTimeout(ctx, auditRecordTimeout)
	defer cancel()
	return write(rctx)
}

// event is the audit record of the step for obj.
func (s *auditedStep) event(obj ConditionedObject) audit.Event {
	targetID := obj.GetName()
	if ns := obj.GetNamespace(); ns != "" {
		targetID = ns + "/" + obj.GetName()
	}
	return audit.Event{
		Action:     audit.ActionSagaStep,
		TenantID:   auditTenantOf(obj),
		TargetType: targetTypeOf(obj),
		TargetID:   targetID,
		Fields: map[string]string{
			"step":           s.Name(),
			"condition":      s.Condition(),
			"final_phase":    s.finalPhase,
			"generation":     fmt.Sprintf("%d", obj.GetGeneration()),
			"correlation_id": s.corrID,
		},
	}
}

// wrapWithAudit wraps each step in an auditedStep.
func (r *Runner) wrapWithAudit(steps []Step, corrID, finalPhase string) []Step {
	out := make([]Step, len(steps))
	for i, st := range steps {
		out[i] = &auditedStep{Step: st, emitter: r.Audit, corrID: corrID, finalPhase: finalPhase}
	}
	return out
}

// targetTypeOf is the kind of obj in lower case, for example "tenant". A
// typed object read through a client often has no kind set, so the Go type
// name stands in.
func targetTypeOf(obj ConditionedObject) string {
	if k := obj.GetObjectKind().GroupVersionKind().Kind; k != "" {
		return strings.ToLower(k)
	}
	t := reflect.TypeOf(obj)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return strings.ToLower(t.Name())
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

// auditTenantOf returns the tenant that owns obj. A Tenant is cluster scoped
// and its name is the tenant id. A namespaced object belongs to the Tenant of
// its owner reference, or else to the tenant of its "tenant-<id>" namespace.
func auditTenantOf(obj ConditionedObject) string {
	ns := obj.GetNamespace()
	if ns == "" {
		return obj.GetName()
	}
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Kind == "Tenant" && ref.Name != "" {
			return ref.Name
		}
	}
	return strings.TrimPrefix(ns, "tenant-")
}
