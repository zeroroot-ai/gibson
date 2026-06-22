/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package saga

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	psaga "github.com/zeroroot-ai/gibson/pkg/platform/saga"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// p99Provider is implemented by steps that embed StepBase and expose their
// expected p99 duration. Used by wrapWithTimeouts to compute per-step deadlines.
type p99Provider interface {
	GetP99() time.Duration
}

// timeoutStep wraps a Step and applies context.WithTimeout(P99 * 3) to every
// Provision and Deprovision call. The 3× multiplier provides a strict upper
// bound that catches goroutine leaks from hung Zitadel/Vault calls
// without being so tight that transient latency spikes trip it (P1 finding:
// saga runner had no per-step deadline).
type timeoutStep struct {
	Step
	timeout time.Duration
}

func (t *timeoutStep) Provision(ctx context.Context, obj ConditionedObject, deps *Deps) (bool, error) {
	tctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.Step.Provision(tctx, obj, deps)
}

func (t *timeoutStep) Deprovision(ctx context.Context, obj ConditionedObject, deps *Deps) error {
	tctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.Step.Deprovision(tctx, obj, deps)
}

// wrapWithTimeouts returns a new []Step slice where each step that implements
// p99Provider (i.e. embeds StepBase with a non-zero P99) is wrapped in a
// timeoutStep. Steps with zero P99 are returned unwrapped — they have no
// expected SLA (e.g. WaitForBillingConfirmation waits up to an hour).
func wrapWithTimeouts(steps []Step) []Step {
	out := make([]Step, len(steps))
	for i, s := range steps {
		p, ok := s.(p99Provider)
		if !ok || p.GetP99() == 0 {
			out[i] = s
			continue
		}
		out[i] = &timeoutStep{Step: s, timeout: p.GetP99() * 3}
	}
	return out
}

// bestEffortStep wraps a teardown Step so that a CLASSIFIED-PERMANENT
// error from Provision is converted to (done=true, err=nil) before
// it reaches psaga.Run. Without this, one permanent fail anywhere in
// the teardown chain returns RunResult.Blocked, the controller hits
// the #157 escape hatch, and every subsequent independent cleanup
// step (DeleteVaultNamespace, RemoveZitadelOrg, DeleteFGATuples,
// DeleteTenantName, DeleteRedisKeyspace, ...) silently doesn't run.
// Each step's Status condition still records its outcome inside
// psaga; this wrapper only changes the loop-stopping behavior.
//
// Scope limit: transient errors that exceed psaga's StepMaxAttempts
// are classified-permanent INSIDE psaga (not by classifyForPSaga), so
// this wrapper does not catch them. The upstream fix
// (psaga.Runner.ContinueOnBlocked, gibson#255) handles that case
// uniformly; this in-repo wrapper is the bridge until that flag is
// available across all consumers.
//
// See tenant-operator#184 for the full rationale.
type bestEffortStep struct {
	Step
}

func (s bestEffortStep) Provision(ctx context.Context, obj ConditionedObject, deps *Deps) (bool, error) {
	done, err := s.Step.Provision(ctx, obj, deps)
	if err == nil {
		return done, nil
	}
	if classifyForPSaga(err) != psaga.ErrorPermanent {
		return done, err
	}
	// Permanent error: record + continue. Step-level conditions inside
	// psaga still mark this step as failed (we let psaga see done=true
	// only AFTER we've logged the leak), but the saga as a whole keeps
	// iterating so siblings are not silently bypassed.
	slog.Default().Warn(
		"teardown step permanently failed; leaking resource and continuing for step-isolation (#184)",
		"step", s.Step.Name(),
		"object_kind", kindOf(obj),
		"object_namespace", obj.GetNamespace(),
		"object_name", obj.GetName(),
		"error", err.Error(),
	)
	return true, nil
}

// wrapBestEffort returns a new []Step where every step's permanent-
// fail outcome is logged-and-converted-to-success. Used by
// RunForDeletion ONLY (provision sagas must halt on permanent — data
// integrity requires it).
func wrapBestEffort(steps []Step) []Step {
	out := make([]Step, len(steps))
	for i, s := range steps {
		out[i] = bestEffortStep{Step: s}
	}
	return out
}

// blockedClearWindow is the age threshold for auto-clearing Blocked/SagaFailed
// conditions on operator restart so a fresh retry is attempted.
const blockedClearWindow = time.Hour

// AnnotationCorrelationID is the annotation key on Tenant objects used to
// propagate a request correlation ID into saga audit events. The propagation
// task (task 17.3) stamps this annotation; Runner reads it here so the audit
// trail links back to the originating API call. If absent, correlationId is
// emitted as an empty string — the field is always present for Loki parsing.
const AnnotationCorrelationID = "gibson.zeroroot.ai/correlation-id"

// ReasonSagaFailed is the Reason on a Blocked status condition that the
// platform runner sets when a saga step exhausts its retry budget. Only
// conditions carrying this reason are auto-cleared by ClearStaleBlocked
// (time-based) or HonorRetryAnnotation (operator-driven). Other reasons
// (SlugCollision, InvalidSpec, etc.) are spec-level permanent failures
// and require human intervention.
const ReasonSagaFailed = "SagaFailed"

// conditionTypeBlocked is the Condition.Type used to signal that the saga
// has permanently failed and requires operator intervention or an explicit
// retry annotation to resume.
const conditionTypeBlocked = "Blocked"

// AnnotationSagaRetryFrom is the annotation key that operators set on a
// CR to force the saga to retry past a Blocked condition. The value is the
// name of the step to retry from (or empty to retry from the beginning).
// When the Runner observes this annotation it:
//
//  1. Drops every Blocked condition whose Reason is "SagaFailed".
//  2. Removes the annotation so the next reconcile doesn't re-trigger.
//  3. Patches metadata + status, then continues normally.
//
// Used by humans (kubectl annotate ...) when they know the underlying
// upstream cause has been fixed and want to short-circuit the time-based
// auto-clear from ClearStaleBlocked. Spec issue #47.
const AnnotationSagaRetryFrom = "gibson.zeroroot.ai/saga-retry-from"

// Runner is the operator's reconcile orchestration entry point. Internally
// it delegates to psaga.Runner (the unified platform-level runner) and
// translates RunResult → (ctrl.Result, error) for controller-runtime.
//
// It also installs operator-specific glue:
//   - Audit hook → audit.SagaEmitter
//   - Metrics hook → internal/metrics
//   - Error classifier → clients.IsPermanent + metrics.ClassifyError
//   - Deps bag passed to every step
//
// The Phase 4 migration deleted the previous in-package saga runner; this
// type preserves the public surface that controllers depend on
// (NewRunner, Run, ClearStaleBlocked).
type Runner struct {
	Client   client.Client
	Recorder events.EventRecorder
	Log      logr.Logger

	// Audit is the operator's saga audit emitter. May be nil — when nil,
	// audit emission is suppressed (test-mode default).
	Audit *audit.SagaEmitter

	// Deps is the unified client bag passed to every Step's
	// Provision/Deprovision invocation. May be nil; steps that require
	// capabilities are expected to fail-closed when their needs are not
	// satisfied (psaga.ValidateAtStartup is the production-mode gate).
	Deps *Deps

	// MaxBackoff caps exponential backoff. Default 5 minutes.
	MaxBackoff time.Duration
	// InitialBackoff is the starting backoff duration. Default 1 second.
	InitialBackoff time.Duration
	// RequeueInterval when a step returns done=false. Default 5 seconds.
	RequeueInterval time.Duration

	// StepMaxAttempts is the upper bound on consecutive non-transient
	// failures before a step is marked Blocked. Default 20.
	StepMaxAttempts int

	// Clock is injectable for tests. If nil, time.Now is used.
	Clock func() time.Time
}

// NewRunner returns a Runner with sensible defaults. Recorder + log are
// required; Audit + Deps + Clock are optional.
func NewRunner(c client.Client, recorder events.EventRecorder, log logr.Logger) *Runner {
	return &Runner{
		Client:          c,
		Recorder:        recorder,
		Log:             log,
		MaxBackoff:      5 * time.Minute,
		InitialBackoff:  time.Second,
		RequeueInterval: 5 * time.Second,
		StepMaxAttempts: 20,
	}
}

// ClearStaleBlocked removes Blocked/SagaFailed conditions that were last
// transitioned more than blockedClearWindow ago, allowing a fresh retry
// on operator restart. Conditions with Reason != "SagaFailed" (e.g.
// SlugCollision) are intentionally preserved — they are permanent and
// must be resolved by a human, not retried automatically.
func (r *Runner) ClearStaleBlocked(conditions *[]metav1.Condition) {
	if conditions == nil {
		return
	}
	now := r.now()
	filtered := (*conditions)[:0:len(*conditions)]
	for _, c := range *conditions {
		if c.Type == conditionTypeBlocked &&
			c.Status == metav1.ConditionTrue &&
			c.Reason == ReasonSagaFailed &&
			now.Sub(c.LastTransitionTime.Time) > blockedClearWindow {
			continue
		}
		filtered = append(filtered, c)
	}
	*conditions = filtered
}

// HonorRetryAnnotation checks obj for the AnnotationSagaRetryFrom
// annotation and, if present, clears Blocked/SagaFailed conditions and
// removes the annotation so the saga can re-attempt the failed step on
// the same reconcile.
//
// Returns true when the annotation was honored (saga should proceed
// with a fresh attempt), false when the annotation was absent. Errors
// surface only when the metadata or status patch fails.
//
// The function mutates obj in-place AND persists the change via the
// supplied client. Callers should invoke it before Runner.Run so the
// saga sees a clean slate. The Runner does this automatically.
func (r *Runner) HonorRetryAnnotation(ctx context.Context, obj ConditionedObject) (bool, error) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return false, nil
	}
	stepName, ok := annotations[AnnotationSagaRetryFrom]
	if !ok {
		return false, nil
	}

	// Compute the post-clear conditions slice up front. Conditions with
	// Reason != "SagaFailed" (e.g. SlugCollision, InvalidSpec) survive
	// — they are permanent spec-level failures and must be resolved by
	// a human, not by setting the retry annotation.
	conditions := obj.GetConditions()
	var clearedConds []metav1.Condition
	if conditions != nil {
		clearedConds = make([]metav1.Condition, 0, len(*conditions))
		for _, c := range *conditions {
			if c.Type == conditionTypeBlocked &&
				c.Status == metav1.ConditionTrue &&
				c.Reason == ReasonSagaFailed {
				continue
			}
			clearedConds = append(clearedConds, c)
		}
	}

	log := r.Log.WithValues(
		"object", fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName()),
		"kind", kindOf(obj),
		"retryFrom", stepName,
	)
	log.Info("honoring saga-retry-from annotation; clearing Blocked + retrying")

	// Two separate Patch calls are required because conditions live on
	// .status (a separate subresource) while the annotation lives on
	// metadata. Each Patch can reset obj from the server response, so
	// we restore the desired in-memory state after each call.

	// 1. Metadata patch — drop the annotation.
	metaBase := obj.DeepCopyObject().(ConditionedObject)
	delete(annotations, AnnotationSagaRetryFrom)
	obj.SetAnnotations(annotations)
	if err := r.Client.Patch(ctx, obj, client.MergeFrom(metaBase)); err != nil {
		return false, fmt.Errorf("saga: patch metadata to drop retry annotation: %w", err)
	}

	// 2. Status patch — clear Blocked. After the metadata patch above,
	// the fake client (and real client) re-populate obj with the server
	// response, which may have re-included the old conditions. Apply
	// the cleared slice to obj BEFORE snapshotting for the diff.
	statusBase := obj.DeepCopyObject().(ConditionedObject)
	if conds := obj.GetConditions(); conds != nil {
		*conds = clearedConds
	}
	if err := r.Client.Status().Patch(ctx, obj, client.MergeFrom(statusBase)); err != nil {
		return false, fmt.Errorf("saga: patch status to clear Blocked: %w", err)
	}
	// Re-apply locally in case the patch response restored Blocked
	// (the fake client's behavior under certain status-subresource modes).
	if conds := obj.GetConditions(); conds != nil {
		*conds = clearedConds
	}
	// And the annotation — same defensive re-apply.
	if a := obj.GetAnnotations(); a != nil {
		delete(a, AnnotationSagaRetryFrom)
		obj.SetAnnotations(a)
	}

	if r.Recorder != nil {
		// events.EventRecorder.Eventf signature: (regarding, related, eventtype,
		// reason, action, note, args...). No related object; reuse reason as action.
		r.Recorder.Eventf(obj, nil, "Normal", "SagaRetryRequested", "SagaRetryRequested",
			"Cleared Blocked condition per %s=%q; retrying", AnnotationSagaRetryFrom, stepName)
	}
	return true, nil
}

// TeardownOutcome is the deletion-flow contract: the operator's
// reconcileDelete must distinguish between "saga still in progress"
// (requeue without removing the finalizer), "saga blocked" (best-effort
// teardown done, MUST proceed to finalizer removal so the CR isn't
// stranded — see issue #157), and "all teardown steps complete"
// (proceed to finalizer removal normally).
//
// Returned by RunForDeletion so the controller can branch correctly.
// The Run entry point continues to return (ctrl.Result, error) for the
// provision flow, where Blocked legitimately stops the reconciler.
type TeardownOutcome struct {
	// Result is what controller-runtime sees. RequeueAfter > 0 means the
	// saga still has work in flight; the controller must requeue and NOT
	// remove the finalizer yet.
	Result ctrl.Result

	// Err mirrors the result returned from psaga (transient retry). Nil
	// when the saga completed or was permanently blocked.
	Err error

	// AllComplete is true when every teardown step ran successfully.
	AllComplete bool

	// Blocked is true when a teardown step exhausted its retry budget
	// (transient → permanent escalation) or returned a permanent error.
	// In the deletion flow this is NOT a stop-the-world condition — the
	// controller proceeds to finalizer removal so the CR is GC'd and
	// downstream tooling (orphan reaper, debug runbook) can clean up the
	// individual stragglers. See #157.
	Blocked bool
}

// RunForDeletion is the teardown counterpart to Run. It returns a
// structured TeardownOutcome that exposes whether the saga is in
// progress, was permanently blocked, or completed — so reconcileDelete
// can finalize the CR even when one teardown step exhausted its retry
// budget. See #157.
func (r *Runner) RunForDeletion(ctx context.Context, obj ConditionedObject, steps []Step, finalPhase string) TeardownOutcome {
	corrID := correlationIDFromCtx(ctx, obj)
	objName := fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())
	if obj.GetNamespace() == "" {
		objName = obj.GetName()
	}
	kind := kindOf(obj)

	if _, err := r.HonorRetryAnnotation(ctx, obj); err != nil {
		return TeardownOutcome{Err: err}
	}

	pr := &psaga.Runner{
		Deps:            r.Deps,
		EventRecorder:   r.Recorder,
		AuditHook:       &auditHookAdapter{emitter: r.Audit, corrID: corrID},
		MetricsHook:     metricsHookAdapter{},
		ErrorClassifier: classifyForPSaga,
		MaxBackoff:      r.MaxBackoff,
		InitialBackoff:  r.InitialBackoff,
		RequeueInterval: r.RequeueInterval,
		StepMaxAttempts: r.StepMaxAttempts,
		Clock:           r.Clock,
	}
	// Teardown step-isolation (#184): wrap each step so a permanent
	// fail in one step does not silently bypass the cleanup work of
	// subsequent steps. Without this, a single Zitadel auth blip
	// strands the K8s namespace, OpenBao namespace,
	// broker_config row, Zitadel org, and FGA tuples for the tenant.
	// The upstream psaga.Runner.ContinueOnBlocked flag (gibson#255) is
	// the cleaner long-term home for this behavior; this wrapper is the
	// in-repo bridge until that flag lands across all consumers.
	result := pr.Run(ctx, obj, wrapBestEffort(wrapWithTimeouts(steps)), finalPhase)

	log := r.Log.WithValues(
		"object", objName,
		"kind", kind,
		"correlationId", corrID,
	)

	switch {
	case result.Blocked:
		// Permanent failure during teardown that the bestEffort wrapper
		// could NOT swallow (the wrapper only catches classified-permanent
		// errors from classifyForPSaga; transient errors that exceed
		// psaga's StepMaxAttempts are classified-permanent INSIDE psaga
		// and still surface here). Do NOT requeue. Log loud so the
		// failed teardown step is visible — but the controller MUST
		// still proceed to finalizer removal so the CR isn't stranded
		// (#157). The orphan reaper + per-step audit events surface any
		// resources that couldn't be cleaned up.
		metrics.ReconcileErrors.WithLabelValues(kind, metrics.ClassifyError(result.Err)).Inc()
		metrics.ReconcileDuration.WithLabelValues(kind, "error").Observe(0)
		log.Error(result.Err, "saga blocked during teardown; proceeding to finalizer removal to avoid stranding the CR (#157)")
		return TeardownOutcome{Blocked: true, Err: result.Err}
	case result.Err != nil:
		// Transient — requeue with backoff. Finalizer stays until the
		// transient cause clears or the step budget is exhausted (above).
		metrics.ReconcileErrors.WithLabelValues(kind, metrics.ClassifyError(result.Err)).Inc()
		metrics.ReconcileDuration.WithLabelValues(kind, "error").Observe(0)
		return TeardownOutcome{Result: ctrl.Result{RequeueAfter: result.RequeueAfter}, Err: result.Err}
	case result.RequeueAfter > 0:
		// In-progress requeue.
		metrics.ReconcileDuration.WithLabelValues(kind, "inprogress").Observe(0)
		return TeardownOutcome{Result: ctrl.Result{RequeueAfter: result.RequeueAfter}}
	default:
		// All steps complete.
		metrics.PhaseGauge.WithLabelValues(kind, finalPhase).Inc()
		metrics.ReconcileDuration.WithLabelValues(kind, "ok").Observe(0)
		log.V(1).Info("all teardown steps complete", "phase", finalPhase)
		return TeardownOutcome{AllComplete: true}
	}
}

// Run executes the steps in order against obj. It is the controllers'
// single entry point; controllers no longer talk to psaga.Runner directly.
//
// Returns the controller-runtime Result + error so reconcilers can return
// the value unchanged.
func (r *Runner) Run(ctx context.Context, obj ConditionedObject, steps []Step, finalPhase string) (ctrl.Result, error) {
	corrID := correlationIDFromCtx(ctx, obj)
	objName := fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())
	if obj.GetNamespace() == "" {
		objName = obj.GetName()
	}
	kind := kindOf(obj)

	// Honor the operator-driven retry annotation before delegating to the
	// platform runner. The annotation clears the Blocked condition + removes
	// itself so the saga runs with a fresh slate. If the underlying cause
	// is still present, the saga will re-block normally — no infinite loop.
	if _, err := r.HonorRetryAnnotation(ctx, obj); err != nil {
		// Surface as transient; controller will requeue + retry.
		return ctrl.Result{}, err
	}

	pr := &psaga.Runner{
		Deps:            r.Deps,
		EventRecorder:   r.Recorder,
		AuditHook:       &auditHookAdapter{emitter: r.Audit, corrID: corrID},
		MetricsHook:     metricsHookAdapter{},
		ErrorClassifier: classifyForPSaga,
		MaxBackoff:      r.MaxBackoff,
		InitialBackoff:  r.InitialBackoff,
		RequeueInterval: r.RequeueInterval,
		StepMaxAttempts: r.StepMaxAttempts,
		Clock:           r.Clock,
	}

	result := pr.Run(ctx, obj, wrapWithTimeouts(steps), finalPhase)

	log := r.Log.WithValues(
		"object", objName,
		"kind", kind,
		"correlationId", corrID,
	)

	switch {
	case result.Blocked:
		// Permanent failure — record reconcile error metric and return
		// without requeue. Status conditions were already set by the
		// platform runner.
		metrics.ReconcileErrors.WithLabelValues(kind, metrics.ClassifyError(result.Err)).Inc()
		metrics.ReconcileDuration.WithLabelValues(kind, "error").Observe(0)
		log.Error(result.Err, "saga blocked; not requeueing")
		return ctrl.Result{}, nil
	case result.Err != nil:
		// Transient — requeue with the platform runner's computed backoff.
		metrics.ReconcileErrors.WithLabelValues(kind, metrics.ClassifyError(result.Err)).Inc()
		metrics.ReconcileDuration.WithLabelValues(kind, "error").Observe(0)
		return ctrl.Result{RequeueAfter: result.RequeueAfter}, result.Err
	case result.RequeueAfter > 0:
		// In-progress requeue.
		metrics.ReconcileDuration.WithLabelValues(kind, "inprogress").Observe(0)
		return ctrl.Result{RequeueAfter: result.RequeueAfter}, nil
	default:
		// All steps complete. Clear any stale Blocked=True condition so a
		// previously-blocked tenant that has since been fixed no longer shows
		// "Blocked and Ready" simultaneously. tenant-operator#141.
		clearBlockedOnSuccess(obj.GetConditions())
		metrics.PhaseGauge.WithLabelValues(kind, finalPhase).Inc()
		metrics.ReconcileDuration.WithLabelValues(kind, "ok").Observe(0)
		log.V(1).Info("all steps complete", "phase", finalPhase)
		return ctrl.Result{}, nil
	}
}

// clearBlockedOnSuccess removes any Blocked=True condition when the saga
// completes without error. All steps ran to completion, so any Blocked
// condition recorded during a previous reconcile is now stale.
func clearBlockedOnSuccess(conditions *[]metav1.Condition) {
	if conditions == nil {
		return
	}
	filtered := (*conditions)[:0:len(*conditions)]
	for _, c := range *conditions {
		if c.Type == conditionTypeBlocked && c.Status == metav1.ConditionTrue {
			continue
		}
		filtered = append(filtered, c)
	}
	*conditions = filtered
}

func (r *Runner) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// classifyForPSaga maps an operator-shaped error to the platform runner's
// transient/permanent classification. Mirrors the behaviour of the
// pre-Phase-4 runner: explicit ErrPermanent / 4xx-class errors are
// permanent; network / timeout / 5xx are transient.
func classifyForPSaga(err error) psaga.ErrorClassification {
	if err == nil {
		return psaga.ErrorTransient
	}
	if clients.IsPermanent(err) {
		return psaga.ErrorPermanent
	}
	switch metrics.ClassifyError(err) {
	case "validation", "conflict":
		// These map onto the operator's previous SlugCollision / InvalidSpec
		// blocked-reason classifications.
		return psaga.ErrorPermanent
	case "unreachable", "timeout":
		return psaga.ErrorTransient
	}
	// Unknown class: treat as transient so a stray error doesn't trip the
	// blocked-condition handler on the first reconcile.
	return psaga.ErrorTransient
}

// auditHookAdapter wires psaga.Runner step transitions onto the operator's
// audit.SagaEmitter (Loki-formatted line emitter consumed by the dashboard
// activity feed). When emitter is nil all calls become no-ops.
type auditHookAdapter struct {
	emitter *audit.SagaEmitter
	corrID  string
}

func (a *auditHookAdapter) emit(obj ConditionedObject, evt audit.SagaAuditEvent) {
	if a == nil || a.emitter == nil {
		return
	}
	evt.TenantId = obj.GetName()
	evt.UserId = "operator"
	evt.CorrelationId = a.corrID
	a.emitter.Emit(evt)
}

func (a *auditHookAdapter) OnStepStarted(_ context.Context, obj ConditionedObject, step Step) {
	a.emit(obj, audit.SagaAuditEvent{
		Action:   audit.ActionSagaStepStarted,
		Outcome:  audit.OutcomeOk,
		StepName: step.Name(),
	})
}

func (a *auditHookAdapter) OnStepCompleted(_ context.Context, obj ConditionedObject, step Step, _ time.Duration) {
	a.emit(obj, audit.SagaAuditEvent{
		Action:   audit.ActionSagaStepCompleted,
		Outcome:  audit.OutcomeOk,
		StepName: step.Name(),
	})
}

func (a *auditHookAdapter) OnStepFailed(_ context.Context, obj ConditionedObject, step Step, err error, _ time.Duration, blocked bool) {
	outcome := audit.OutcomeFailed
	errCode := ReasonStepFailed
	if blocked {
		outcome = audit.OutcomeLocked
		errCode = ReasonSagaFailed
		if clients.IsPermanent(err) {
			switch metrics.ClassifyError(err) {
			case "conflict":
				errCode = "SlugCollision"
			case "validation":
				errCode = "InvalidSpec"
			}
		}
	}
	a.emit(obj, audit.SagaAuditEvent{
		Action:       audit.ActionSagaStepFailed,
		Outcome:      outcome,
		StepName:     step.Name(),
		ErrorCode:    errCode,
		ErrorMessage: audit.TruncateErrorMessage(err.Error()),
	})
}

func (a *auditHookAdapter) OnStepSkipped(_ context.Context, obj ConditionedObject, step Step) {
	a.emit(obj, audit.SagaAuditEvent{
		Action:   audit.ActionSagaStepSkipped,
		Outcome:  audit.OutcomeOk,
		StepName: step.Name(),
		Reason:   "skip predicate matched",
	})
}

// metricsHookAdapter wires psaga.Runner step + reconcile observations onto
// the operator's existing Prometheus collectors.
type metricsHookAdapter struct{}

func (metricsHookAdapter) ObserveStep(stepName, kind string, start time.Time, outcome string) {
	metrics.ObserveStep(stepName, kind, start, outcome)
}

func (metricsHookAdapter) ObserveReconcile(kind, outcome string, duration time.Duration) {
	metrics.ReconcileDuration.WithLabelValues(kind, outcome).Observe(duration.Seconds())
}

// ctxKeyCorrelationID is the typed context key used to pass the correlation
// ID from the controller through to the runner's log fields and audit
// events. Unexported so callers either use CtxWithCorrelationID or rely on
// the AnnotationCorrelationID fallback in correlationIDFromCtx.
type ctxKeyCorrelationID struct{}

// CtxWithCorrelationID stores the correlation ID in ctx using the saga
// package's typed key.
func CtxWithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyCorrelationID{}, id)
}

// correlationIDFromCtx extracts the correlation ID first from the context
// (using the saga package key), then from the object's annotation. Returns
// an empty string if neither is present.
func correlationIDFromCtx(ctx context.Context, obj ConditionedObject) string {
	if id, ok := ctx.Value(ctxKeyCorrelationID{}).(string); ok && id != "" {
		return id
	}
	if annotations := obj.GetAnnotations(); annotations != nil {
		return annotations[AnnotationCorrelationID]
	}
	return ""
}

func kindOf(obj ConditionedObject) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Kind != "" {
		return gvk.Kind
	}
	return fmt.Sprintf("%T", obj)
}

// ValidateAtStartup is a thin re-export so cmd/main.go can call it without
// importing psaga directly. The devMode bypass was deleted in the
// one-code-path epic (deploy#205) — one binary, every environment.
func ValidateAtStartup(steps []Step, deps *Deps) error {
	return psaga.ValidateAtStartup(steps, deps)
}

// ValidateAtStartupVerbose mirrors the psaga helper of the same name so
// cmd/main.go can log a one-line success summary in the startup log.
func ValidateAtStartupVerbose(steps []Step, deps *Deps) (string, error) {
	return psaga.ValidateAtStartupVerbose(steps, deps)
}
