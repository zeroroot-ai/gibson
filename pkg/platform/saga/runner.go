package saga

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
)

// defaultStepMaxAttempts is how many consecutive failures a step may
// accumulate (for non-transient errors) before the runner gives up and
// sets Blocked/SagaFailed. Transient errors (network/5xx) are not
// counted toward this cap — a long upstream outage must not kill the
// saga.
const defaultStepMaxAttempts = 20

// Runner executes a topologically-sorted set of Steps with idempotent
// retry, condition tracking, and pluggable audit/metrics hooks.
//
// Runner is the gibson-pkg-platform-saga side of the abstraction: pure
// orchestration with no daemon-internal client imports. Operator-specific
// behavior (Loki audit emission, Prometheus per-step histograms,
// IsPermanent classification specific to operator's own client errors)
// is injected via Options.
type Runner struct {
	// Deps is the client bag passed to every Step. Must be non-nil.
	Deps *Deps

	// EventRecorder records K8s Events on step transitions. May be nil.
	// Uses the modern events.k8s.io API (k8s.io/client-go/tools/events) —
	// the legacy core/v1 events API (k8s.io/client-go/tools/record) is
	// deprecated.
	EventRecorder events.EventRecorder

	// AuditHook is called at every step transition (started, completed,
	// failed, skipped) with structured event data. May be nil.
	AuditHook AuditHook

	// MetricsHook is called at every step completion with timing + outcome.
	// May be nil.
	MetricsHook MetricsHook

	// ErrorClassifier maps a step error to ErrorTransient | ErrorPermanent.
	// May be nil; when nil, all errors are treated as transient.
	ErrorClassifier func(err error) ErrorClassification

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

// AuditHook receives structured events at each step transition. Hooks
// should be cheap (audit emission is in the saga hot path).
type AuditHook interface {
	OnStepStarted(ctx context.Context, obj ConditionedObject, step Step)
	OnStepCompleted(ctx context.Context, obj ConditionedObject, step Step, duration time.Duration)
	OnStepFailed(ctx context.Context, obj ConditionedObject, step Step, err error, duration time.Duration, blocked bool)
	OnStepSkipped(ctx context.Context, obj ConditionedObject, step Step)
}

// MetricsHook receives timing + outcome data at each step completion.
type MetricsHook interface {
	ObserveStep(stepName, kind string, start time.Time, outcome string)
	ObserveReconcile(kind, outcome string, duration time.Duration)
}

// RunResult carries the outcome of a single Run invocation, suitable for
// adapting into controller-runtime's reconcile.Result.
type RunResult struct {
	// RequeueAfter > 0 indicates the caller should requeue after this
	// duration (transient error backoff or in-progress requeue).
	RequeueAfter time.Duration

	// Blocked indicates a permanent error has occurred; caller should NOT
	// requeue. The Tenant.status will already have a Blocked condition set.
	Blocked bool

	// AllComplete indicates every step finished successfully.
	AllComplete bool

	// Err is the underlying error (if any). Non-nil for transient retries
	// AND permanent blocks; check Blocked to distinguish.
	Err error
}

// Run executes the topologically-sorted steps in order. Steps must be
// pre-sorted by TopoSort (or the caller must guarantee dependency order).
// For convenience, Run will TopoSort the input itself when called with an
// unsorted slice.
//
// Semantics:
//   - Step.Skip(obj) → true: condition True with Reason=Skipped, continue.
//   - Step previously completed with current ObservedGeneration: skipped.
//   - Provision returns done=true, err=nil → condition True, continue.
//   - Provision returns done=false, err=nil → condition False/InProgress,
//     return RequeueAfter=RequeueInterval.
//   - Provision returns transient err → condition False/StepFailed, return
//     RequeueAfter=exponential backoff.
//   - Provision returns permanent err (or transient errors past
//     StepMaxAttempts) → Blocked=true, condition False/StepFailed, no
//     requeue (a human must intervene or the operator must restart).
//   - All steps complete → set Ready=True, set finalPhase, return
//     AllComplete=true.
//
// The caller is responsible for calling client.Status().Update(ctx, obj)
// after Run returns.
func (r *Runner) Run(ctx context.Context, obj ConditionedObject, steps []Step, finalPhase string) RunResult {
	sorted, err := TopoSort(steps)
	if err != nil {
		return RunResult{Err: fmt.Errorf("saga: cannot run unsorted steps with topology error: %w", err), Blocked: true}
	}
	conditions := obj.GetConditions()
	kind := kindOf(obj)
	reconcileStart := r.now()
	reconcileOutcome := "ok"

	for _, step := range sorted {
		// Skip predicate.
		if step.Skip(obj) {
			SetCondition(conditions, metav1.Condition{
				Type:               step.Condition(),
				Status:             metav1.ConditionTrue,
				Reason:             ReasonSkipped,
				Message:            fmt.Sprintf("Step %q skipped", step.Name()),
				ObservedGeneration: obj.GetGeneration(),
			})
			if r.MetricsHook != nil {
				r.MetricsHook.ObserveStep(step.Name(), kind, r.now(), "skipped")
			}
			if r.AuditHook != nil {
				r.AuditHook.OnStepSkipped(ctx, obj, step)
			}
			continue
		}

		// Already-completed short-circuit (current generation only).
		if IsConditionTrue(*conditions, step.Condition()) {
			existing := FindCondition(*conditions, step.Condition())
			if existing != nil && existing.ObservedGeneration == obj.GetGeneration() {
				continue
			}
		}

		if r.AuditHook != nil {
			r.AuditHook.OnStepStarted(ctx, obj, step)
		}

		stepStart := r.now()
		done, err := step.Provision(ctx, obj, r.Deps)
		duration := r.now().Sub(stepStart)

		if err != nil {
			if r.MetricsHook != nil {
				r.MetricsHook.ObserveStep(step.Name(), kind, stepStart, "error")
			}
			class := r.classify(err)
			attempts := r.attemptsForStep(*conditions, step.Condition())
			max := r.StepMaxAttempts
			if max <= 0 {
				max = defaultStepMaxAttempts
			}
			permanent := class == ErrorPermanent || (class == ErrorTransient && attempts >= max)
			if permanent {
				SetCondition(conditions, metav1.Condition{
					Type:               "Blocked",
					Status:             metav1.ConditionTrue,
					Reason:             "SagaFailed",
					Message:            fmt.Sprintf("Step %q permanently failed: %s", step.Name(), err.Error()),
					ObservedGeneration: obj.GetGeneration(),
				})
				SetCondition(conditions, metav1.Condition{
					Type:               step.Condition(),
					Status:             metav1.ConditionFalse,
					Reason:             ReasonStepFailed,
					Message:            err.Error(),
					ObservedGeneration: obj.GetGeneration(),
				})
				SetCondition(conditions, metav1.Condition{
					Type:               "Ready",
					Status:             metav1.ConditionFalse,
					Reason:             "Blocked",
					Message:            fmt.Sprintf("Step %q is permanently blocked: %s", step.Name(), err.Error()),
					ObservedGeneration: obj.GetGeneration(),
				})
				r.event(obj, corev1.EventTypeWarning, "StepBlocked",
					fmt.Sprintf("Step %q permanently failed after %s: %v", step.Name(), duration, err))
				if r.AuditHook != nil {
					r.AuditHook.OnStepFailed(ctx, obj, step, err, duration, true)
				}
				if r.MetricsHook != nil {
					r.MetricsHook.ObserveReconcile(kind, "error", r.now().Sub(reconcileStart))
				}
				return RunResult{Blocked: true, Err: err}
			}
			// Transient.
			SetCondition(conditions, metav1.Condition{
				Type:               step.Condition(),
				Status:             metav1.ConditionFalse,
				Reason:             ReasonStepFailed,
				Message:            err.Error(),
				ObservedGeneration: obj.GetGeneration(),
			})
			SetCondition(conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				Reason:             ReasonStepFailed,
				Message:            fmt.Sprintf("Step %q failed: %s", step.Name(), err.Error()),
				ObservedGeneration: obj.GetGeneration(),
			})
			r.event(obj, corev1.EventTypeWarning, "StepFailed",
				fmt.Sprintf("Step %q failed after %s: %v", step.Name(), duration, err))
			if r.AuditHook != nil {
				r.AuditHook.OnStepFailed(ctx, obj, step, err, duration, false)
			}
			backoff := r.backoffForStep(*conditions, step.Condition())
			if r.MetricsHook != nil {
				r.MetricsHook.ObserveReconcile(kind, "error", r.now().Sub(reconcileStart))
			}
			return RunResult{RequeueAfter: backoff, Err: err}
		}

		if !done {
			SetCondition(conditions, metav1.Condition{
				Type:               step.Condition(),
				Status:             metav1.ConditionFalse,
				Reason:             ReasonInProgress,
				Message:            fmt.Sprintf("Step %q in progress", step.Name()),
				ObservedGeneration: obj.GetGeneration(),
			})
			if r.MetricsHook != nil {
				r.MetricsHook.ObserveStep(step.Name(), kind, stepStart, "inprogress")
				r.MetricsHook.ObserveReconcile(kind, "inprogress", r.now().Sub(reconcileStart))
			}
			return RunResult{RequeueAfter: r.requeueInterval()}
		}

		// Done!
		SetCondition(conditions, metav1.Condition{
			Type:               step.Condition(),
			Status:             metav1.ConditionTrue,
			Reason:             ReasonReady,
			Message:            fmt.Sprintf("Step %q complete", step.Name()),
			ObservedGeneration: obj.GetGeneration(),
		})
		if r.MetricsHook != nil {
			r.MetricsHook.ObserveStep(step.Name(), kind, stepStart, "ok")
		}
		r.event(obj, corev1.EventTypeNormal, "StepComplete",
			fmt.Sprintf("Step %q complete in %s", step.Name(), duration))
		if r.AuditHook != nil {
			r.AuditHook.OnStepCompleted(ctx, obj, step, duration)
		}
	}

	// All steps done.
	SetCondition(conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             ReasonAllStepsComplete,
		Message:            "All reconcile steps complete",
		ObservedGeneration: obj.GetGeneration(),
	})
	obj.SetPhase(finalPhase)
	obj.SetObservedGeneration(obj.GetGeneration())
	if r.MetricsHook != nil {
		r.MetricsHook.ObserveReconcile(kind, reconcileOutcome, r.now().Sub(reconcileStart))
	}
	return RunResult{AllComplete: true}
}

// classify returns ErrorTransient unless the runner has an explicit
// classifier installed.
func (r *Runner) classify(err error) ErrorClassification {
	if err == nil {
		return ErrorTransient
	}
	if r.ErrorClassifier != nil {
		return r.ErrorClassifier(err)
	}
	// Fall back: any step that returns an instance of *ValidationError
	// or wraps it is permanent (config bug, not a network blip).
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ErrorPermanent
	}
	return ErrorTransient
}

func (r *Runner) requeueInterval() time.Duration {
	if r.RequeueInterval > 0 {
		return r.RequeueInterval
	}
	return 5 * time.Second
}

func (r *Runner) attemptsForStep(conditions []metav1.Condition, condType string) int {
	c := FindCondition(conditions, condType)
	if c == nil || c.Status != metav1.ConditionFalse {
		return 0
	}
	elapsed := r.now().Sub(c.LastTransitionTime.Time)
	if elapsed < 0 {
		elapsed = 0
	}
	init := r.InitialBackoff
	if init <= 0 {
		init = time.Second
	}
	return int(elapsed / init)
}

func (r *Runner) backoffForStep(conditions []metav1.Condition, condType string) time.Duration {
	c := FindCondition(conditions, condType)
	init := r.InitialBackoff
	if init <= 0 {
		init = time.Second
	}
	max := r.MaxBackoff
	if max <= 0 {
		max = 5 * time.Minute
	}
	if c == nil {
		return init
	}
	elapsed := r.now().Sub(c.LastTransitionTime.Time)
	if elapsed < 0 {
		elapsed = 0
	}
	attempts := int(elapsed / init)
	if attempts < 0 {
		attempts = 0
	}
	backoff := time.Duration(float64(init) * math.Pow(2, float64(attempts)))
	if backoff > max {
		backoff = max
	}
	if backoff < init {
		backoff = init
	}
	return backoff
}

func (r *Runner) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r *Runner) event(obj runtime.Object, eventType, reason, message string) {
	if r.EventRecorder == nil {
		return
	}
	// events.EventRecorder.Eventf signature: (regarding, related, eventtype,
	// reason, action, note, args...). We pass nil for `related` (no second
	// object), and use the same `reason` value for `action` since saga step
	// transitions are reason-as-verb already ("StepStarted", "StepFailed").
	r.EventRecorder.Eventf(obj, nil, eventType, reason, reason, message)
}

func kindOf(obj runtime.Object) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Kind != "" {
		return gvk.Kind
	}
	return fmt.Sprintf("%T", obj)
}
