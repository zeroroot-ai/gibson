// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// Step is a single unit of the provisioning pipeline. Each step exposes an
// idempotent Provision and Rollback function. The pipeline orchestrator runs
// steps in order on Provision and LIFO on failure rollback.
type Step struct {
	// Name is a short identifier used in log messages and Kubernetes events.
	Name string

	// Provision is the forward action. Must be idempotent. limits carries the
	// per-tenant limits the step applies; a step with no limit ignores it.
	Provision func(ctx context.Context, tenantID string, limits Limits) error

	// Rollback is the compensating action run on failure. Must be idempotent.
	// Called LIFO for steps that completed successfully before the failure.
	Rollback func(ctx context.Context, tenantID string) error

	// StatusUpdate is an optional func called after Provision succeeds to
	// record per-step progress in the Tenant CRD status. May be nil.
	StatusUpdate func(dp *gibsonv1alpha1.TenantDataPlaneStatus)

	// AlreadyProvisioned returns true if this step's artifact existed BEFORE
	// the current Provision call (i.e., it was provisioned in a prior run).
	// When true, this step is excluded from the rollback chain on failure of a
	// later step: rolling back pre-existing infra would destroy live state that
	// other systems already depend on (gibson#279).
	// May be nil — treated as false (step is always rollback-eligible).
	AlreadyProvisioned func(dp *gibsonv1alpha1.TenantDataPlaneStatus) bool
}

// PipelineConfig holds all provisioner instances and wiring needed by the
// pipeline orchestrator.
type PipelineConfig struct {
	Postgres *pgProvisioner
	Neo4j    *Neo4jProvisioner
	Redis    *redisProvisioner
	Vector   *redisVSSProvisioner
	KEK      *KEKInitProvisioner

	// K8sClient is used to update Tenant CRD status after each step.
	K8sClient client.Client

	// Recorder emits Kubernetes events for each step transition.
	Recorder events.EventRecorder

	// Log is the structured logger. Defaults to slog.Default() when nil.
	Log *slog.Logger
}

// pipelineProvisioner implements dataplane.Provisioner and orchestrates the
// five sub-provisioners in the fixed order:
// Postgres → Neo4j → Redis → Vector → KEK
type pipelineProvisioner struct {
	cfg   PipelineConfig
	steps []Step
	log   *slog.Logger
}

// compile-time interface check
var _ Provisioner = (*pipelineProvisioner)(nil)

// New constructs a pipelineProvisioner wiring the five steps. Each store, the
// Kubernetes client and the event recorder are required: a tenant gets every
// store or none (ADR-0003, gibson#681).
func New(cfg PipelineConfig) (Provisioner, error) {
	var missing []string
	for name, absent := range map[string]bool{
		"Postgres":  cfg.Postgres == nil,
		"Neo4j":     cfg.Neo4j == nil,
		"Redis":     cfg.Redis == nil,
		"Vector":    cfg.Vector == nil,
		"KEK":       cfg.KEK == nil,
		"K8sClient": cfg.K8sClient == nil,
		"Recorder":  cfg.Recorder == nil,
	} {
		if absent {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("dataplane: the pipeline needs %s", strings.Join(missing, ", "))
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	p := &pipelineProvisioner{cfg: cfg, log: log}
	p.steps = p.buildSteps()
	return p, nil
}

func (p *pipelineProvisioner) buildSteps() []Step {
	steps := []Step{
		{
			Name: "Postgres",
			Provision: func(ctx context.Context, tenantID string, limits Limits) error {
				return p.cfg.Postgres.Provision(ctx, tenantID, limits)
			},
			Rollback: func(ctx context.Context, tenantID string) error {
				return p.cfg.Postgres.Deprovision(ctx, tenantID)
			},
			StatusUpdate: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) {
				dp.PostgresProvisioned = true
			},
			AlreadyProvisioned: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) bool {
				return dp != nil && dp.PostgresProvisioned
			},
		},
		{
			Name: "Neo4j",
			Provision: func(ctx context.Context, tenantID string, _ Limits) error {
				return p.cfg.Neo4j.Provision(ctx, tenantID)
			},
			Rollback: func(ctx context.Context, tenantID string) error {
				return p.cfg.Neo4j.Deprovision(ctx, tenantID)
			},
			StatusUpdate: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) {
				dp.Neo4jProvisioned = true
			},
			AlreadyProvisioned: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) bool {
				return dp.Neo4jProvisioned
			},
		},
		{
			Name: "Redis",
			Provision: func(ctx context.Context, tenantID string, _ Limits) error {
				return p.cfg.Redis.Provision(ctx, tenantID)
			},
			Rollback: func(ctx context.Context, tenantID string) error {
				return p.cfg.Redis.Deprovision(ctx, tenantID)
			},
			StatusUpdate: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) {
				dp.RedisProvisioned = true
			},
			AlreadyProvisioned: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) bool {
				return dp.RedisProvisioned
			},
		},
		{
			Name: "Vector",
			Provision: func(ctx context.Context, tenantID string, _ Limits) error {
				return p.cfg.Vector.Provision(ctx, tenantID)
			},
			Rollback: func(ctx context.Context, tenantID string) error {
				return p.cfg.Vector.Deprovision(ctx, tenantID)
			},
			StatusUpdate: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) {
				dp.VectorProvisioned = true
			},
			AlreadyProvisioned: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) bool {
				return dp.VectorProvisioned
			},
		},
		{
			Name: "KEKInit",
			Provision: func(ctx context.Context, tenantID string, _ Limits) error {
				return p.cfg.KEK.Provision(ctx, tenantID)
			},
			Rollback: func(ctx context.Context, tenantID string) error {
				// KEK init has no persistent state to roll back.
				return nil
			},
			StatusUpdate: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) {
				dp.KEKInitialized = true
			},
			AlreadyProvisioned: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) bool {
				return dp.KEKInitialized
			},
		},
	}
	return steps
}

// Provision runs all pipeline steps in order. On step N failure, it rolls back
// only steps 0..N-1 that were NEW to this pass (not pre-existing from a prior
// run). Steps whose AlreadyProvisioned flag returned true before this call are
// excluded from rollback — their artifacts are live and depended on by other
// systems (gibson#279).
func (p *pipelineProvisioner) Provision(ctx context.Context, tenantID string, limits Limits) error {
	p.log.InfoContext(ctx, "dataplane: provision start", "tenant", tenantID)

	tenant, err := p.getTenant(ctx, tenantID)
	if err != nil {
		p.log.WarnContext(ctx, "dataplane: could not fetch tenant CR for status updates", "error", err)
	}

	if tenant != nil {
		tenant.Status.DataPlane.Phase = DataPlanePhaseProvisioning
		p.patchStatus(ctx, tenant)
	}

	// Capture which steps were already done BEFORE this run so we can exclude
	// them from the rollback chain if a later step fails. AlreadyProvisioned
	// is called with nil when the Tenant CR is unavailable; implementations
	// must guard against nil (production) and stubs return true regardless
	// (tests that exercise the re-reconcile path).
	preExisting := make([]bool, len(p.steps))
	var statusDP *gibsonv1alpha1.TenantDataPlaneStatus
	if tenant != nil {
		statusDP = &tenant.Status.DataPlane
	}
	for i, step := range p.steps {
		if step.AlreadyProvisioned != nil {
			preExisting[i] = step.AlreadyProvisioned(statusDP)
		}
	}

	// newlyCompleted tracks the indices of steps completed in this pass that
	// are eligible for rollback (pre-existing steps are not eligible).
	var newlyCompleted []int

	for i, step := range p.steps {
		p.log.InfoContext(ctx, "dataplane: step start", "tenant", tenantID, "step", step.Name)
		p.emitEvent(ctx, tenant, corev1.EventTypeNormal, "StepStarted", fmt.Sprintf("data-plane step %q started", step.Name))

		if err := step.Provision(ctx, tenantID, limits); err != nil {
			p.log.ErrorContext(ctx, "dataplane: step failed", "tenant", tenantID, "step", step.Name, "error", err)
			p.emitEvent(ctx, tenant, corev1.EventTypeWarning, "StepFailed", fmt.Sprintf("data-plane step %q failed: %v", step.Name, err))

			// Rollback only steps newly completed in this pass (LIFO order).
			rbErr := p.rollbackIndices(ctx, tenantID, tenant, newlyCompleted)

			if tenant != nil {
				tenant.Status.DataPlane.Phase = DataPlanePhaseFailed
				tenant.Status.DataPlane.LastError = err.Error()
				p.patchStatus(ctx, tenant)
			}

			if rbErr != nil {
				return fmt.Errorf("dataplane: step %q failed: %w (rollback error: %v)", step.Name, err, rbErr)
			}
			return fmt.Errorf("dataplane: step %q failed: %w", step.Name, err)
		}

		p.log.InfoContext(ctx, "dataplane: step success", "tenant", tenantID, "step", step.Name)
		p.emitEvent(ctx, tenant, corev1.EventTypeNormal, "StepSucceeded", fmt.Sprintf("data-plane step %q succeeded", step.Name))

		if tenant != nil && step.StatusUpdate != nil {
			step.StatusUpdate(&tenant.Status.DataPlane)
			p.patchStatus(ctx, tenant)
		}

		if !preExisting[i] {
			newlyCompleted = append(newlyCompleted, i)
		}
	}

	if tenant != nil {
		tenant.Status.DataPlane.Phase = DataPlanePhaseActive
		tenant.Status.DataPlane.Ready = true
		tenant.Status.DataPlane.LastError = ""
		p.patchStatus(ctx, tenant)
	}

	p.log.InfoContext(ctx, "dataplane: provision complete", "tenant", tenantID)
	return nil
}

// Deprovision runs each step's Rollback in reverse order. Errors are collected
// but do not stop subsequent rollbacks (best-effort idempotent teardown).
func (p *pipelineProvisioner) Deprovision(ctx context.Context, tenantID string) error {
	p.log.InfoContext(ctx, "dataplane: deprovision start", "tenant", tenantID)

	tenant, _ := p.getTenant(ctx, tenantID)

	if tenant != nil {
		tenant.Status.DataPlane.Phase = DataPlanePhaseDeprovisioning
		p.patchStatus(ctx, tenant)
	}

	var errs []error
	for i := len(p.steps) - 1; i >= 0; i-- {
		step := p.steps[i]
		p.log.InfoContext(ctx, "dataplane: deprovision step", "tenant", tenantID, "step", step.Name)
		p.emitEvent(ctx, tenant, corev1.EventTypeNormal, "DeprovisionStep", fmt.Sprintf("data-plane deprovision step %q started", step.Name))

		if err := step.Rollback(ctx, tenantID); err != nil {
			p.log.ErrorContext(ctx, "dataplane: deprovision step error (continuing)", "tenant", tenantID, "step", step.Name, "error", err)
			errs = append(errs, fmt.Errorf("step %q: %w", step.Name, err))
		}
	}

	if tenant != nil {
		tenant.Status.DataPlane.Ready = false
		tenant.Status.DataPlane.Phase = ""
		p.patchStatus(ctx, tenant)
	}

	p.log.InfoContext(ctx, "dataplane: deprovision complete", "tenant", tenantID, "errors", len(errs))
	return errors.Join(errs...)
}

// rollbackIndices runs Rollback for the given step indices in LIFO (reverse)
// order. Only steps that were newly completed in this pass are included —
// pre-existing steps are excluded by the caller.
func (p *pipelineProvisioner) rollbackIndices(ctx context.Context, tenantID string, tenant *gibsonv1alpha1.Tenant, indices []int) error {
	var errs []error
	for j := len(indices) - 1; j >= 0; j-- {
		step := p.steps[indices[j]]
		p.log.InfoContext(ctx, "dataplane: rollback step", "tenant", tenantID, "step", step.Name)
		p.emitEvent(ctx, tenant, corev1.EventTypeWarning, "RollbackStep", fmt.Sprintf("rolling back step %q", step.Name))

		if err := step.Rollback(ctx, tenantID); err != nil {
			p.log.ErrorContext(ctx, "dataplane: rollback error", "tenant", tenantID, "step", step.Name, "error", err)
			errs = append(errs, fmt.Errorf("rollback %q: %w", step.Name, err))
		}
	}
	return errors.Join(errs...)
}

// getTenant fetches the Tenant CR from the API server.
func (p *pipelineProvisioner) getTenant(ctx context.Context, tenantID string) (*gibsonv1alpha1.Tenant, error) {
	var tenant gibsonv1alpha1.Tenant
	if err := p.cfg.K8sClient.Get(ctx, types.NamespacedName{Name: tenantID}, &tenant); err != nil {
		return nil, err
	}
	return &tenant, nil
}

// patchStatus persists the Tenant status via status subresource patch.
// Errors are logged but not propagated so status write failures do not block
// the provisioning pipeline. Each caller passes a Tenant it read.
//
// Uses Patch with an empty MergeFrom base so the resulting JSON merge-patch
// contains only the fields we want to update (status.dataPlane.*) and does
// NOT include resourceVersion. A concurrent writer (the controller's saga
// updating status.phase / status.conditions) will not conflict with this
// write because merge-patch applies field-by-field instead of replacing the
// whole object.
func (p *pipelineProvisioner) patchStatus(ctx context.Context, tenant *gibsonv1alpha1.Tenant) {
	// Build a minimal "before" containing just identity + an empty status,
	// so MergeFrom emits the full current status as the patch body.
	base := &gibsonv1alpha1.Tenant{}
	base.Name = tenant.Name
	base.Namespace = tenant.Namespace
	base.UID = tenant.UID
	if err := p.cfg.K8sClient.Status().Patch(ctx, tenant, client.MergeFrom(base)); err != nil {
		p.log.WarnContext(ctx, "dataplane: status patch failed", "tenant", tenant.Name, "error", err)
	}
}

// emitEvent records a Kubernetes event on the Tenant object. It does nothing
// when the Tenant CR could not be read: there is no object to attach it to.
func (p *pipelineProvisioner) emitEvent(ctx context.Context, tenant *gibsonv1alpha1.Tenant, eventType, reason, message string) {
	_ = ctx // EventRecorder does not accept a context in the current API
	// events.EventRecorder.Eventf signature: (regarding, related, eventtype,
	// reason, action, note, args...). No related object; reuse reason as action.
	if tenant != nil {
		p.cfg.Recorder.Eventf(tenant, nil, eventType, reason, reason, "%s", message)
	}
}

// DataPlane phase constants used in TenantDataPlaneStatus.Phase.
const (
	DataPlanePhaseProvisioning   = "Provisioning"
	DataPlanePhaseActive         = "Active"
	DataPlanePhaseFailed         = "Failed"
	DataPlanePhaseDeprovisioning = "Deprovisioning"
)
