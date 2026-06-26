// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// EnrollmentDeps bundles clients needed by enrollment sagas.
//
// The legacy CapabilityGrant (Postgres-based bootstrap token issuance) has
// been removed. Agents are now registered via the dashboard "Register
// Agent" UI, which creates a Zitadel service account.
type EnrollmentDeps struct {
	K8sClient   client.Client
	FGA         fga.Client
	PlatformURL string
}

// EnrollmentIssuanceSteps writes FGA grants for an AgentEnrollment.
//
// For plugin_principal enrollments two extra steps run:
//
//  1. WriteSecretResolveGrantFGA — writes
//     (plugin_principal:<id>, can_resolve, secret:tenant-<id>:*).
//  2. WritePluginCanInvokeGrantFGA — writes
//     (tenant:<id>#member, can_invoke, plugin:<id>:<plugin_name>).
func EnrollmentIssuanceSteps(deps EnrollmentDeps) []saga.Step {
	return []saga.Step{
		newWriteAgentGrantsStep(deps),
		newWriteSecretResolveGrantStep(deps),
		newWritePluginCanInvokeGrantStep(deps),
	}
}

// EnrollmentRevocationSteps revokes FGA grants for an AgentEnrollment.
func EnrollmentRevocationSteps(deps EnrollmentDeps) []saga.Step {
	return []saga.Step{
		newDeleteAgentFGAStep(deps),
	}
}

// agentEnrollmentOf returns obj as *AgentEnrollment or an error.
func agentEnrollmentOf(obj saga.ConditionedObject) (*gibsonv1alpha1.AgentEnrollment, error) {
	ae, ok := obj.(*gibsonv1alpha1.AgentEnrollment)
	if !ok {
		return nil, fmt.Errorf("expected *AgentEnrollment, got %T", obj)
	}
	return ae, nil
}

// agentPrincipal returns the FGA user string for an AgentEnrollment.
func agentPrincipal(ae *gibsonv1alpha1.AgentEnrollment) string {
	switch ae.Spec.PrincipalKind {
	case gibsonv1alpha1.PrincipalKindTool:
		return fmt.Sprintf("tool_principal:enrollment-%s", ae.UID)
	case gibsonv1alpha1.PrincipalKindPlugin:
		return fmt.Sprintf("plugin_principal:enrollment-%s", ae.UID)
	default:
		return fmt.Sprintf("agent_principal:enrollment-%s", ae.UID)
	}
}

// skipNonPluginPrincipal returns true (skip the step) for any enrollment
// that is not a plugin_principal.
func skipNonPluginPrincipal(obj saga.ConditionedObject) bool {
	ae, ok := obj.(*gibsonv1alpha1.AgentEnrollment)
	if !ok {
		return true
	}
	return ae.Spec.PrincipalKind != gibsonv1alpha1.PrincipalKindPlugin
}

// ---------------------------------------------------------------------------
// WriteComponentGrantsFGA
// ---------------------------------------------------------------------------

type writeAgentGrantsStep struct {
	saga.StepBase
	deps EnrollmentDeps
}

func newWriteAgentGrantsStep(deps EnrollmentDeps) *writeAgentGrantsStep {
	return &writeAgentGrantsStep{
		StepBase: saga.StepBase{
			N:     "WriteComponentGrantsFGA",
			C:     "GrantsApplied",
			Caps:  []saga.ClientCapability{saga.CapabilityFGA},
			Owner: "fga-integration",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *writeAgentGrantsStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	ae, err := agentEnrollmentOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.FGA is guaranteed non-nil: cmd/main.go exits 1 when FGA_URL or
	// FGA_STORE_ID are unset (one-code-path epic, deploy#186).
	if s.deps.FGA == nil {
		return false, fmt.Errorf("fga client unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	if len(ae.Spec.ComponentGrants) == 0 {
		ae.Status.GrantsAppliedCount = 0
		return true, nil
	}
	tuples := componentGrantTuples(ae)
	if err := s.deps.FGA.Write(ctx, tuples); err != nil {
		if errors.Is(err, clients.ErrAlreadyExists) {
			ae.Status.GrantsAppliedCount = len(tuples)
			return true, nil
		}
		return false, err
	}
	ae.Status.GrantsAppliedCount = len(tuples)
	return true, nil
}

// componentGrantTuples builds the FGA grant tuples for an enrollment's
// component grants, in the canonical form (gibson#694):
//
//	(<kind>_principal:enrollment-<uid>, direct_execute, component:<name>)
//
// The object is the bare, kind-less, tenant-less "component:<name>" — the
// same form gibson's daemon-side enrollment writes and every checker derives.
// The previous "component:<kind>-<name>" form matched no checker, and the
// previous can_execute relation is a computed relation in model.fga (no
// direct type restrictions), so OpenFGA rejects tuples written to it. The
// writable owner-side grant relation is direct_execute; the model composes it
// with in_tenant_catalog and the deny relations into the effective
// can_execute checkers evaluate.
func componentGrantTuples(ae *gibsonv1alpha1.AgentEnrollment) []fga.Tuple {
	tuples := make([]fga.Tuple, 0, len(ae.Spec.ComponentGrants))
	user := agentPrincipal(ae)
	for _, ref := range ae.Spec.ComponentGrants {
		tuples = append(tuples, fga.Tuple{
			User:     user,
			Relation: "direct_execute",
			Object:   "component:" + ref.Name,
		})
	}
	return tuples
}

// ---------------------------------------------------------------------------
// WriteSecretResolveGrantFGA (plugin_principal only)
// ---------------------------------------------------------------------------

type writeSecretResolveGrantStep struct {
	saga.StepBase
	deps EnrollmentDeps
}

func newWriteSecretResolveGrantStep(deps EnrollmentDeps) *writeSecretResolveGrantStep {
	return &writeSecretResolveGrantStep{
		StepBase: saga.StepBase{
			N:     "WriteSecretResolveGrantFGA",
			C:     "SecretResolveGrantApplied",
			Req:   []string{"WriteComponentGrantsFGA"},
			Caps:  []saga.ClientCapability{saga.CapabilityFGA},
			Owner: "fga-integration",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *writeSecretResolveGrantStep) Skip(obj saga.ConditionedObject) bool {
	return skipNonPluginPrincipal(obj)
}

func (s *writeSecretResolveGrantStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	ae, err := agentEnrollmentOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.FGA is guaranteed non-nil: cmd/main.go exits 1 when FGA_URL or
	// FGA_STORE_ID are unset (one-code-path epic, deploy#186).
	if s.deps.FGA == nil {
		return false, fmt.Errorf("fga client unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	enrollmentUID := fmt.Sprintf("enrollment-%s", ae.UID)
	tenantID := ae.Namespace
	if err := fga.WriteSecretResolveGrant(ctx, s.deps.FGA, enrollmentUID, tenantID); err != nil {
		return false, err
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// WritePluginCanInvokeGrantFGA (plugin_principal only)
// ---------------------------------------------------------------------------

type writePluginCanInvokeGrantStep struct {
	saga.StepBase
	deps EnrollmentDeps
}

func newWritePluginCanInvokeGrantStep(deps EnrollmentDeps) *writePluginCanInvokeGrantStep {
	return &writePluginCanInvokeGrantStep{
		StepBase: saga.StepBase{
			N:     "WritePluginCanInvokeGrantFGA",
			C:     "PluginCanInvokeGrantApplied",
			Req:   []string{"WriteSecretResolveGrantFGA"},
			Caps:  []saga.ClientCapability{saga.CapabilityFGA},
			Owner: "fga-integration",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *writePluginCanInvokeGrantStep) Skip(obj saga.ConditionedObject) bool {
	return skipNonPluginPrincipal(obj)
}

func (s *writePluginCanInvokeGrantStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	ae, err := agentEnrollmentOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.FGA is guaranteed non-nil: cmd/main.go exits 1 when FGA_URL or
	// FGA_STORE_ID are unset (one-code-path epic, deploy#186).
	if s.deps.FGA == nil {
		return false, fmt.Errorf("fga client unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	pluginName := ae.Spec.AgentName
	if pluginName == "" {
		return false, fmt.Errorf("plugin enrollment %s has empty AgentName", ae.Name)
	}
	tenantID := ae.Namespace
	if err := fga.WritePluginCanInvokeGrant(ctx, s.deps.FGA, pluginName, tenantID); err != nil {
		return false, err
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// DeleteAgentFGATuples
// ---------------------------------------------------------------------------

type deleteAgentFGAStep struct {
	saga.StepBase
	deps EnrollmentDeps
}

func newDeleteAgentFGAStep(deps EnrollmentDeps) *deleteAgentFGAStep {
	return &deleteAgentFGAStep{
		StepBase: saga.StepBase{
			N:     "DeleteAgentFGATuples",
			C:     "FGAGrantsDeleted",
			Caps:  []saga.ClientCapability{saga.CapabilityFGA},
			Owner: "fga-integration",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *deleteAgentFGAStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	ae, err := agentEnrollmentOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.FGA is guaranteed non-nil: cmd/main.go exits 1 when FGA_URL or
	// FGA_STORE_ID are unset (one-code-path epic, deploy#186).
	if s.deps.FGA == nil {
		return false, fmt.Errorf("fga client unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	if len(ae.Spec.ComponentGrants) == 0 {
		return true, nil
	}
	// Delete the same canonical tuples Provision writes (gibson#694).
	tuples := componentGrantTuples(ae)
	err = s.deps.FGA.Delete(ctx, tuples)
	if err == nil || errors.Is(err, clients.ErrNotFound) {
		return true, nil
	}
	return false, err
}

// AgentEnrollment ConditionedObject conformance check.
var _ saga.ConditionedObject = (*gibsonv1alpha1.AgentEnrollment)(nil)
