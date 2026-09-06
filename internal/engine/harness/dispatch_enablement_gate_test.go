// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"go.opentelemetry.io/otel/trace/noop"
)

// These cover the tenant-enablement gate on AGENT dispatch (gibson#1595): a
// mission may dispatch to component:agent/<name> only when the calling tenant
// has that agent enabled. The gate sits at the single choke point every
// mission→agent and agent→sub-agent dispatch flows through, so the fixtures
// drive the remote work-queue path and observe the gate as an Enqueue (allowed)
// or its absence (denied) — nothing may be enqueued on a deny.

// newEnablementGateHarness builds a harness whose only reachable dispatch path
// is the remote work queue. The authorizer is injected (nil to exercise the
// unwired fail-closed branch).
func newEnablementGateHarness(authorizer authz.Authorizer, q component.WorkQueue) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		logger:              slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:              noop.NewTracerProvider().Tracer("test"),
		metrics:             &NoOpMetricsRecorder{},
		componentRegistry:   &gateFakeRegistry{tenantInstances: remoteAgentInstances()},
		workQueue:           q,
		componentAuthorizer: authorizer,
	}
}

func successResultQueue(t *testing.T) *queueFake {
	t.Helper()
	return &queueFake{result: executeResponseJSON(t, &agentpb.ExecuteResponse{
		Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS},
	})}
}

// TestDispatchGate_AgentEnabled_Dispatches: can_execute → true, so the agent
// work is enqueued, and the check asks the exact question the callback service
// asks at invocation time (user = the caller's typed FGA ref, relation =
// can_execute, object = component:agent/<name>).
func TestDispatchGate_AgentEnabled_Dispatches(t *testing.T) {
	authorizer := &recordingAuthorizer{allow: true}
	q := successResultQueue(t)
	h := newEnablementGateHarness(authorizer, q)

	ctx := callerCtx(t, "user-42", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil)); err != nil {
		t.Fatalf("enabled agent must dispatch: %v", err)
	}

	if q.gotKind != "agent" {
		t.Fatalf("enabled agent was not enqueued (gotKind=%q)", q.gotKind)
	}
	if authorizer.gotRelation != "can_execute" {
		t.Errorf("relation = %q, want can_execute", authorizer.gotRelation)
	}
	if authorizer.gotObject != authz.ComponentObject(authz.KindAgent, "zerocool") {
		t.Errorf("object = %q, want component:agent/zerocool", authorizer.gotObject)
	}
	if authorizer.gotUser != "user:user-42" {
		t.Errorf("user = %q, want user:user-42 (the caller's typed FGA ref)", authorizer.gotUser)
	}
}

// TestDispatchGate_AgentNotEnabled_DeniedNoEnqueue: can_execute → false is
// exactly "not enabled for this tenant". The dispatch is denied with a clear
// SANDBOX_POLICY_DENIED error and NOTHING is enqueued.
func TestDispatchGate_AgentNotEnabled_DeniedNoEnqueue(t *testing.T) {
	q := successResultQueue(t)
	h := newEnablementGateHarness(&recordingAuthorizer{allow: false}, q)

	ctx := callerCtx(t, "user-42", "zerocool-lab")
	_, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil))
	if err == nil {
		t.Fatal("a disabled agent must be denied")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q, want SANDBOX_POLICY_DENIED", code)
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("error = %v, want a clear not-enabled message", err)
	}
	if q.gotKind != "" {
		t.Fatalf("denied dispatch still enqueued work (gotKind=%q)", q.gotKind)
	}
}

// TestDispatchGate_CheckError_DeniedNoEnqueue: an FGA error is undecidable, so
// the gate fails closed rather than dispatching.
func TestDispatchGate_CheckError_DeniedNoEnqueue(t *testing.T) {
	q := successResultQueue(t)
	h := newEnablementGateHarness(&recordingAuthorizer{err: errors.New("fga: connection refused")}, q)

	ctx := callerCtx(t, "user-42", "zerocool-lab")
	_, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil))
	if err == nil {
		t.Fatal("an FGA check error must fail closed")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q, want SANDBOX_POLICY_DENIED", code)
	}
	if q.gotKind != "" {
		t.Fatalf("failed-closed dispatch still enqueued work (gotKind=%q)", q.gotKind)
	}
}

// TestDispatchGate_NilAuthorizer_DeniedNoEnqueue: an unwired authorizer cannot
// decide, so the dispatch is denied. This matches the callback service's
// nil-authorizer handling (callback_credential_authz.go).
func TestDispatchGate_NilAuthorizer_DeniedNoEnqueue(t *testing.T) {
	q := successResultQueue(t)
	h := newEnablementGateHarness(nil, q)

	ctx := callerCtx(t, "user-42", "zerocool-lab")
	_, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil))
	if err == nil {
		t.Fatal("an unwired authorizer must fail closed")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q, want SANDBOX_POLICY_DENIED", code)
	}
	if q.gotKind != "" {
		t.Fatalf("unwired-authorizer dispatch still enqueued work (gotKind=%q)", q.gotKind)
	}
}
