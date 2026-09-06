// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/emptypb"
)

// These cover the tenant-enablement gate on TOOL dispatch (ADR-0017 /
// gibson#1638), the analogue of the agent gate: a mission may execute
// component:tool/<name> only when the calling tenant has that tool enabled. The
// gate is what gives tools per-tenant control, replacing the ungated _system
// refresher path.

func newToolGateHarness(a authz.Authorizer) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		logger:              slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:              noop.NewTracerProvider().Tracer("test"),
		metrics:             &NoOpMetricsRecorder{},
		componentAuthorizer: a,
	}
}

// TestToolGate_Enabled_Allows: can_execute → true passes, and the gate asks the
// exact question — user = the caller's typed FGA ref, relation = can_execute,
// object = component:tool/<name>.
func TestToolGate_Enabled_Allows(t *testing.T) {
	a := &recordingAuthorizer{allow: true}
	h := newToolGateHarness(a)
	if err := h.authorizeToolDispatch(callerCtx(t, "user-42", "acme"), "nmap"); err != nil {
		t.Fatalf("enabled tool must pass the gate: %v", err)
	}
	if a.gotRelation != "can_execute" {
		t.Errorf("relation = %q, want can_execute", a.gotRelation)
	}
	if a.gotObject != authz.ComponentObject(authz.KindTool, "nmap") {
		t.Errorf("object = %q, want component:tool/nmap", a.gotObject)
	}
	if a.gotUser != "user:user-42" {
		t.Errorf("user = %q, want user:user-42", a.gotUser)
	}
}

// TestToolGate_NotEnabled_Denied: can_execute → false is "not enabled for this
// tenant"; deny with SANDBOX_POLICY_DENIED and a clear message.
func TestToolGate_NotEnabled_Denied(t *testing.T) {
	h := newToolGateHarness(&recordingAuthorizer{allow: false})
	err := h.authorizeToolDispatch(callerCtx(t, "user-42", "acme"), "nmap")
	if err == nil {
		t.Fatal("a tool the tenant did not enable must be denied")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q, want SANDBOX_POLICY_DENIED", code)
	}
}

// TestToolGate_CheckError_FailsClosed: an FGA error is undecidable → deny.
func TestToolGate_CheckError_FailsClosed(t *testing.T) {
	h := newToolGateHarness(&recordingAuthorizer{err: errors.New("fga: connection refused")})
	if err := h.authorizeToolDispatch(callerCtx(t, "user-42", "acme"), "nmap"); err == nil {
		t.Fatal("an FGA check error must fail closed")
	}
}

// TestToolGate_NilAuthorizer_FailsClosed: an unwired authorizer cannot decide → deny.
func TestToolGate_NilAuthorizer_FailsClosed(t *testing.T) {
	h := newToolGateHarness(nil)
	if err := h.authorizeToolDispatch(callerCtx(t, "user-42", "acme"), "nmap"); err == nil {
		t.Fatal("an unwired authorizer must fail closed")
	}
}

// TestSandboxedToolSpecFromManifest resolves nmap's launch spec straight from
// the embedded kind:tool manifest (ADR-0017): the shared executor image, the
// launch command, and GIBSON_TOOL_NAME selecting the tool inside it.
func TestSandboxedToolSpecFromManifest(t *testing.T) {
	h := &DefaultAgentHarness{} // zero missionCtx is fine: agentEgressCeiling("") is nil
	spec, ok := h.sandboxedToolSpecFromManifest("nmap")
	if !ok {
		t.Fatal("nmap must resolve from the embedded manifest")
	}
	if spec.Env["GIBSON_TOOL_NAME"] != "nmap" {
		t.Errorf("GIBSON_TOOL_NAME = %q, want nmap", spec.Env["GIBSON_TOOL_NAME"])
	}
	if spec.Image == "" || len(spec.Command) == 0 {
		t.Errorf("spec must carry the executor image + command, got image=%q command=%v", spec.Image, spec.Command)
	}
	if _, ok := h.sandboxedToolSpecFromManifest("does-not-exist"); ok {
		t.Error("an unknown tool must not resolve")
	}
}

// TestCallToolProto_ManifestTool_DeniedForUnenabledTenant proves the manifest
// dispatch path is gated: nmap is a real manifest tool, but a tenant that never
// enabled it is denied before anything is launched (the executor is never
// consulted — it is nil here and the call still returns a clean deny).
func TestCallToolProto_ManifestTool_DeniedForUnenabledTenant(t *testing.T) {
	h := &DefaultAgentHarness{
		logger:              slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:              noop.NewTracerProvider().Tracer("test"),
		metrics:             &NoOpMetricsRecorder{},
		componentAuthorizer: &recordingAuthorizer{allow: false},
	}
	err := h.CallToolProto(callerCtx(t, "user-42", "acme"), "nmap", &emptypb.Empty{}, &emptypb.Empty{})
	if err == nil {
		t.Fatal("nmap dispatch for a tenant that never enabled it must be denied")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q, want SANDBOX_POLICY_DENIED", code)
	}
	if a := h.componentAuthorizer.(*recordingAuthorizer); a.gotObject != authz.ComponentObject(authz.KindTool, "nmap") {
		t.Errorf("gate object = %q, want component:tool/nmap", a.gotObject)
	}
}
