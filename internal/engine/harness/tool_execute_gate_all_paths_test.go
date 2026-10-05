// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// These tests cover the execute gate on EVERY tool dispatch path. The gate
// asks one question before any lookup: may the caller execute
// component:tool/<name>? A tool the tenant did not enable is refused whether
// it is found in the manifest catalog, the component registry or the registry
// adapter, and whether the call is unary or streaming.
//
// Each test uses a TRUSTED component under the setec-only shape, so the trust
// gate would let the call through. The execute gate is the only thing that
// can refuse it.

// TestExecuteGate_RegistryTool_RefusedWhenNotEnabled: a tool found in the
// component registry, for a tenant that did not enable it, is refused and no
// dispatch path is reached.
func TestExecuteGate_RegistryTool_RefusedWhenNotEnabled(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	deny := &recordingAuthorizer{allow: false}
	h.componentAuthorizer = deny

	err := h.CallToolProto(callerCtx(t, "user-42", "acme"), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{})
	if err == nil {
		t.Fatal("a registry tool the tenant did not enable must be refused")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q, want SANDBOX_POLICY_DENIED", code)
	}
	if spy.discoverToolCalled {
		t.Fatal("the call reached the in-process dispatch path after the gate refused it")
	}
	if deny.gotRelation != "can_execute" || deny.gotObject != authz.ComponentObject(authz.KindTool, "acme-registry-tool") {
		t.Errorf("gate asked (%q, %q), want (can_execute, component:tool/acme-registry-tool)", deny.gotRelation, deny.gotObject)
	}
}

// TestExecuteGate_AdapterOnlyTool_RefusedWhenNotEnabled: a tool that only the
// registry adapter knows (no component registry at all) is refused the same
// way. This is the last dispatch path.
func TestExecuteGate_AdapterOnlyTool_RefusedWhenNotEnabled(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	h.componentRegistry = nil
	h.componentAuthorizer = &recordingAuthorizer{allow: false}

	err := h.CallToolProto(callerCtx(t, "user-42", "acme"), "adapter-only-tool", wrapperspb.String("in"), &wrapperspb.StringValue{})
	if err == nil {
		t.Fatal("an adapter tool the tenant did not enable must be refused")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q, want SANDBOX_POLICY_DENIED", code)
	}
	if spy.discoverToolCalled {
		t.Fatal("the call reached the registry adapter after the gate refused it")
	}
}

// TestExecuteGate_Stream_RefusedWhenNotEnabled: the streaming harness call is
// another road to the same tool, and it is refused before any lookup.
func TestExecuteGate_Stream_RefusedWhenNotEnabled(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
	h.componentAuthorizer = &recordingAuthorizer{allow: false}

	err := h.CallToolProtoStream(callerCtx(t, "user-42", "acme"), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{}, nil)
	if err == nil {
		t.Fatal("a streaming call to a tool the tenant did not enable must be refused")
	}
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q, want SANDBOX_POLICY_DENIED", code)
	}
	if spy.discoverToolCalled {
		t.Fatal("the streaming call reached discovery after the gate refused it")
	}
}

// TestExecuteGate_FailsClosedOnEveryPath: no authorizer, no caller identity
// and no tenant each refuse the call on the registry path and on the
// streaming path. An undecidable question is a refusal.
func TestExecuteGate_FailsClosedOnEveryPath(t *testing.T) {
	cases := []struct {
		name string
		ctx  func(t *testing.T) context.Context
		az   authz.Authorizer
	}{
		{"no authorizer wired", func(t *testing.T) context.Context { return callerCtx(t, "user-42", "acme") }, nil},
		{"no caller identity", func(*testing.T) context.Context {
			return auth.ContextWithTenantString(context.Background(), "acme")
		}, &recordingAuthorizer{allow: true}},
		{"no tenant", func(*testing.T) context.Context { return context.Background() }, &recordingAuthorizer{allow: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, dispatchpolicy.ShapeSetecOnly)
			h.componentAuthorizer = tc.az

			if err := h.CallToolProto(tc.ctx(t), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{}); err == nil {
				t.Error("the unary call must be refused")
			}
			if err := h.CallToolProtoStream(tc.ctx(t), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{}, nil); err == nil {
				t.Error("the streaming call must be refused")
			}
			if spy.discoverToolCalled {
				t.Error("a refused call reached discovery")
			}
		})
	}
}

// TestExecuteGate_CallbackStream_RefusedWhenNotEnabled: the callback service
// resolves and streams a tool itself, so it asks the question itself. A
// refusal sends one PERMISSION_DENIED event, returns PermissionDenied, never
// opens a stream to the tool, and records no tool call.
func TestExecuteGate_CallbackStream_RefusedWhenNotEnabled(t *testing.T) {
	toolServer := &fakeStreamToolServer{sendComplete: true, outputJSON: `{"ok":true}`}
	conn := startFakeToolServer(t, toolServer)

	h := newStreamingTestHarness(conn)
	h.componentAuthorizer = &recordingAuthorizer{allow: false}
	registry := NewCallbackHarnessRegistry()
	registry.Register("test-mission-stream", "test-agent", h)

	var captured int
	svc := NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(os.Stdout, nil)),
		registry,
		WithToolCallSink(func(context.Context, string, ToolCallRecord) { captured++ }),
	)
	req := &harnesspb.CallToolProtoStreamRequest{
		Context: &harnesspb.ContextInfo{
			TaskId: "task-1", AgentName: "test-agent", MissionId: "test-mission-stream",
			MissionRunId: "run-1", ToolExecutionId: "tool-exec-refused-1",
		},
		Name:       "stream-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query":"streamed"}`),
		OutputType: "testtool.ToolOutput",
		TimeoutMs:  5000,
	}
	stream := &fakeStreamSendServer{ctx: callerCtx(t, "user-42", "test-tenant")}

	err := svc.CallToolProtoStream(req, stream)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("sent %d events, want one error event", len(stream.sent))
	}
	ev := stream.sent[0].GetError()
	if ev == nil || !ev.GetFatal() || ev.GetError().GetCode().String() != "ERROR_CODE_PERMISSION_DENIED" {
		t.Fatalf("event = %v, want a fatal PERMISSION_DENIED error", stream.sent[0])
	}
	if captured != 0 {
		t.Errorf("a refused call recorded %d tool call(s)", captured)
	}
}
