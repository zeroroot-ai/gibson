// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// spyAdapter is a component.ComponentDiscovery whose DescribeTool records
// whether it was reached. Every other method is inherited from the embedded
// nil interface and panics if invoked. A tool has the sandbox path and the
// work queue path only (ADR-0110), so the dispatch asks the adapter for
// nothing.
type spyAdapter struct {
	component.ComponentDiscovery
	discoverToolCalled bool
}

func (s *spyAdapter) DescribeTool(_ context.Context, _ string) (component.ComponentInfo, error) {
	s.discoverToolCalled = true
	return component.ComponentInfo{}, errors.New("spy: the registry adapter was selected for a dispatch")
}

// newNoFallbackHarness wires a harness whose one tool instance reports a
// grpc_endpoint, with a spyAdapter installed. Before gibson#755 such an
// instance took a direct gRPC call through the adapter.
func newNoFallbackHarness(t *testing.T, trust componentpb.ContentTrust) (*DefaultAgentHarness, *spyAdapter) {
	t.Helper()
	spy := &spyAdapter{}
	h := &DefaultAgentHarness{
		logger: slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer: noop.NewTracerProvider().Tracer("test"),
		// The execute gate runs first. The tenant has the tool enabled, so
		// these tests still measure the dispatch and not the execute gate.
		componentAuthorizer: &recordingAuthorizer{allow: true},
		componentRegistry: &gateFakeRegistry{
			tenantInstances: []component.ComponentInfo{{
				Kind:         "tool",
				Name:         "acme-registry-tool",
				InstanceID:   "i1",
				ContentTrust: trust,
				// The gate reads where an instance runs, not what it reports.
				// The denied case is an attested instance the catalog does not
				// list. The allowed case is an instance on the tenant's machine.
				Attested: trust == componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED,
				Metadata: map[string]string{"grpc_endpoint": "localhost:1"},
			}},
		},
		registryAdapter: spy,
	}
	return h, spy
}

// The tool name must NOT be a kind:tool catalog manifest. A manifest tool takes
// the earlier manifest path in CallToolProto (ADR-0117) and never reaches the
// registry dispatch these tests cover.

// TestDispatchGate_UntrustedSetecOnly_NoInProcessFallback: cluster code that
// the catalog does not state as trusted is denied with the typed
// SANDBOX_POLICY_DENIED code, and the registry adapter is not called.
func TestDispatchGate_UntrustedSetecOnly_NoInProcessFallback(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED)
	ctx := callerCtx(t, "user-42", "acme")

	err := h.CallToolProto(ctx, "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{})
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED", code)
	}
	if spy.discoverToolCalled {
		t.Fatal("a denied tool reached the registry adapter")
	}
}

// TestCallToolProto_AReportedEndpointSelectsNoDirectCall: a tool that passes
// the gate and reports a grpc_endpoint takes the work queue. The daemon dials
// no address that a tool reports (gibson#755).
func TestCallToolProto_AReportedEndpointSelectsNoDirectCall(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED)
	q := &queueFake{waitErr: errors.New("stop after the enqueue")}
	h.workQueue = q
	h.metrics = &NoOpMetricsRecorder{}

	_ = h.CallToolProto(callerCtx(t, "user-42", "acme"), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{})
	if spy.discoverToolCalled {
		t.Fatal("the tool reached the registry adapter; a tool has the sandbox and the work queue only")
	}
	if q.gotKind != "tool" || q.gotName != "acme-registry-tool" {
		t.Fatalf("enqueued kind/name = %q/%q; want tool/acme-registry-tool", q.gotKind, q.gotName)
	}
}

// TestCallToolProto_NoManifestAndNoQueueInstanceIsNotFound: a tool with no
// sandbox manifest and no work queue instance gets the typed error, and the
// registry adapter is no fallback (gibson#755).
func TestCallToolProto_NoManifestAndNoQueueInstanceIsNotFound(t *testing.T) {
	cases := map[string]func(h *DefaultAgentHarness){
		"no instance":           func(h *DefaultAgentHarness) { h.componentRegistry = &gateFakeRegistry{}; h.workQueue = &queueFake{} },
		"no component registry": func(h *DefaultAgentHarness) { h.componentRegistry = nil; h.workQueue = &queueFake{} },
		"no work queue":         func(h *DefaultAgentHarness) { h.workQueue = nil },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED)
			setup(h)
			err := h.CallToolProto(callerCtx(t, "user-42", "acme"), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{})
			if code := gibsonCode(t, err); code != ErrHarnessToolNotFound {
				t.Fatalf("code = %q; want %q", code, ErrHarnessToolNotFound)
			}
			if spy.discoverToolCalled {
				t.Fatal("the registry adapter was used as a fallback")
			}
		})
	}
}

// TestCallToolProtoStream_UsesTheSameDispatch: a streamed call takes the work
// queue like a unary call, and delivers the error through the callback.
func TestCallToolProtoStream_UsesTheSameDispatch(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED)
	q := &queueFake{waitErr: errors.New("stop after the enqueue")}
	h.workQueue = q
	h.metrics = &NoOpMetricsRecorder{}

	err := h.CallToolProtoStream(callerCtx(t, "user-42", "acme"), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{}, nil)
	if err == nil {
		t.Fatal("want the work queue error")
	}
	if spy.discoverToolCalled {
		t.Fatal("a streamed call reached the registry adapter")
	}
	if q.gotKind != "tool" {
		t.Fatalf("enqueued kind = %q; want tool", q.gotKind)
	}
}

// TestCallToolProto_DiscoveryFailureIsAnExecutionFailure: a registry error
// stops the dispatch with the typed error. It is not a missing tool.
func TestCallToolProto_DiscoveryFailureIsAnExecutionFailure(t *testing.T) {
	h, _ := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED)
	h.componentRegistry = &gateFakeRegistry{discoverErr: errors.New("registry down")}
	h.workQueue = &queueFake{}

	err := h.CallToolProto(callerCtx(t, "user-42", "acme"), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{})
	if code := gibsonCode(t, err); code != ErrHarnessToolExecutionFailed {
		t.Fatalf("code = %q; want %q", code, ErrHarnessToolExecutionFailed)
	}
}

// recordingStreamCallback records the events of a streamed tool call.
type recordingStreamCallback struct {
	partials int
	errs     []error
}

func (c *recordingStreamCallback) OnProgress(int, string, string) {}
func (c *recordingStreamCallback) OnPartial(proto.Message, bool)  { c.partials++ }
func (c *recordingStreamCallback) OnWarning(string, string)       {}
func (c *recordingStreamCallback) OnError(err error, _ bool)      { c.errs = append(c.errs, err) }

// TestCallToolProtoStream_ErrorReachesTheCallback: the error of the unary
// dispatch reaches the callback once and returns.
func TestCallToolProtoStream_ErrorReachesTheCallback(t *testing.T) {
	h, _ := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED)
	h.componentRegistry = &gateFakeRegistry{}
	h.workQueue = &queueFake{}
	cb := &recordingStreamCallback{}

	err := h.CallToolProtoStream(callerCtx(t, "user-42", "acme"), "acme-registry-tool", wrapperspb.String("in"), &wrapperspb.StringValue{}, cb)
	if code := gibsonCode(t, err); code != ErrHarnessToolNotFound {
		t.Fatalf("code = %q; want %q", code, ErrHarnessToolNotFound)
	}
	if len(cb.errs) != 1 || cb.partials != 0 {
		t.Fatalf("callback got %d errors and %d partials; want 1 and 0", len(cb.errs), cb.partials)
	}
}

// TestCallToolProtoStream_NilMessageIsRefused: a nil request or response is
// an execution failure, and no dispatch starts.
func TestCallToolProtoStream_NilMessageIsRefused(t *testing.T) {
	h, spy := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED)

	err := h.CallToolProtoStream(callerCtx(t, "user-42", "acme"), "acme-registry-tool", nil, &wrapperspb.StringValue{}, nil)
	if code := gibsonCode(t, err); code != ErrHarnessToolExecutionFailed {
		t.Fatalf("code = %q; want %q", code, ErrHarnessToolExecutionFailed)
	}
	if spy.discoverToolCalled {
		t.Fatal("a refused call reached the registry adapter")
	}
}

// TestCallToolProtoStream_ResultReachesTheCallback: the result of the unary
// dispatch reaches the callback as one partial event.
func TestCallToolProtoStream_ResultReachesTheCallback(t *testing.T) {
	h, _ := newNoFallbackHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED)
	h.workQueue = &queueFake{result: []byte(`"out"`)}
	h.metrics = &NoOpMetricsRecorder{}
	cb := &recordingStreamCallback{}
	out := &wrapperspb.StringValue{}

	if err := h.CallToolProtoStream(callerCtx(t, "user-42", "acme"), "acme-registry-tool", wrapperspb.String("in"), out, cb); err != nil {
		t.Fatalf("CallToolProtoStream: %v", err)
	}
	if cb.partials != 1 || len(cb.errs) != 0 {
		t.Fatalf("callback got %d partials and %d errors; want 1 and 0", cb.partials, len(cb.errs))
	}
	if out.GetValue() != "out" {
		t.Fatalf("output = %q; want out", out.GetValue())
	}
}
