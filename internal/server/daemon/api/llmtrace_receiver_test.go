// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
)

const collectorSVID = "spiffe://example.org/platform/otel-collector"

// spanFromFixture reads a real gateway span from the llmtrace test data and
// returns it as an OTLP span. The test data holds typed attributes.
func spanFromFixture(t *testing.T, name string, override map[string]string) *tracepb.Span {
	t.Helper()
	data, err := fs.ReadFile(os.DirFS(filepath.Join("..", "..", "..", "engine", "llmtrace", "testdata")), name+".json")
	if err != nil {
		t.Fatalf("read span %s: %v", name, err)
	}
	var f struct {
		Attributes map[string]any `json:"attributes"`
		Start      uint64         `json:"start_unix_nano"`
		End        uint64         `json:"end_unix_nano"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for k, v := range override {
		f.Attributes[k] = v
	}
	sp := &tracepb.Span{Name: "POST /*", StartTimeUnixNano: f.Start, EndTimeUnixNano: f.End}
	for k, v := range f.Attributes {
		kv := &commonpb.KeyValue{Key: k}
		switch x := v.(type) {
		case string:
			kv.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: x}}
		case float64:
			kv.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(x)}}
		default:
			continue
		}
		sp.Attributes = append(sp.Attributes, kv)
	}
	return sp
}

func exportOf(spans ...*tracepb.Span) *coltrace.ExportTraceServiceRequest {
	return &coltrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: spans}},
	}}}
}

func newReceiver(t *testing.T) (*TraceReceiver, *brain.Registry) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	return NewTraceReceiver(collectorSVID, reg, nil), reg
}

func awaitCalls(t *testing.T, eng *brain.Engine, want int) []brain.LlmCallSnapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := eng.LlmCalls(); len(got) == want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("LLM calls = %d, want %d", len(eng.LlmCalls()), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Only the SPIFFE identity of the collector may send spans.
func TestTraceReceiver_OnlyTheCollectorMaySend(t *testing.T) {
	r, _ := newReceiver(t)
	req := exportOf(spanFromFixture(t, "messages_plain", nil))
	for name, ctx := range map[string]context.Context{
		"no peer":       context.Background(),
		"another peer":  peerCtx(t, "spiffe://example.org/platform/tenant-operator"),
		"envoy as peer": peerCtx(t, "spiffe://example.org/ns/gibson/sa/envoy"),
	} {
		_, err := r.Export(ctx, req)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: code = %v, want PermissionDenied", name, status.Code(err))
		}
	}
	empty := NewTraceReceiver("", nil, nil)
	if _, err := empty.Export(peerCtx(t, collectorSVID), req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no configured collector: code = %v, want PermissionDenied", status.Code(err))
	}
}

// A span goes to the engine of its tenant, as the call event and the token
// event. A span delivered two times counts one time.
func TestTraceReceiver_RoutesByTenantAndCountsACallOnce(t *testing.T) {
	r, reg := newReceiver(t)
	ctx := peerCtx(t, collectorSVID)
	span := spanFromFixture(t, "messages_plain", map[string]string{"gibson.tenant": "acme", "gibson.mission": "m1"})
	engine := reg.For("acme")
	engine.Submit(brain.MissionStarted{ID: "m1", RunID: "r1"})

	beforeDelivered := testutil.ToFloat64(gatewayLLMDeliveredTotal)
	for range 2 {
		if _, err := r.Export(ctx, exportOf(span)); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}
	calls := awaitCalls(t, engine, 1)
	if calls[0].Cost != "0.00069" || len(calls[0].Items) != 6 {
		t.Errorf("call = %+v", calls[0])
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		ms := engine.Missions()
		if len(ms) == 1 && ms[0].TokensUsed == 165 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mission tokens = %+v, want 165 once", engine.Missions())
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // the second delivery has folded by now
	if got := engine.Missions()[0].TokensUsed; got != 165 {
		t.Errorf("tokens after a second delivery = %d, want 165", got)
	}
	if got := testutil.ToFloat64(gatewayLLMDeliveredTotal) - beforeDelivered; got != 2 {
		t.Errorf("delivered = %v, want 2 (each delivery is counted, the fold is idempotent)", got)
	}
	// Another tenant holds nothing.
	if n := len(reg.For("other").LlmCalls()); n != 0 {
		t.Errorf("tenant other holds %d calls, want 0", n)
	}
}

func TestTraceReceiver_DropsAreCounted(t *testing.T) {
	r, _ := newReceiver(t)
	ctx := peerCtx(t, collectorSVID)
	drops := func(reason string) float64 { return testutil.ToFloat64(gatewayLLMDroppedTotal.WithLabelValues(reason)) }

	noTenant := spanFromFixture(t, "messages_plain", map[string]string{"gibson.tenant": ""})
	badTenant := spanFromFixture(t, "messages_plain", map[string]string{"gibson.tenant": "NOT A TENANT"})
	badBody := spanFromFixture(t, "messages_plain", map[string]string{"gibson.request_body": "not json"})
	notModel := spanFromFixture(t, "messages_plain", map[string]string{"url.path": "/healthz"})

	before := map[string]float64{dropNoTenant: drops(dropNoTenant), dropBadTenant: drops(dropBadTenant), dropParse: drops(dropParse)}
	reqBefore := testutil.ToFloat64(gatewayLLMRequestsTotal)
	resp, err := r.Export(ctx, exportOf(noTenant, badTenant, badBody, notModel))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	for reason, want := range map[string]float64{dropNoTenant: 1, dropBadTenant: 1, dropParse: 1} {
		if got := drops(reason) - before[reason]; got != want {
			t.Errorf("drops[%s] = %v, want %v", reason, got, want)
		}
	}
	// A span that is not a model call is not counted as a request.
	if got := testutil.ToFloat64(gatewayLLMRequestsTotal) - reqBefore; got != 3 {
		t.Errorf("requests = %v, want 3", got)
	}
	if resp.GetPartialSuccess().GetRejectedSpans() != 3 {
		t.Errorf("rejected spans = %d, want 3", resp.GetPartialSuccess().GetRejectedSpans())
	}
}

// A call that the gateway refused has no tenant, because ext-authz set none. It
// is counted as refused. It is not a request and not a drop, so the drop check
// of the exit test still means "a span that the daemon should have stored".
func TestTraceReceiver_ARefusedCallIsNotADrop(t *testing.T) {
	r, _ := newReceiver(t)
	ctx := peerCtx(t, collectorSVID)
	refused := spanFromFixture(t, "messages_denied", map[string]string{"gibson.tenant": ""})

	refusedBefore := testutil.ToFloat64(gatewayLLMRefusedTotal)
	dropsBefore := testutil.ToFloat64(gatewayLLMDroppedTotal.WithLabelValues(dropNoTenant))
	reqBefore := testutil.ToFloat64(gatewayLLMRequestsTotal)
	resp, err := r.Export(ctx, exportOf(refused))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := testutil.ToFloat64(gatewayLLMRefusedTotal) - refusedBefore; got != 1 {
		t.Errorf("refused = %v, want 1", got)
	}
	if got := testutil.ToFloat64(gatewayLLMDroppedTotal.WithLabelValues(dropNoTenant)) - dropsBefore; got != 0 {
		t.Errorf("drops[no_tenant] = %v, want 0", got)
	}
	if got := testutil.ToFloat64(gatewayLLMRequestsTotal) - reqBefore; got != 0 {
		t.Errorf("requests = %v, want 0", got)
	}
	if resp.GetPartialSuccess().GetRejectedSpans() != 0 {
		t.Errorf("rejected spans = %d, want 0", resp.GetPartialSuccess().GetRejectedSpans())
	}
}

// An engine that is not available fails the call, so the collector sends it
// again.
func TestTraceReceiver_AStoppedEngineFailsTheCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, func(context.Context, string) (brain.TimelineStore, error) {
		return nil, errors.New("the Timeline store is down")
	})
	r := NewTraceReceiver(collectorSVID, reg, nil)
	span := spanFromFixture(t, "messages_plain", map[string]string{"gibson.tenant": "acme"})
	_, err := r.Export(peerCtx(t, collectorSVID), exportOf(span))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

// oneOutsideStore is an outside agent store with one registered name for one
// tenant.
type oneOutsideStore struct {
	tenant, name string
	err          error
}

func (m *oneOutsideStore) Register(context.Context, string, outsideagentstore.Entry) (*outsideagentstore.Entry, error) {
	return nil, errors.New("not used")
}

func (m *oneOutsideStore) List(context.Context, string) ([]outsideagentstore.Entry, error) {
	return nil, errors.New("not used")
}

func (m *oneOutsideStore) Get(_ context.Context, tenant, name string) (*outsideagentstore.Entry, error) {
	if m.err != nil {
		return nil, m.err
	}
	if tenant == m.tenant && name == m.name {
		return &outsideagentstore.Entry{Name: name}, nil
	}
	return nil, outsideagentstore.ErrNotFound
}

func (m *oneOutsideStore) Delete(context.Context, string, string) error {
	return errors.New("not used")
}

func awaitOutsideCalls(t *testing.T, eng *brain.Engine, want int) []brain.OutsideAgentCall {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := eng.OutsideAgentCalls(); len(got) == want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("outside calls = %d, want %d", len(eng.OutsideAgentCalls()), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The real A2A span of the gateway becomes one Timeline event of the tenant, with
// the caller, the target, the times and the outcome. A second delivery of the
// span keeps one event.
func TestTraceReceiver_AnA2ASpanToAnOutsideAgentBecomesATimelineEvent(t *testing.T) {
	r, reg := newReceiver(t)
	store := &oneOutsideStore{tenant: "acme", name: "partner-scout"}
	r.WithOutsideAgents(func() outsideagentstore.Store { return store })
	ctx := peerCtx(t, collectorSVID)
	span := spanFromFixture(t, "a2a_send_message", map[string]string{"gibson.tenant": "acme"})
	engine := reg.For("acme")

	before := testutil.ToFloat64(gatewayOutsideCallsTotal.WithLabelValues(outsideRecorded))
	for range 2 {
		if _, err := r.Export(ctx, exportOf(span)); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}
	calls := awaitOutsideCalls(t, engine, 1)
	time.Sleep(50 * time.Millisecond)
	if got := engine.OutsideAgentCalls(); len(got) != 1 {
		t.Fatalf("calls after a second delivery = %d, want 1", len(got))
	}
	c := calls[0]
	if c.Target != "partner-scout" || c.MissionID != "m-1" || c.TaskID != "task-1" || c.Subject != "user:u1" ||
		c.Method != "SendMessage" || c.Status != "ok" || c.HTTPStatus != 200 ||
		c.StartUnixNano == 0 || c.EndUnixNano < c.StartUnixNano {
		t.Errorf("call = %+v", c)
	}
	if got := testutil.ToFloat64(gatewayOutsideCallsTotal.WithLabelValues(outsideRecorded)) - before; got != 2 {
		t.Errorf("recorded = %v, want 2 (each delivery counts, the fold keeps one)", got)
	}
	// Another tenant holds nothing.
	if n := len(reg.For("other").OutsideAgentCalls()); n != 0 {
		t.Errorf("tenant other holds %d calls, want 0", n)
	}
}

// An A2A span of a target that is not an outside agent of the tenant is ignored.
// So is the span of a tenant that registered the name under another tenant.
func TestTraceReceiver_AnA2ASpanOfAnotherTargetIsIgnored(t *testing.T) {
	cases := map[string]struct {
		store *oneOutsideStore
		over  map[string]string
	}{
		"a platform agent":           {&oneOutsideStore{tenant: "acme", name: "partner-scout"}, map[string]string{"gibson.route_agent": "cve-triage"}},
		"the name of another tenant": {&oneOutsideStore{tenant: "globex", name: "partner-scout"}, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, reg := newReceiver(t)
			r.WithOutsideAgents(func() outsideagentstore.Store { return tc.store })
			over := map[string]string{"gibson.tenant": "acme"}
			for k, v := range tc.over {
				over[k] = v
			}
			before := testutil.ToFloat64(gatewayOutsideCallsTotal.WithLabelValues(outsideNotOutside))
			resp, err := r.Export(peerCtx(t, collectorSVID), exportOf(spanFromFixture(t, "a2a_send_message", over)))
			if err != nil || resp.GetPartialSuccess().GetRejectedSpans() != 0 {
				t.Fatalf("Export = %v, %v; want success with no rejected span", resp, err)
			}
			if got := testutil.ToFloat64(gatewayOutsideCallsTotal.WithLabelValues(outsideNotOutside)) - before; got != 1 {
				t.Errorf("not_outside = %v, want 1", got)
			}
			time.Sleep(50 * time.Millisecond)
			if n := len(reg.For("acme").OutsideAgentCalls()); n != 0 {
				t.Errorf("events = %d, want 0", n)
			}
		})
	}

	// With no store, the span is ignored.
	r, reg := newReceiver(t)
	if _, err := r.Export(peerCtx(t, collectorSVID), exportOf(spanFromFixture(t, "a2a_send_message",
		map[string]string{"gibson.tenant": "acme"}))); err != nil {
		t.Fatalf("Export with no store: %v", err)
	}
	if n := len(reg.For("acme").OutsideAgentCalls()); n != 0 {
		t.Errorf("events with no store = %d, want 0", n)
	}
}

func TestTraceReceiver_AnA2ASpanWithADefectIsRejectedAndCounted(t *testing.T) {
	r, _ := newReceiver(t)
	r.WithOutsideAgents(func() outsideagentstore.Store { return &oneOutsideStore{tenant: "acme", name: "partner-scout"} })
	drops := func(result string) float64 {
		return testutil.ToFloat64(gatewayOutsideCallsTotal.WithLabelValues(result))
	}
	beforeParse, beforeTenant := drops(outsideDropParse), drops(outsideDropTenant)

	noTarget := spanFromFixture(t, "a2a_send_message", map[string]string{"gibson.tenant": "acme", "gibson.route_agent": ""})
	badTenant := spanFromFixture(t, "a2a_send_message", map[string]string{"gibson.tenant": "NOT A TENANT"})
	resp, err := r.Export(peerCtx(t, collectorSVID), exportOf(noTarget, badTenant))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if resp.GetPartialSuccess().GetRejectedSpans() != 2 {
		t.Errorf("rejected = %d, want 2", resp.GetPartialSuccess().GetRejectedSpans())
	}
	if got := drops(outsideDropParse) - beforeParse; got != 1 {
		t.Errorf("dropped_parse = %v, want 1", got)
	}
	if got := drops(outsideDropTenant) - beforeTenant; got != 1 {
		t.Errorf("dropped_tenant = %v, want 1", got)
	}
}

// A store that cannot answer fails the call, so the collector sends it again.
func TestTraceReceiver_AStoreThatCannotAnswerFailsTheCall(t *testing.T) {
	r, _ := newReceiver(t)
	r.WithOutsideAgents(func() outsideagentstore.Store { return &oneOutsideStore{err: errors.New("db down")} })
	_, err := r.Export(peerCtx(t, collectorSVID), exportOf(spanFromFixture(t, "a2a_send_message",
		map[string]string{"gibson.tenant": "acme"})))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}
