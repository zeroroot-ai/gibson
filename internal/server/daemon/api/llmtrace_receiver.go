// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/llmtrace"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	"github.com/zeroroot-ai/sdk/auth"
)

// EnvTraceCollectorSVID names the environment variable that holds the SPIFFE ID
// of the trace collector. Only that identity may send spans to the daemon.
const EnvTraceCollectorSVID = "GIBSON_TRACE_COLLECTOR_SVID"

// The metrics of the gateway trace path (gibson#1390). The drop counter is the
// check of the exit test: each model call that the gateway served makes one
// span, each span makes one delivery, and a drop names why it did not.
var (
	gatewayLLMRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gibson_gateway_llm_requests_total",
		Help: "Model call spans that the gateway trace delivered to the daemon.",
	})
	gatewayLLMDeliveredTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gibson_gateway_llm_events_delivered_total",
		Help: "Model call spans whose events were submitted to the Timeline of a tenant.",
	})
	// gatewayOutsideCallsTotal counts the A2A spans of the Agent gateway by what
	// the receiver did with them. A span of a call to an agent that is not an
	// outside agent is ignored, because the daemon records that call itself.
	gatewayOutsideCallsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gibson_gateway_outside_calls_total",
		Help: "A2A spans of the Agent gateway, by result.",
	}, []string{"result"})
	gatewayLLMDroppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gibson_gateway_llm_dropped_total",
		Help: "Model call spans that the daemon did not deliver, by reason.",
	}, []string{"reason"})
)

// Results of an A2A span, the label of gibson_gateway_outside_calls_total.
const (
	outsideRecorded   = "recorded"
	outsideNotOutside = "not_outside"
	outsideDropParse  = "dropped_parse"
	outsideDropTenant = "dropped_tenant"
	outsideDropLookup = "dropped_lookup"
)

// Reasons of a dropped span.
const (
	dropParse     = "parse"
	dropNoTenant  = "no_tenant"
	dropBadTenant = "bad_tenant"
)

// TraceReceiver is the OTLP trace service of the daemon. The collector sends
// the spans of the gateway to it. Only the SPIFFE identity of the collector may
// call it, and the tenant on a span is trusted only for that reason: ext-authz
// set the tenant header on the request, and the gateway put it on the span.
type TraceReceiver struct {
	coltrace.UnimplementedTraceServiceServer
	collectorSVID string
	registry      *brain.Registry
	logger        *slog.Logger
	now           func() time.Time
	usage         UsageRecorder
	outsideAgents func() outsideagentstore.Store
}

// WithOutsideAgents wires the source of the outside agent store. The receiver
// then records an A2A span whose target is an outside agent of the tenant. A
// source that returns nil, or no source, makes the receiver ignore each A2A
// span. The source is read for each span, because the data pool is built after
// the listener options are assembled.
func (r *TraceReceiver) WithOutsideAgents(src func() outsideagentstore.Store) *TraceReceiver {
	r.outsideAgents = src
	return r
}

// ModelCallUsage is the usage of one model call, for the platform budget. It
// reads from the span that the gateway sent.
type ModelCallUsage struct {
	Tenant string
	// CallID is stable for the span. A recorder counts one call once.
	CallID string
	// Mission names the mission of the call, or is empty.
	Mission string
	Tokens  int64
	// CostKnown is false for a model with no price.
	CostKnown bool
	// CostUSD is the cost in US dollars as a decimal string, for example "0.0123".
	CostUSD string
}

// UsageRecorder adds the usage of a model call to the platform budget (tenant,
// user and team scopes). The trace receiver is the one place that sees each
// model call, because the gateway sends each call to the model provider.
type UsageRecorder interface {
	RecordModelCall(ctx context.Context, u ModelCallUsage) error
}

// WithUsage wires the platform budget. The receiver then records the usage of
// each model call in it. It returns the receiver.
func (r *TraceReceiver) WithUsage(u UsageRecorder) *TraceReceiver {
	r.usage = u
	return r
}

// NewTraceReceiver returns the receiver. With an empty collectorSVID, no caller
// is accepted.
func NewTraceReceiver(collectorSVID string, registry *brain.Registry, logger *slog.Logger) *TraceReceiver {
	if logger == nil {
		logger = slog.Default()
	}
	return &TraceReceiver{
		collectorSVID: strings.TrimSpace(collectorSVID),
		registry:      registry,
		logger:        logger.With("component", "trace-receiver"),
		now:           time.Now,
	}
}

// Export implements TraceServiceServer.
//
// A span that is not a model call is ignored. A span with a defect that a retry
// cannot fix is counted as a drop and reported as a rejected span, so the
// collector does not send it again. An engine that is not available fails the
// whole call with Unavailable, so the collector sends it again. A second
// delivery is safe: the fold of a call and the count of its tokens are
// idempotent on the call ID.
func (r *TraceReceiver) Export(
	ctx context.Context, req *coltrace.ExportTraceServiceRequest,
) (*coltrace.ExportTraceServiceResponse, error) {
	if reason, ok := callerRefusal(ctx, r.collectorSVID); !ok {
		return nil, status.Error(codes.PermissionDenied, reason)
	}
	var rejected int64
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				switch err := r.deliverSpan(ctx, sp); {
				case err == nil, errors.Is(err, llmtrace.ErrNotAModelCall):
				case errors.Is(err, errEngineUnavailable):
					return nil, status.Error(codes.Unavailable, "the World of the tenant is not available; try again later")
				case errors.Is(err, errUsageUnavailable):
					return nil, status.Error(codes.Unavailable, "the platform budget is not available; try again later")
				default:
					rejected++
				}
			}
		}
	}
	resp := &coltrace.ExportTraceServiceResponse{}
	if rejected > 0 {
		resp.PartialSuccess = &coltrace.ExportTracePartialSuccess{
			RejectedSpans: rejected,
			ErrorMessage:  "some model call spans could not be read; see the daemon log",
		}
	}
	return resp, nil
}

// deliverSpan routes one span. A model call goes to deliver. An A2A call to an
// outside agent goes to deliverOutside. Any other span is ignored.
func (r *TraceReceiver) deliverSpan(ctx context.Context, sp *tracepb.Span) error {
	err := r.deliver(ctx, sp.GetAttributes())
	if !errors.Is(err, llmtrace.ErrNotAModelCall) {
		return err
	}
	return r.deliverOutside(ctx, llmtrace.Span{
		Attributes:    spanAttributes(sp.GetAttributes()),
		StartUnixNano: int64(sp.GetStartTimeUnixNano()), //nolint:gosec // a time in nanoseconds fits int64
		EndUnixNano:   int64(sp.GetEndTimeUnixNano()),   //nolint:gosec // a time in nanoseconds fits int64
	})
}

// deliverOutside records the A2A call of a mission agent to an outside agent as
// one Timeline event of the tenant. The daemon has no work item for such a call,
// so the span of the gateway is the one record. The tenant, the mission and the
// target come from the trusted headers that ext-authz set and that the gateway
// put on the span. The target is an outside agent only when the tenant registered
// that name. Any other A2A span returns nil, and the daemon records it elsewhere.
func (r *TraceReceiver) deliverOutside(ctx context.Context, sp llmtrace.Span) error {
	call, err := llmtrace.OutsideCallFromSpan(sp)
	if errors.Is(err, llmtrace.ErrNotAnA2ACall) {
		return llmtrace.ErrNotAModelCall
	}
	if err != nil {
		gatewayOutsideCallsTotal.WithLabelValues(outsideDropParse).Inc()
		r.logger.Warn("an A2A span cannot be read", "error", err)
		return errDropped
	}
	tenant, err := auth.NewTenantID(call.Tenant)
	if err != nil {
		gatewayOutsideCallsTotal.WithLabelValues(outsideDropTenant).Inc()
		r.logger.Warn("an A2A span has no valid tenant", "call_id", call.CallID, "error", err)
		return errDropped
	}
	var store outsideagentstore.Store
	if r.outsideAgents != nil {
		store = r.outsideAgents()
	}
	if store == nil {
		// Without the store no call can be told apart. The span is ignored.
		gatewayOutsideCallsTotal.WithLabelValues(outsideNotOutside).Inc()
		return nil
	}
	if _, gerr := store.Get(ctx, tenant.String(), call.Target); gerr != nil {
		if errors.Is(gerr, outsideagentstore.ErrNotFound) {
			gatewayOutsideCallsTotal.WithLabelValues(outsideNotOutside).Inc()
			return nil
		}
		gatewayOutsideCallsTotal.WithLabelValues(outsideDropLookup).Inc()
		r.logger.Warn("the outside agent record could not be read", "call_id", call.CallID, "error", gerr)
		return errEngineUnavailable
	}
	eng, ok := TenantEngine(r.registry, tenant.String())
	if !ok {
		r.logger.Warn("the engine of the tenant is not available", "tenant", tenant.String())
		return errEngineUnavailable
	}
	eng.Submit(call.Event(r.now()))
	gatewayOutsideCallsTotal.WithLabelValues(outsideRecorded).Inc()
	return nil
}

var errEngineUnavailable = errors.New("the tenant engine is not available")

// errUsageUnavailable marks a span whose usage the budget could not record.
var errUsageUnavailable = errors.New("the platform budget is not available")

// errDropped marks a span that was counted as a drop.
var errDropped = errors.New("the span was dropped")

func (r *TraceReceiver) deliver(ctx context.Context, attrs []*commonpb.KeyValue) error {
	obs, err := llmtrace.FromSpan(llmtrace.Span{Attributes: spanAttributes(attrs)})
	if errors.Is(err, llmtrace.ErrNotAModelCall) {
		return err
	}
	gatewayLLMRequestsTotal.Inc()
	if err != nil {
		gatewayLLMDroppedTotal.WithLabelValues(dropParse).Inc()
		r.logger.Warn("a model call span cannot be read", "error", err)
		return errDropped
	}
	if obs.Tenant == "" {
		gatewayLLMDroppedTotal.WithLabelValues(dropNoTenant).Inc()
		r.logger.Warn("a model call span has no tenant", "call_id", obs.CallID)
		return errDropped
	}
	tenant, err := auth.NewTenantID(obs.Tenant)
	if err != nil {
		gatewayLLMDroppedTotal.WithLabelValues(dropBadTenant).Inc()
		r.logger.Warn("a model call span has an invalid tenant", "call_id", obs.CallID, "error", err)
		return errDropped
	}
	eng, ok := TenantEngine(r.registry, tenant.String())
	if !ok {
		// The span is not lost: the collector sends it again.
		r.logger.Warn("the engine of the tenant is not available", "tenant", tenant.String())
		return errEngineUnavailable
	}
	for _, ev := range obs.Events(r.now()) {
		eng.Submit(ev)
	}
	if r.usage != nil {
		err := r.usage.RecordModelCall(ctx, ModelCallUsage{
			Tenant: tenant.String(), CallID: obs.CallID, Mission: obs.Mission,
			Tokens: obs.InputTokens + obs.OutputTokens, CostKnown: obs.Cost.Known, CostUSD: obs.Cost.Total,
		})
		if err != nil {
			// The collector sends the span again. The fold of the events and the
			// count of the usage are both idempotent on the call id.
			r.logger.Warn("the usage of a model call was not recorded", "call_id", obs.CallID, "error", err)
			return errUsageUnavailable
		}
	}
	gatewayLLMDeliveredTotal.Inc()
	return nil
}

// spanAttributes reads OTLP attributes into the typed map that llmtrace reads.
func spanAttributes(kvs []*commonpb.KeyValue) map[string]any {
	out := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		switch v := kv.GetValue().GetValue().(type) {
		case *commonpb.AnyValue_StringValue:
			out[kv.GetKey()] = v.StringValue
		case *commonpb.AnyValue_IntValue:
			out[kv.GetKey()] = v.IntValue
		case *commonpb.AnyValue_DoubleValue:
			out[kv.GetKey()] = v.DoubleValue
		case *commonpb.AnyValue_BoolValue:
			out[kv.GetKey()] = v.BoolValue
		}
	}
	return out
}
