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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/llmtrace"
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
	gatewayLLMDroppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gibson_gateway_llm_dropped_total",
		Help: "Model call spans that the daemon did not deliver, by reason.",
	}, []string{"reason"})
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
				switch err := r.deliver(sp.GetAttributes()); {
				case err == nil, errors.Is(err, llmtrace.ErrNotAModelCall):
				case errors.Is(err, errEngineUnavailable):
					return nil, status.Error(codes.Unavailable, "the World of the tenant is not available; try again later")
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

var errEngineUnavailable = errors.New("the tenant engine is not available")

// errDropped marks a span that was counted as a drop.
var errDropped = errors.New("the span was dropped")

func (r *TraceReceiver) deliver(attrs []*commonpb.KeyValue) error {
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
