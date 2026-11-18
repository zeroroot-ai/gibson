// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

func TestTraceExportMethodMatchesTheService(t *testing.T) {
	want := "/" + coltrace.TraceService_ServiceDesc.ServiceName + "/" + coltrace.TraceService_ServiceDesc.Methods[0].MethodName
	if traceExportMethod != want {
		t.Errorf("traceExportMethod = %q, want %q", traceExportMethod, want)
	}
}

// The collector may call the export method and no other method. With no
// identity configured, there is no peer.
func TestTraceCollectorPeerPolicy(t *testing.T) {
	const svid = "spiffe://example.org/platform/otel-collector"
	t.Setenv(api.EnvTraceCollectorSVID, svid)
	td := spiffeid.RequireTrustDomainFromString("example.org")
	policies := spiffePeerMethodPolicies(td, api.ConnectionPointCallers{})

	allowed, err := spiffeBypassDecision(svid, traceExportMethod, []string{svid}, policies)
	if err != nil || !allowed {
		t.Fatalf("export = %v, %v, want allowed", allowed, err)
	}
	if allowed, err := spiffeBypassDecision(svid, "/gibson.daemon.v1.DaemonService/ListMissions", []string{svid}, policies); allowed || err == nil {
		t.Errorf("another method = %v, %v, want a refusal", allowed, err)
	}
	// The tenant operator may not send spans.
	op := tenantOperatorSVID(td)
	if allowed, err := spiffeBypassDecision(op, traceExportMethod, []string{op}, policies); allowed || err == nil {
		t.Errorf("tenant operator export = %v, %v, want a refusal", allowed, err)
	}
	if err := validateAllowedPeerPolicies([]string{svid}, policies); err != nil {
		t.Errorf("the collector has a policy, but the check failed: %v", err)
	}

	t.Setenv(api.EnvTraceCollectorSVID, "")
	if got := traceCollectorPeerPolicies(traceCollectorSVIDFromEnv()); len(got) != 0 {
		t.Errorf("no configured collector gave the policies %v", got)
	}
}
