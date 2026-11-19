// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	"github.com/zeroroot-ai/sdk/auth"
)

// modelResolvedCount reads the count of model_resolved audit events that the
// writer accepted, from the default Prometheus registry.
func modelResolvedCount(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != "gibson_audit_events_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "action" && l.GetValue() == "model_resolved" {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// Each slot resolution gives one audit event, whether the model was allowed or
// not, and the user is the acting user or else the initiator of the call.
// The test reads a process-wide counter, so it does not run in parallel.
func TestModelResolvedCallback_EmitsOneEventForEachResolution(t *testing.T) {
	d := newMinimalDaemon(nil)
	// The writer only buffers an event here. No flush goroutine runs, so the
	// database is never reached.
	d.auditWriter = audit.NewWriter(&sql.DB{}, slog.New(slog.DiscardHandler))
	callback := d.modelResolvedCallback()
	picked := modelgate.Candidate{Provider: "anthropic", Model: "claude-sonnet-5-5"}

	base := auth.WithIdentity(context.Background(), auth.Identity{Subject: "u1", Tenant: auth.MustNewTenantID("acme")})
	acting := auth.ContextWithInitiatorUser(base, "initiator-1")
	for _, ctx := range []context.Context{base, acting} {
		before := modelResolvedCount(t)
		callback(ctx, picked, true)
		callback(ctx, picked, false)
		assert.InDelta(t, before+2, modelResolvedCount(t), 0.001, "one event for an allowed and one for a denied resolution")
	}
}
