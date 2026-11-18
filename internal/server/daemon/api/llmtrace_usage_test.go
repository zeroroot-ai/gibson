// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeUsage struct {
	mu    sync.Mutex
	calls []ModelCallUsage
	err   error
}

func (f *fakeUsage) RecordModelCall(_ context.Context, u ModelCallUsage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, u)
	return nil
}

// Each model call span feeds the platform budget with its tenant, its call id,
// its tokens and its cost.
func TestTraceReceiver_FeedsThePlatformBudget(t *testing.T) {
	r, _ := newReceiver(t)
	usage := &fakeUsage{}
	r.WithUsage(usage)
	span := spanFromFixture(t, "messages_plain", map[string]string{"gibson.tenant": "acme", "gibson.mission": "m1"})
	if _, err := r.Export(peerCtx(t, collectorSVID), exportOf(span)); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(usage.calls) != 1 {
		t.Fatalf("recorded %d calls, want 1", len(usage.calls))
	}
	got := usage.calls[0]
	if got.Tenant != "acme" || got.Mission != "m1" || got.CallID == "" || got.Tokens != 165 ||
		!got.CostKnown || got.CostUSD != "0.00069" {
		t.Fatalf("usage = %+v", got)
	}
}

// A budget that cannot record the call fails the export with Unavailable, so
// the collector sends the span again. A usage of zero for ever is the failure
// that this feed exists to prevent.
func TestTraceReceiver_ABudgetFailureFailsTheExport(t *testing.T) {
	r, _ := newReceiver(t)
	r.WithUsage(&fakeUsage{err: errors.New("redis down")})
	span := spanFromFixture(t, "messages_plain", map[string]string{"gibson.tenant": "acme"})
	_, err := r.Export(peerCtx(t, collectorSVID), exportOf(span))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}
