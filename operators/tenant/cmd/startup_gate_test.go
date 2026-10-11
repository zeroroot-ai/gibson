// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// TestStartupGateSteps checks that the gate validates the namespace step
// first, then the provision and teardown steps in their order.
func TestStartupGateSteps(t *testing.T) {
	ns := controller.NewNamespaceProvisioner(nil, "gibson")
	p1 := controller.NewNamespaceProvisioner(nil, "p1")
	t1 := controller.NewNamespaceProvisioner(nil, "t1")
	got := startupGateSteps(ns, []saga.Step{p1}, []saga.Step{t1})
	want := []saga.Step{ns, p1, t1}
	if len(got) != len(want) {
		t.Fatalf("startupGateSteps returned %d steps, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step %d is %v, want %v", i, got[i], want[i])
		}
	}
}
