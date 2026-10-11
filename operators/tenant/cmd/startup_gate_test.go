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
	p1 := controller.NewNamespaceProvisioner(nil, "p1")
	t1 := controller.NewNamespaceProvisioner(nil, "t1")
	got := startupGateSteps(nil, "gibson", []saga.Step{p1}, []saga.Step{t1})
	if len(got) != 3 {
		t.Fatalf("startupGateSteps returned %d steps, want 3", len(got))
	}
	ns, ok := got[0].(*controller.NamespaceProvisioner)
	if !ok || ns.PlatformNamespace != "gibson" {
		t.Errorf("step 0 is %v, want the namespace step of the operator namespace", got[0])
	}
	if got[1] != saga.Step(p1) || got[2] != saga.Step(t1) {
		t.Errorf("steps 1 and 2 are %v and %v, want the provision step, then the teardown step", got[1], got[2])
	}
}
