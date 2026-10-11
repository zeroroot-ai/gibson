// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// startupGateSteps is the step graph that the startup gate validates: the
// foundation namespace step first, then every provision step and every
// teardown step, in order.
func startupGateSteps(nsStep saga.Step, provision, teardown []saga.Step) []saga.Step {
	all := make([]saga.Step, 0, 1+len(provision)+len(teardown))
	all = append(all, nsStep)
	all = append(all, provision...)
	all = append(all, teardown...)
	return all
}
