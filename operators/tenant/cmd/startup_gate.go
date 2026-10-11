// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// startupGateSteps is the step graph that the startup gate validates: the
// foundation namespace step of the operator namespace first, then every
// provision step and every teardown step, in order.
func startupGateSteps(c client.Client, operatorNS string, provision, teardown []saga.Step) []saga.Step {
	all := make([]saga.Step, 0, 1+len(provision)+len(teardown))
	all = append(all, controller.NewNamespaceProvisioner(c, operatorNS))
	all = append(all, provision...)
	all = append(all, teardown...)
	return all
}
