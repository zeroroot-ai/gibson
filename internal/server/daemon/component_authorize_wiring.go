// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// runAuthorizerTarget is what wireRunAuthorizer wires: the component service.
type runAuthorizerTarget interface {
	WithRunAuthorizer(a component.RunAuthorizer) *component.ComponentServiceServer
}

// runAuthorizerSource is what wireRunAuthorizer reads the decision from: the
// callback manager.
type runAuthorizerSource interface {
	RunAuthorizer() *harness.HarnessCallbackService
}

// wireRunAuthorizer gives ComponentService.Authorize the decision of the
// callback path, so the pull transport and the callback transport decide the
// same way (D86). It reports whether it wired one. Without a decision,
// Authorize refuses every request.
func wireRunAuthorizer(target runAuthorizerTarget, source runAuthorizerSource) bool {
	svc := source.RunAuthorizer()
	if svc == nil {
		return false
	}
	target.WithRunAuthorizer(svc)
	return true
}
